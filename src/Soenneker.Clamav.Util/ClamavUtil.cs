using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Soenneker.Asyncs.Initializers;
using Soenneker.Clamav.Freshclam.Util.Abstract;
using Soenneker.Clamav.Util.Abstract;
using Soenneker.Clamav.Util.Options;
using Soenneker.Clamav.Util.Results;
using Soenneker.Extensions.Task;
using Soenneker.Extensions.ValueTask;
using Soenneker.Utils.Directory.Abstract;
using Soenneker.Utils.File.Abstract;
using Soenneker.Utils.Path.Abstract;
using Soenneker.Utils.Paths.Resources.Abstract;
using Soenneker.Utils.PooledStringBuilders;
using Soenneker.Utils.Process.Abstract;
using Soenneker.Utils.Process.Dtos;
using Soenneker.Utils.Runtime;

namespace Soenneker.Clamav.Util;

public sealed class ClamavUtil : IClamavUtil, IDisposable
{
    private readonly IProcessUtil _processUtil;
    private readonly IFreshclamUtil _freshclamUtil;
    private readonly IFileUtil _fileUtil;
    private readonly IDirectoryUtil _directoryUtil;
    private readonly IPathUtil _pathUtil;
    private readonly IResourcesPathUtil _resourcesPathUtil;
    private readonly ILogger<ClamavUtil> _logger;
    private readonly ConcurrentDictionary<string, Lazy<AsyncInitializer>> _definitionInitializers;
    private readonly ClamavUtilOptions _options;
    private readonly bool _windows;
    private readonly string _runtimeIdentifier;
    private System.Diagnostics.Process? _daemonProcess;
    private string? _daemonConfigPath;
    private string? _daemonDatabaseDirectory;

    public ClamavUtil(IProcessUtil processUtil, IFreshclamUtil freshclamUtil, IFileUtil fileUtil,
        IDirectoryUtil directoryUtil, IPathUtil pathUtil, IResourcesPathUtil resourcesPathUtil,
        ILogger<ClamavUtil> logger, IOptions<ClamavUtilOptions> options)
    {
        _processUtil = processUtil;
        _freshclamUtil = freshclamUtil;
        _fileUtil = fileUtil;
        _directoryUtil = directoryUtil;
        _pathUtil = pathUtil;
        _resourcesPathUtil = resourcesPathUtil;
        _logger = logger;
        EnsureSupportedPlatform();

        _options = options.Value;

        if (_options.DaemonPort is < 1 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(options), _options.DaemonPort, "The daemon port must be between 1 and 65535.");

        _windows = RuntimeUtil.IsWindows();
        _runtimeIdentifier = _windows ? "win-x64" : "linux-x64";
        _definitionInitializers = new ConcurrentDictionary<string, Lazy<AsyncInitializer>>(
            _windows ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        _logger.LogDebug("Initialized ClamAV for {RuntimeIdentifier}", _runtimeIdentifier);
    }

    public async ValueTask<ClamavScanResult> Scan(string path, ClamavScanOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        string fullPath = Path.GetFullPath(path);

        _logger.LogDebug("Resolving ClamAV scan target {TargetPath}", fullPath);

        if (await _fileUtil.Exists(fullPath, cancellationToken).NoSync())
        {
            _logger.LogDebug("Resolved ClamAV scan target {TargetPath} as a file", fullPath);
            return await ScanFile(fullPath, options, cancellationToken).NoSync();
        }

        if (await _directoryUtil.Exists(fullPath, cancellationToken).NoSync())
        {
            _logger.LogDebug("Resolved ClamAV scan target {TargetPath} as a directory", fullPath);
            return await ScanDirectory(fullPath, options, cancellationToken).NoSync();
        }

        _logger.LogWarning("ClamAV scan target {TargetPath} was not found", fullPath);

        throw new FileNotFoundException("The ClamAV scan target was not found.", fullPath);
    }

    public async ValueTask<ClamavScanResult> ScanFile(string filePath, ClamavScanOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        string fullPath = Path.GetFullPath(filePath);
        if (!await _fileUtil.Exists(fullPath, cancellationToken).NoSync())
            throw new FileNotFoundException("The file to scan was not found.", fullPath);

        return await ScanCore(fullPath, isDirectory: false, options ?? new ClamavScanOptions(), cancellationToken)
            .NoSync();
    }

    public async ValueTask<ClamavScanResult> ScanDirectory(string directoryPath, ClamavScanOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directoryPath);
        string fullPath = Path.GetFullPath(directoryPath);
        if (!await _directoryUtil.Exists(fullPath, cancellationToken).NoSync())
            throw new DirectoryNotFoundException($"The directory to scan was not found: {fullPath}");

        return await ScanCore(fullPath, isDirectory: true, options ?? new ClamavScanOptions(), cancellationToken)
            .NoSync();
    }

    public ValueTask<IReadOnlyList<string>> UpdateDefinitions(string? databaseDirectory = null,
        CancellationToken cancellationToken = default) =>
        _freshclamUtil.Update(databaseDirectory, cancellationToken: cancellationToken);

    public async ValueTask<string> GetVersion(CancellationToken cancellationToken = default)
    {
        (string runtimeDirectory, string scannerPath) = await GetRuntimePaths(cancellationToken).NoSync();
        _logger.LogDebug("Reading bundled ClamAV version from {ScannerPath}", scannerPath);
        await EnsureToolExists(scannerPath, "clamscan", cancellationToken).NoSync();
        EnsureExecutable(scannerPath);

        List<string> output = await _processUtil.Start(scannerPath, runtimeDirectory, "--version", log: false,
            environmentalVars: BuildEnvironment(runtimeDirectory), cancellationToken: cancellationToken).NoSync();
        string version = output.Count == 0 ? string.Empty : output[0];
        _logger.LogDebug("Bundled ClamAV version is {ClamavVersion}", version);
        return version;
    }

    private async ValueTask<ClamavScanResult> ScanCore(string targetPath, bool isDirectory, ClamavScanOptions options,
        CancellationToken cancellationToken)
    {
        Validate(options);
        (string runtimeDirectory, string scannerPath) = await GetRuntimePaths(cancellationToken).NoSync();
        await EnsureToolExists(scannerPath, "clamscan", cancellationToken).NoSync();
        EnsureExecutable(scannerPath);

        string databaseDirectory = await GetDatabaseDirectory(options.DatabaseDirectory, cancellationToken).NoSync();
        if (options.UpdateDefinitions)
        {
            _logger.LogInformation("Ensuring ClamAV definitions are initialized in {DatabaseDirectory}",
                databaseDirectory);
            Lazy<AsyncInitializer> initializer = _definitionInitializers.GetOrAdd(databaseDirectory,
                directory => new Lazy<AsyncInitializer>(() =>
                    new AsyncInitializer(token => UpdateDefinitions(directory, token))));
            await initializer.Value.Init(cancellationToken).NoSync();
        }
        else if (!await _freshclamUtil.HasDefinitions(databaseDirectory, cancellationToken).NoSync())
        {
            _logger.LogWarning(
                "No ClamAV definitions were found in {DatabaseDirectory}, and definition updates are disabled",
                databaseDirectory);
            throw new InvalidOperationException($"No ClamAV virus definitions were found in '{databaseDirectory}'.");
        }

        bool useDaemon = CanUseDaemon(isDirectory, options);
        string logPath = await _pathUtil.GetRandomTempFilePath(".log", cancellationToken).NoSync();
        string arguments = useDaemon
            ? string.Empty
            : BuildScanArguments(targetPath, databaseDirectory, logPath, isDirectory, options);
        bool infected = false;
        string targetType = isDirectory ? "directory" : "file";

        _logger.LogInformation(
            "Starting ClamAV scan of {TargetType} {TargetPath} using definitions from {DatabaseDirectory}", targetType,
            targetPath, databaseDirectory);

        try
        {
            if (useDaemon)
            {
                (scannerPath, arguments) = await PrepareDaemonScan(runtimeDirectory, databaseDirectory, targetPath, logPath,
                    options, cancellationToken).NoSync();
            }

            List<string> output;
            try
            {
                output = await _processUtil.Start(scannerPath, runtimeDirectory, arguments, timeout: options.Timeout,
                    log: false, environmentalVars: BuildEnvironment(runtimeDirectory),
                    cancellationToken: cancellationToken).NoSync();
            }
            catch (InvalidOperationException exception) when (IsThreatExitCode(exception))
            {
                infected = true;
                output = ExtractOutput(exception);
            }

            if (await _fileUtil.Exists(logPath, cancellationToken).NoSync())
                output = await _fileUtil.ReadAsLines(logPath, log: false, cancellationToken).NoSync();

            List<ClamavDetection> detections = ParseDetections(output);
            var result = new ClamavScanResult(targetPath, infected, detections, output);

            if (infected)
                _logger.LogWarning(
                    "ClamAV detected {DetectionCount} threat(s) while scanning {TargetType} {TargetPath}",
                    detections.Count, targetType, targetPath);
            else
                _logger.LogInformation("ClamAV scan completed cleanly for {TargetType} {TargetPath}", targetType,
                    targetPath);

            return result;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            _logger.LogInformation("ClamAV scan was cancelled for {TargetType} {TargetPath}", targetType, targetPath);
            throw;
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "ClamAV scan failed for {TargetType} {TargetPath}", targetType, targetPath);
            throw;
        }
        finally
        {
            await _fileUtil.TryDelete(logPath, log: false, CancellationToken.None).NoSync();
            _logger.LogDebug("Removed temporary ClamAV scan log {LogPath}", logPath);
        }
    }

    private bool CanUseDaemon(bool isDirectory, ClamavScanOptions options)
    {
        if (!_options.UseDaemon)
            return false;

        bool unsupported = options.DetectPotentiallyUnwantedApplications || options.FollowFileSymbolicLinks ||
                           options.FollowDirectorySymbolicLinks || (isDirectory && !options.Recursive);

        if (unsupported)
            _logger.LogDebug("Using clamscan because the requested scan options cannot be applied per request by clamd");

        return !unsupported;
    }

    private async ValueTask<(string ScannerPath, string Arguments)> PrepareDaemonScan(string runtimeDirectory,
        string databaseDirectory, string targetPath, string logPath, ClamavScanOptions options,
        CancellationToken cancellationToken)
    {
        await EnsureDaemon(runtimeDirectory, databaseDirectory, cancellationToken).NoSync();

        string scannerPath = Path.Combine(_windows ? runtimeDirectory : Path.Combine(runtimeDirectory, "bin"),
            _windows ? "clamdscan.exe" : "clamdscan");
        await EnsureToolExists(scannerPath, "clamdscan", cancellationToken).NoSync();
        EnsureExecutable(scannerPath);

        using var builder = new PooledStringBuilder(256);
        builder.Append("--config-file=");
        builder.Append(Quote(_daemonConfigPath!));
        builder.Append(" --wait --ping=120:1 --no-summary --stdout --log=");
        builder.Append(Quote(logPath));
        if (options.AllMatches)
            builder.Append(" --allmatch");
        builder.Append(' ');
        builder.Append(Quote(targetPath));
        return (scannerPath, builder.ToString());
    }

    private async ValueTask EnsureDaemon(string runtimeDirectory, string databaseDirectory,
        CancellationToken cancellationToken)
    {
        if (_daemonProcess is not null && !_daemonProcess.HasExited)
        {
            if (!string.Equals(_daemonDatabaseDirectory, databaseDirectory,
                    _windows ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"The running ClamAV daemon uses '{_daemonDatabaseDirectory}', not '{databaseDirectory}'.");
            }

            return;
        }

        _daemonProcess?.Dispose();
        _daemonProcess = null;

        string daemonPath = Path.Combine(_windows ? runtimeDirectory : Path.Combine(runtimeDirectory, "sbin"),
            _windows ? "clamd.exe" : "clamd");
        await EnsureToolExists(daemonPath, "clamd", cancellationToken).NoSync();
        EnsureExecutable(daemonPath);

        _daemonConfigPath ??= await _pathUtil.GetRandomTempFilePath(".clamd.conf", cancellationToken).NoSync();
        string config = $"TCPSocket {_options.DaemonPort}{Environment.NewLine}" +
                        $"TCPAddr 127.0.0.1{Environment.NewLine}";
        await File.WriteAllTextAsync(_daemonConfigPath, config, cancellationToken).NoSync();

        var dto = new ProcessStartDto
        {
            FileName = daemonPath,
            WorkingDirectory = runtimeDirectory,
            Arguments = $"--foreground --datadir={Quote(databaseDirectory)} --config-file={Quote(_daemonConfigPath)}",
            EnvironmentVariables = BuildEnvironment(runtimeDirectory),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            Log = false,
            OutputCallback = line => _logger.LogDebug("clamd: {Output}", line),
            ErrorCallback = line => _logger.LogWarning("clamd: {Output}", line)
        };

        cancellationToken.ThrowIfCancellationRequested();
        _daemonProcess = await _processUtil.StartDetached(dto, CancellationToken.None).NoSync() ??
                         throw new InvalidOperationException("The ClamAV daemon could not be started.");
        _daemonDatabaseDirectory = databaseDirectory;
        _logger.LogInformation("Started persistent ClamAV daemon process {ProcessId}", _daemonProcess.Id);
    }

    private string BuildScanArguments(string targetPath, string databaseDirectory, string logPath, bool isDirectory,
        ClamavScanOptions options)
    {
        using var builder = new PooledStringBuilder(256);
        builder.Append("--database=");
        builder.Append(Quote(databaseDirectory));
        builder.Append(" --log=");
        builder.Append(Quote(logPath));
        builder.Append(" --stdout");

        if (isDirectory)
            builder.Append(options.Recursive ? " --recursive=yes" : " --recursive=no");
        if (options.DetectPotentiallyUnwantedApplications)
            builder.Append(" --detect-pua=yes");
        if (options.AllMatches)
            builder.Append(" --allmatch=yes");

        builder.Append(options.FollowFileSymbolicLinks ? " --follow-file-symlinks=2" : " --follow-file-symlinks=0");
        builder.Append(options.FollowDirectorySymbolicLinks ? " --follow-dir-symlinks=2" : " --follow-dir-symlinks=0");
        builder.Append(' ');
        builder.Append(Quote(targetPath));
        return builder.ToString();
    }

    private static List<ClamavDetection> ParseDetections(IEnumerable<string> output)
    {
        var detections = new List<ClamavDetection>();

        foreach (string originalLine in output)
        {
            string line = originalLine.StartsWith("[stderr] ", StringComparison.Ordinal)
                ? originalLine[9..]
                : originalLine;
            if (!line.EndsWith(" FOUND", StringComparison.Ordinal))
                continue;

            int separator = line.LastIndexOf(": ", line.Length - 7, StringComparison.Ordinal);
            if (separator <= 0)
                continue;

            string path = line[..separator];
            string signature = line[(separator + 2)..^6];
            detections.Add(new ClamavDetection(path, signature));
        }

        return detections;
    }

    private Dictionary<string, string>? BuildEnvironment(string runtimeDirectory)
    {
        if (_windows)
            return null;

        string libraryPath = string.Join(Path.PathSeparator, Path.Combine(runtimeDirectory, "lib64"),
            Path.Combine(runtimeDirectory, "lib"));
        string? existing = Environment.GetEnvironmentVariable("LD_LIBRARY_PATH");
        if (!string.IsNullOrWhiteSpace(existing))
            libraryPath = string.IsNullOrEmpty(libraryPath) ? existing : $"{libraryPath}{Path.PathSeparator}{existing}";

        return new Dictionary<string, string>
        {
            ["LD_LIBRARY_PATH"] = libraryPath,
            ["CVD_CERTS_DIR"] = Path.Combine(runtimeDirectory, "etc", "certs")
        };
    }

    private async ValueTask<(string RuntimeDirectory, string ScannerPath)> GetRuntimePaths(
        CancellationToken cancellationToken)
    {
        string runtimeDirectory = await _resourcesPathUtil
                                        .GetResourceFilePath(Path.Combine(_runtimeIdentifier, "clamav"),
                                            cancellationToken).NoSync();
        string binaryDirectory = _windows ? runtimeDirectory : Path.Combine(runtimeDirectory, "bin");
        return (runtimeDirectory, Path.Combine(binaryDirectory, _windows ? "clamscan.exe" : "clamscan"));
    }

    private async ValueTask<string> GetDatabaseDirectory(string? directory, CancellationToken cancellationToken) =>
        string.IsNullOrWhiteSpace(directory)
            ? await _resourcesPathUtil.GetResourceFilePath("clamav-database", cancellationToken).NoSync()
            : Path.GetFullPath(directory);

    private static bool IsThreatExitCode(Exception exception)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            if (current.Message.Contains("exited with code 1.", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static List<string> ExtractOutput(Exception exception)
    {
        int separator = exception.Message.IndexOf(Environment.NewLine, StringComparison.Ordinal);
        if (separator < 0)
            return [];

        return new List<string>(exception.Message[(separator + Environment.NewLine.Length)..]
                                         .Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries));
    }

    private static void Validate(ClamavScanOptions options)
    {
        if (options.Timeout is { } timeout && timeout <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(options), "The scan timeout must be greater than zero.");
    }

    private async ValueTask EnsureToolExists(string path, string tool, CancellationToken cancellationToken)
    {
        if (!await _fileUtil.Exists(path, cancellationToken).NoSync())
        {
            _logger.LogError("Bundled ClamAV tool {Tool} was not found at {ToolPath}", tool, path);
            throw new FileNotFoundException($"The bundled {tool} executable was not found.", path);
        }
    }

    private static void EnsureExecutable(string path)
    {
        if (!OperatingSystem.IsLinux())
            return;

        File.SetUnixFileMode(path,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead |
            UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
    }

    private static void EnsureSupportedPlatform()
    {
        if (RuntimeInformation.ProcessArchitecture != Architecture.X64 ||
            (!RuntimeUtil.IsLinux() && !RuntimeUtil.IsWindows()))
            throw new PlatformNotSupportedException(
                "Soenneker.Clamav.Util currently supports Linux x64 and Windows x64.");
    }

    private static string Quote(string value) => $"\"{value.Replace("\"", "\\\"")}\"";

    public void Dispose()
    {
        foreach (Lazy<AsyncInitializer> initializer in _definitionInitializers.Values)
        {
            if (initializer.IsValueCreated)
                initializer.Value.Dispose();
        }

        if (_daemonProcess is not null)
        {
            try
            {
                if (!_daemonProcess.HasExited)
                    _daemonProcess.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
            }

            _daemonProcess.Dispose();
        }

        if (_daemonConfigPath is not null)
        {
            try
            {
                File.Delete(_daemonConfigPath);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }
}
