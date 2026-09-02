using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Soenneker.Clamav.Freshclam.Util.Abstract;
using Soenneker.Clamav.Util.Abstract;
using Soenneker.Clamav.Util.Options;
using Soenneker.Clamav.Util.Results;
using Soenneker.Extensions.Task;
using Soenneker.Extensions.ValueTask;
using Soenneker.Utils.Directory.Abstract;
using Soenneker.Utils.File.Abstract;
using Soenneker.Utils.Path.Abstract;
using Soenneker.Utils.PooledStringBuilders;
using Soenneker.Utils.Process.Abstract;
using Soenneker.Utils.Runtime;

namespace Soenneker.Clamav.Util;

public sealed class ClamavUtil : IClamavUtil
{
    private readonly IProcessUtil _processUtil;
    private readonly IFreshclamUtil _freshclamUtil;
    private readonly IFileUtil _fileUtil;
    private readonly IDirectoryUtil _directoryUtil;
    private readonly IPathUtil _pathUtil;
    private readonly ILogger<ClamavUtil> _logger;
    private readonly string _runtimeDirectory;
    private readonly string _scannerPath;
    private readonly string _defaultDatabaseDirectory;
    private readonly Dictionary<string, string>? _environmentVariables;

    public ClamavUtil(IProcessUtil processUtil, IFreshclamUtil freshclamUtil, IFileUtil fileUtil, IDirectoryUtil directoryUtil, IPathUtil pathUtil,
        ILogger<ClamavUtil> logger)
    {
        _processUtil = processUtil ?? throw new ArgumentNullException(nameof(processUtil));
        _freshclamUtil = freshclamUtil ?? throw new ArgumentNullException(nameof(freshclamUtil));
        _fileUtil = fileUtil ?? throw new ArgumentNullException(nameof(fileUtil));
        _directoryUtil = directoryUtil ?? throw new ArgumentNullException(nameof(directoryUtil));
        _pathUtil = pathUtil ?? throw new ArgumentNullException(nameof(pathUtil));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        EnsureSupportedPlatform();

        bool windows = RuntimeUtil.IsWindows();
        string runtimeIdentifier = windows ? "win-x64" : "linux-x64";
        _runtimeDirectory = Path.Combine(AppContext.BaseDirectory, "Resources", runtimeIdentifier, "clamav");
        string binaryDirectory = windows ? _runtimeDirectory : Path.Combine(_runtimeDirectory, "bin");
        _scannerPath = Path.Combine(binaryDirectory, windows ? "clamscan.exe" : "clamscan");
        _defaultDatabaseDirectory = Path.Combine(AppContext.BaseDirectory, "Resources", "clamav-database");

        if (!windows)
            _environmentVariables = BuildLinuxEnvironment();

        _logger.LogDebug("Initialized ClamAV for {RuntimeIdentifier} with runtime directory {RuntimeDirectory}", runtimeIdentifier, _runtimeDirectory);
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

        return await ScanCore(fullPath, isDirectory: false, options ?? new ClamavScanOptions(), cancellationToken).NoSync();
    }

    public async ValueTask<ClamavScanResult> ScanDirectory(string directoryPath, ClamavScanOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directoryPath);
        string fullPath = Path.GetFullPath(directoryPath);
        if (!await _directoryUtil.Exists(fullPath, cancellationToken).NoSync())
            throw new DirectoryNotFoundException($"The directory to scan was not found: {fullPath}");

        return await ScanCore(fullPath, isDirectory: true, options ?? new ClamavScanOptions(), cancellationToken).NoSync();
    }

    public ValueTask<IReadOnlyList<string>> UpdateDefinitions(string? databaseDirectory = null,
        CancellationToken cancellationToken = default) =>
        _freshclamUtil.Update(databaseDirectory, cancellationToken: cancellationToken);

    public async ValueTask<string> GetVersion(CancellationToken cancellationToken = default)
    {
        _logger.LogDebug("Reading bundled ClamAV version from {ScannerPath}", _scannerPath);
        await EnsureToolExists(_scannerPath, "clamscan", cancellationToken).NoSync();
        EnsureExecutable(_scannerPath);

        List<string> output = await _processUtil.Start(_scannerPath, _runtimeDirectory, "--version", log: false,
            environmentalVars: _environmentVariables, cancellationToken: cancellationToken).NoSync();
        string version = output.Count == 0 ? string.Empty : output[0];
        _logger.LogDebug("Bundled ClamAV version is {ClamavVersion}", version);
        return version;
    }

    private async ValueTask<ClamavScanResult> ScanCore(string targetPath, bool isDirectory, ClamavScanOptions options,
        CancellationToken cancellationToken)
    {
        Validate(options);
        await EnsureToolExists(_scannerPath, "clamscan", cancellationToken).NoSync();
        EnsureExecutable(_scannerPath);

        string databaseDirectory = GetDatabaseDirectory(options.DatabaseDirectory);
        if (!await _freshclamUtil.HasDefinitions(databaseDirectory, cancellationToken).NoSync())
        {
            if (!options.UpdateDefinitionsIfMissing)
            {
                _logger.LogWarning("No ClamAV definitions were found in {DatabaseDirectory}, and automatic updates are disabled", databaseDirectory);
                throw new InvalidOperationException($"No ClamAV virus definitions were found in '{databaseDirectory}'.");
            }

            _logger.LogInformation("No ClamAV definitions were found in {DatabaseDirectory}; starting an update", databaseDirectory);
            await UpdateDefinitions(databaseDirectory, cancellationToken).NoSync();
        }

        string logPath = await _pathUtil.GetRandomTempFilePath(".log", cancellationToken).NoSync();
        string arguments = BuildScanArguments(targetPath, databaseDirectory, logPath, isDirectory, options);
        List<string> output;
        bool infected = false;
        string targetType = isDirectory ? "directory" : "file";

        _logger.LogInformation("Starting ClamAV scan of {TargetType} {TargetPath} using definitions from {DatabaseDirectory}",
            targetType, targetPath, databaseDirectory);

        try
        {
            try
            {
                output = await _processUtil.Start(_scannerPath, _runtimeDirectory, arguments, timeout: options.Timeout, log: false,
                    environmentalVars: _environmentVariables, cancellationToken: cancellationToken).NoSync();
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
                _logger.LogWarning("ClamAV detected {DetectionCount} threat(s) while scanning {TargetType} {TargetPath}", detections.Count, targetType, targetPath);
            else
                _logger.LogInformation("ClamAV scan completed cleanly for {TargetType} {TargetPath}", targetType, targetPath);

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

    private string BuildScanArguments(string targetPath, string databaseDirectory, string logPath, bool isDirectory, ClamavScanOptions options)
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
            string line = originalLine.StartsWith("[stderr] ", StringComparison.Ordinal) ? originalLine[9..] : originalLine;
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

    private Dictionary<string, string> BuildLinuxEnvironment()
    {
        string libraryPath = string.Join(Path.PathSeparator,
            Path.Combine(_runtimeDirectory, "lib64"), Path.Combine(_runtimeDirectory, "lib"));
        string? existing = Environment.GetEnvironmentVariable("LD_LIBRARY_PATH");
        if (!string.IsNullOrWhiteSpace(existing))
            libraryPath = string.IsNullOrEmpty(libraryPath) ? existing : $"{libraryPath}{Path.PathSeparator}{existing}";

        return new Dictionary<string, string>
        {
            ["LD_LIBRARY_PATH"] = libraryPath,
            ["CVD_CERTS_DIR"] = Path.Combine(_runtimeDirectory, "etc", "certs")
        };
    }

    private string GetDatabaseDirectory(string? directory) =>
        Path.GetFullPath(string.IsNullOrWhiteSpace(directory) ? _defaultDatabaseDirectory : directory);

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
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
            UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
            UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
    }

    private static void EnsureSupportedPlatform()
    {
        if (RuntimeInformation.ProcessArchitecture != Architecture.X64 ||
            (!RuntimeUtil.IsLinux() && !RuntimeUtil.IsWindows()))
            throw new PlatformNotSupportedException("Soenneker.Clamav.Util currently supports Linux x64 and Windows x64.");
    }

    private static string Quote(string value) => $"\"{value.Replace("\"", "\\\"")}\"";
}
