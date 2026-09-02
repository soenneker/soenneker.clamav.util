using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Soenneker.Clamav.Util.Abstract;
using Soenneker.Clamav.Util.Options;
using Soenneker.Clamav.Util.Results;
using Soenneker.Utils.Directory.Abstract;
using Soenneker.Utils.File.Abstract;
using Soenneker.Utils.Path.Abstract;
using Soenneker.Utils.Process.Abstract;

namespace Soenneker.Clamav.Util;

public sealed class ClamavUtil : IClamavUtil
{
    private static readonly SemaphoreSlim _definitionLock = new(1, 1);
    private static readonly string[] _definitionExtensions = ["cvd", "cld", "cud"];

    private readonly IProcessUtil _processUtil;
    private readonly IFileUtil _fileUtil;
    private readonly IDirectoryUtil _directoryUtil;
    private readonly IPathUtil _pathUtil;
    private readonly string _runtimeDirectory;
    private readonly string _scannerPath;
    private readonly string _freshclamPath;
    private readonly string _certificatesDirectory;
    private readonly string _defaultDatabaseDirectory;
    private readonly Dictionary<string, string>? _environmentVariables;

    public ClamavUtil(IProcessUtil processUtil, IFileUtil fileUtil, IDirectoryUtil directoryUtil, IPathUtil pathUtil)
    {
        _processUtil = processUtil ?? throw new ArgumentNullException(nameof(processUtil));
        _fileUtil = fileUtil ?? throw new ArgumentNullException(nameof(fileUtil));
        _directoryUtil = directoryUtil ?? throw new ArgumentNullException(nameof(directoryUtil));
        _pathUtil = pathUtil ?? throw new ArgumentNullException(nameof(pathUtil));
        EnsureSupportedPlatform();

        bool windows = OperatingSystem.IsWindows();
        string runtimeIdentifier = windows ? "win-x64" : "linux-x64";
        _runtimeDirectory = Path.Combine(AppContext.BaseDirectory, "Resources", runtimeIdentifier, "clamav");
        string binaryDirectory = windows ? _runtimeDirectory : Path.Combine(_runtimeDirectory, "bin");
        _scannerPath = Path.Combine(binaryDirectory, windows ? "clamscan.exe" : "clamscan");
        _freshclamPath = Path.Combine(binaryDirectory, windows ? "freshclam.exe" : "freshclam");
        _certificatesDirectory = windows ? Path.Combine(_runtimeDirectory, "certs") : Path.Combine(_runtimeDirectory, "etc", "certs");
        _defaultDatabaseDirectory = Path.Combine(AppContext.BaseDirectory, "Resources", "clamav-database");

        if (!windows)
            _environmentVariables = BuildLinuxEnvironment();
    }

    public async ValueTask<ClamavScanResult> Scan(string path, ClamavScanOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        string fullPath = Path.GetFullPath(path);

        if (await _fileUtil.Exists(fullPath, cancellationToken))
            return await ScanFile(fullPath, options, cancellationToken);
        if (await _directoryUtil.Exists(fullPath, cancellationToken))
            return await ScanDirectory(fullPath, options, cancellationToken);

        throw new FileNotFoundException("The ClamAV scan target was not found.", fullPath);
    }

    public async ValueTask<ClamavScanResult> ScanFile(string filePath, ClamavScanOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        string fullPath = Path.GetFullPath(filePath);
        if (!await _fileUtil.Exists(fullPath, cancellationToken))
            throw new FileNotFoundException("The file to scan was not found.", fullPath);

        return await ScanCore(fullPath, isDirectory: false, options ?? new ClamavScanOptions(), cancellationToken);
    }

    public async ValueTask<ClamavScanResult> ScanDirectory(string directoryPath, ClamavScanOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directoryPath);
        string fullPath = Path.GetFullPath(directoryPath);
        if (!await _directoryUtil.Exists(fullPath, cancellationToken))
            throw new DirectoryNotFoundException($"The directory to scan was not found: {fullPath}");

        return await ScanCore(fullPath, isDirectory: true, options ?? new ClamavScanOptions(), cancellationToken);
    }

    public async ValueTask<IReadOnlyList<string>> UpdateDefinitions(string? databaseDirectory = null,
        CancellationToken cancellationToken = default)
    {
        await EnsureToolExists(_freshclamPath, "freshclam", cancellationToken);
        EnsureExecutable(_freshclamPath);

        string fullDatabaseDirectory = GetDatabaseDirectory(databaseDirectory);
        await _directoryUtil.Create(fullDatabaseDirectory, log: false, cancellationToken);
        string configurationPath = Path.Combine(fullDatabaseDirectory, "freshclam.conf");

        await _definitionLock.WaitAsync(cancellationToken);
        try
        {
            string configuration = BuildFreshclamConfiguration();
            await _fileUtil.Write(configurationPath, configuration, log: false, cancellationToken);

            string arguments = $"--config-file={Quote(configurationPath)} --datadir={Quote(fullDatabaseDirectory)} " +
                               $"--cvdcertsdir={Quote(_certificatesDirectory)} --stdout";
            return await _processUtil.Start(_freshclamPath, _runtimeDirectory, arguments, log: false,
                environmentalVars: _environmentVariables, cancellationToken: cancellationToken);
        }
        finally
        {
            _definitionLock.Release();
        }
    }

    public async ValueTask<string> GetVersion(CancellationToken cancellationToken = default)
    {
        await EnsureToolExists(_scannerPath, "clamscan", cancellationToken);
        EnsureExecutable(_scannerPath);

        List<string> output = await _processUtil.Start(_scannerPath, _runtimeDirectory, "--version", log: false,
            environmentalVars: _environmentVariables, cancellationToken: cancellationToken);
        return output.Count == 0 ? string.Empty : output[0];
    }

    private async ValueTask<ClamavScanResult> ScanCore(string targetPath, bool isDirectory, ClamavScanOptions options,
        CancellationToken cancellationToken)
    {
        Validate(options);
        await EnsureToolExists(_scannerPath, "clamscan", cancellationToken);
        EnsureExecutable(_scannerPath);

        string databaseDirectory = GetDatabaseDirectory(options.DatabaseDirectory);
        if (!await HasDefinitions(databaseDirectory, cancellationToken))
        {
            if (!options.UpdateDefinitionsIfMissing)
                throw new InvalidOperationException($"No ClamAV virus definitions were found in '{databaseDirectory}'.");

            await UpdateDefinitions(databaseDirectory, cancellationToken);
        }

        string logPath = await _pathUtil.GetRandomTempFilePath(".log", cancellationToken);
        string arguments = BuildScanArguments(targetPath, databaseDirectory, logPath, isDirectory, options);
        List<string> output;
        bool infected = false;

        try
        {
            try
            {
                output = await _processUtil.Start(_scannerPath, _runtimeDirectory, arguments, timeout: options.Timeout, log: false,
                    environmentalVars: _environmentVariables, cancellationToken: cancellationToken);
            }
            catch (InvalidOperationException exception) when (IsThreatExitCode(exception))
            {
                infected = true;
                output = ExtractOutput(exception);
            }

            if (await _fileUtil.Exists(logPath, cancellationToken))
                output = await _fileUtil.ReadAsLines(logPath, log: false, cancellationToken);

            List<ClamavDetection> detections = ParseDetections(output);
            return new ClamavScanResult(targetPath, infected, detections, output);
        }
        finally
        {
            await _fileUtil.TryDelete(logPath, log: false, CancellationToken.None);
        }
    }

    private string BuildScanArguments(string targetPath, string databaseDirectory, string logPath, bool isDirectory, ClamavScanOptions options)
    {
        var builder = new StringBuilder(256);
        builder.Append("--database=").Append(Quote(databaseDirectory))
               .Append(" --log=").Append(Quote(logPath))
               .Append(" --stdout");

        if (isDirectory)
            builder.Append(options.Recursive ? " --recursive=yes" : " --recursive=no");
        if (options.DetectPotentiallyUnwantedApplications)
            builder.Append(" --detect-pua=yes");
        if (options.AllMatches)
            builder.Append(" --allmatch=yes");

        builder.Append(options.FollowFileSymbolicLinks ? " --follow-file-symlinks=2" : " --follow-file-symlinks=0");
        builder.Append(options.FollowDirectorySymbolicLinks ? " --follow-dir-symlinks=2" : " --follow-dir-symlinks=0");
        builder.Append(' ').Append(Quote(targetPath));
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

    private static string BuildFreshclamConfiguration()
    {
        var builder = new StringBuilder()
            .AppendLine("DatabaseMirror database.clamav.net")
            .AppendLine("ScriptedUpdates yes")
            .AppendLine("CompressLocalDatabase no")
            .AppendLine("Checks 12");

        if (OperatingSystem.IsLinux())
            builder.Append("DatabaseOwner ").AppendLine(Environment.UserName);

        return builder.ToString();
    }

    private async ValueTask<bool> HasDefinitions(string directory, CancellationToken cancellationToken)
    {
        if (!await _directoryUtil.Exists(directory, cancellationToken))
            return false;

        foreach (string extension in _definitionExtensions)
        {
            if ((await _directoryUtil.GetFilesByExtension(directory, extension, recursive: false, cancellationToken)).Count > 0)
                return true;
        }

        return false;
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
        if (!await _fileUtil.Exists(path, cancellationToken))
            throw new FileNotFoundException($"The bundled {tool} executable was not found.", path);
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
            (!OperatingSystem.IsLinux() && !OperatingSystem.IsWindows()))
            throw new PlatformNotSupportedException("Soenneker.Clamav.Util currently supports Linux x64 and Windows x64.");
    }

    private static string Quote(string value) => $"\"{value.Replace("\"", "\\\"")}\"";
}
