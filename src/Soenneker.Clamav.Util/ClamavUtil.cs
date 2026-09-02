using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Soenneker.Clamav.Util.Abstract;
using Soenneker.Clamav.Util.Options;
using Soenneker.Clamav.Util.Results;
using Soenneker.Utils.Process.Abstract;

namespace Soenneker.Clamav.Util;

public sealed class ClamavUtil : IClamavUtil
{
    private static readonly SemaphoreSlim _definitionLock = new(1, 1);
    private static readonly string[] _definitionPatterns = ["*.cvd", "*.cld", "*.cud"];
    private static readonly Encoding _utf8WithoutBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

    private readonly IProcessUtil _processUtil;
    private readonly string _runtimeDirectory;
    private readonly string _scannerPath;
    private readonly string _freshclamPath;
    private readonly string _certificatesDirectory;
    private readonly string _defaultDatabaseDirectory;
    private readonly Dictionary<string, string>? _environmentVariables;

    public ClamavUtil(IProcessUtil processUtil)
    {
        _processUtil = processUtil ?? throw new ArgumentNullException(nameof(processUtil));
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

    public ValueTask<ClamavScanResult> Scan(string path, ClamavScanOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        string fullPath = Path.GetFullPath(path);

        if (File.Exists(fullPath))
            return ScanFile(fullPath, options, cancellationToken);
        if (Directory.Exists(fullPath))
            return ScanDirectory(fullPath, options, cancellationToken);

        throw new FileNotFoundException("The ClamAV scan target was not found.", fullPath);
    }

    public ValueTask<ClamavScanResult> ScanFile(string filePath, ClamavScanOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        string fullPath = Path.GetFullPath(filePath);
        if (!File.Exists(fullPath))
            throw new FileNotFoundException("The file to scan was not found.", fullPath);

        return ScanCore(fullPath, isDirectory: false, options ?? new ClamavScanOptions(), cancellationToken);
    }

    public ValueTask<ClamavScanResult> ScanDirectory(string directoryPath, ClamavScanOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directoryPath);
        string fullPath = Path.GetFullPath(directoryPath);
        if (!Directory.Exists(fullPath))
            throw new DirectoryNotFoundException($"The directory to scan was not found: {fullPath}");

        return ScanCore(fullPath, isDirectory: true, options ?? new ClamavScanOptions(), cancellationToken);
    }

    public async ValueTask<IReadOnlyList<string>> UpdateDefinitions(string? databaseDirectory = null,
        CancellationToken cancellationToken = default)
    {
        EnsureToolExists(_freshclamPath, "freshclam");
        EnsureExecutable(_freshclamPath);

        string fullDatabaseDirectory = GetDatabaseDirectory(databaseDirectory);
        Directory.CreateDirectory(fullDatabaseDirectory);
        string configurationPath = Path.Combine(fullDatabaseDirectory, "freshclam.conf");

        await _definitionLock.WaitAsync(cancellationToken);
        try
        {
            string configuration = BuildFreshclamConfiguration();
            await File.WriteAllTextAsync(configurationPath, configuration, _utf8WithoutBom, cancellationToken);

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
        EnsureToolExists(_scannerPath, "clamscan");
        EnsureExecutable(_scannerPath);

        List<string> output = await _processUtil.Start(_scannerPath, _runtimeDirectory, "--version", log: false,
            environmentalVars: _environmentVariables, cancellationToken: cancellationToken);
        return output.Count == 0 ? string.Empty : output[0];
    }

    private async ValueTask<ClamavScanResult> ScanCore(string targetPath, bool isDirectory, ClamavScanOptions options,
        CancellationToken cancellationToken)
    {
        Validate(options);
        EnsureToolExists(_scannerPath, "clamscan");
        EnsureExecutable(_scannerPath);

        string databaseDirectory = GetDatabaseDirectory(options.DatabaseDirectory);
        if (!HasDefinitions(databaseDirectory))
        {
            if (!options.UpdateDefinitionsIfMissing)
                throw new InvalidOperationException($"No ClamAV virus definitions were found in '{databaseDirectory}'.");

            await UpdateDefinitions(databaseDirectory, cancellationToken);
        }

        string logPath = Path.Combine(Path.GetTempPath(), $"soenneker-clamav-{Guid.NewGuid():N}.log");
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

            if (File.Exists(logPath))
                output = (await File.ReadAllLinesAsync(logPath, cancellationToken)).ToList();

            List<ClamavDetection> detections = ParseDetections(output);
            return new ClamavScanResult(targetPath, infected, detections, output);
        }
        finally
        {
            if (File.Exists(logPath))
                File.Delete(logPath);
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
            new[] { Path.Combine(_runtimeDirectory, "lib64"), Path.Combine(_runtimeDirectory, "lib") }
                .Where(Directory.Exists));
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

    private static bool HasDefinitions(string directory)
    {
        if (!Directory.Exists(directory))
            return false;

        return _definitionPatterns.Any(pattern => Directory.EnumerateFiles(directory, pattern, SearchOption.TopDirectoryOnly).Any());
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

        return exception.Message[(separator + Environment.NewLine.Length)..]
                        .Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries)
                        .ToList();
    }

    private static void Validate(ClamavScanOptions options)
    {
        if (options.Timeout is { } timeout && timeout <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(options), "The scan timeout must be greater than zero.");
    }

    private static void EnsureToolExists(string path, string tool)
    {
        if (!File.Exists(path))
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
