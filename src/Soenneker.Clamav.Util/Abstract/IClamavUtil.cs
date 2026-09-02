using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Soenneker.Clamav.Util.Options;
using Soenneker.Clamav.Util.Results;

namespace Soenneker.Clamav.Util.Abstract;

/// <summary>
/// Provides cross-platform malware scanning with the bundled ClamAV command-line distribution.
/// </summary>
public interface IClamavUtil
{
    /// <summary>
    /// Scans a file or directory, selecting the correct behavior from the target type.
    /// </summary>
    /// <param name="path">The file or directory to scan.</param>
    /// <param name="options">Optional scan and virus-definition settings.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The scan verdict, detections, and native scanner output.</returns>
    ValueTask<ClamavScanResult> Scan(string path, ClamavScanOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Scans one file for malware.
    /// </summary>
    /// <param name="filePath">The file to scan.</param>
    /// <param name="options">Optional scan and virus-definition settings.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The scan verdict, detections, and native scanner output.</returns>
    ValueTask<ClamavScanResult> ScanFile(string filePath, ClamavScanOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Scans a directory for malware.
    /// </summary>
    /// <param name="directoryPath">The directory to scan.</param>
    /// <param name="options">Optional scan and virus-definition settings.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The scan verdict, detections, and native scanner output.</returns>
    ValueTask<ClamavScanResult> ScanDirectory(string directoryPath, ClamavScanOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Downloads or updates the official ClamAV virus definitions.
    /// </summary>
    /// <param name="databaseDirectory">An optional writable database directory. The app-local default is used when omitted.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>Lines written by <c>freshclam</c>.</returns>
    ValueTask<IReadOnlyList<string>> UpdateDefinitions(string? databaseDirectory = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the bundled ClamAV version string.
    /// </summary>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The first line written by <c>clamscan --version</c>.</returns>
    ValueTask<string> GetVersion(CancellationToken cancellationToken = default);
}
