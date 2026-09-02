using System;

namespace Soenneker.Clamav.Util.Options;

/// <summary>
/// Configures a ClamAV file or directory scan.
/// </summary>
public sealed class ClamavScanOptions
{
    /// <summary>
    /// Gets or sets the writable virus-definition directory. The app-local default is used when omitted.
    /// </summary>
    public string? DatabaseDirectory { get; set; }

    /// <summary>
    /// Gets or sets whether missing virus definitions are downloaded before scanning. Defaults to <see langword="true"/>.
    /// </summary>
    public bool UpdateDefinitionsIfMissing { get; set; } = true;

    /// <summary>
    /// Gets or sets whether directory scans recurse into child directories. Defaults to <see langword="true"/>.
    /// </summary>
    public bool Recursive { get; set; } = true;

    /// <summary>
    /// Gets or sets whether potentially unwanted applications are detected.
    /// </summary>
    public bool DetectPotentiallyUnwantedApplications { get; set; }

    /// <summary>
    /// Gets or sets whether scanning continues after the first match in a file.
    /// </summary>
    public bool AllMatches { get; set; }

    /// <summary>
    /// Gets or sets whether symbolic links to files are followed.
    /// </summary>
    public bool FollowFileSymbolicLinks { get; set; }

    /// <summary>
    /// Gets or sets whether symbolic links to directories are followed.
    /// </summary>
    public bool FollowDirectorySymbolicLinks { get; set; }

    /// <summary>
    /// Gets or sets the maximum scan duration. A null value allows ClamAV to run until completion or cancellation.
    /// </summary>
    public TimeSpan? Timeout { get; set; }
}
