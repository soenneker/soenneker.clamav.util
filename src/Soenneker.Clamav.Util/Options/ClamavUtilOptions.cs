namespace Soenneker.Clamav.Util.Options;

/// <summary>
/// Configures shared ClamAV utility behavior.
/// </summary>
public sealed class ClamavUtilOptions
{
    /// <summary>
    /// Gets or sets whether scans use a persistent ClamAV daemon. This avoids loading the virus database for every scan. Defaults to
    /// <see langword="false"/>.
    /// </summary>
    public bool UseDaemon { get; set; }

    /// <summary>
    /// Gets or sets the loopback TCP port used by the managed ClamAV daemon. Defaults to 3310.
    /// </summary>
    public int DaemonPort { get; set; } = 3310;
}
