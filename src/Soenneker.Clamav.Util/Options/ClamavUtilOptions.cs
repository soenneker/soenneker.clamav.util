namespace Soenneker.Clamav.Util.Options;

/// <summary>
/// Configures shared ClamAV utility behavior.
/// </summary>
public sealed class ClamavUtilOptions
{
    /// <summary>
    /// Gets or sets the maximum number of ClamAV scan processes that may run concurrently. The default is 4.
    /// </summary>
    public int MaxConcurrency { get; set; } = 4;
}
