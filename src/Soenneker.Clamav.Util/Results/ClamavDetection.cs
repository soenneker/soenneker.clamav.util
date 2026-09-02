namespace Soenneker.Clamav.Util.Results;

/// <summary>
/// Describes one malware signature reported by ClamAV.
/// </summary>
/// <param name="Path">The scanned path associated with the detection.</param>
/// <param name="Signature">The ClamAV signature name.</param>
public sealed record ClamavDetection(string Path, string Signature);
