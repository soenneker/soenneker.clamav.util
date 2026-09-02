using System.Collections.Generic;

namespace Soenneker.Clamav.Util.Results;

/// <summary>
/// Represents the completed result of a ClamAV scan.
/// </summary>
public sealed class ClamavScanResult
{
    /// <summary>
    /// Gets the path supplied to the scan.
    /// </summary>
    public string TargetPath { get; }

    /// <summary>
    /// Gets whether ClamAV reported at least one threat.
    /// </summary>
    public bool IsInfected { get; }

    /// <summary>
    /// Gets whether ClamAV reported the target as clean.
    /// </summary>
    public bool IsClean => !IsInfected;

    /// <summary>
    /// Gets the parsed malware detections.
    /// </summary>
    public IReadOnlyList<ClamavDetection> Detections { get; }

    /// <summary>
    /// Gets all output lines written by the native scanner.
    /// </summary>
    public IReadOnlyList<string> Output { get; }

    internal ClamavScanResult(string targetPath, bool isInfected, IReadOnlyList<ClamavDetection> detections,
        IReadOnlyList<string> output)
    {
        TargetPath = targetPath;
        IsInfected = isInfected;
        Detections = detections;
        Output = output;
    }
}
