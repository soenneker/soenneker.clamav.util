[![](https://img.shields.io/nuget/v/soenneker.clamav.util.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.clamav.util/)

# Soenneker.Clamav.Util

A cross-platform .NET API for scanning files and directories with bundled official ClamAV command-line distributions.

## Install

```bash
dotnet add package Soenneker.Clamav.Util
```

## Quick start

```csharp
using Microsoft.Extensions.DependencyInjection;
using Soenneker.Clamav.Util.Abstract;
using Soenneker.Clamav.Util.Registrars;

await using ServiceProvider provider = new ServiceCollection()
    .AddLogging()
    .AddClamavUtilAsSingleton()
    .BuildServiceProvider();

IClamavUtil clamav = provider.GetRequiredService<IClamavUtil>();

var fileResult = await clamav.ScanFile("uploads/document.pdf");
if (fileResult.IsInfected)
{
    foreach (var detection in fileResult.Detections)
        Console.WriteLine($"{detection.Path}: {detection.Signature}");
}

var directoryResult = await clamav.ScanDirectory("uploads");
```

Virus definitions are downloaded with `freshclam` before the first scan and stored in `Resources/clamav-database` beneath the application output directory. Use a custom writable location when appropriate:

```csharp
using Soenneker.Clamav.Util.Options;

var result = await clamav.Scan("uploads", new ClamavScanOptions
{
    DatabaseDirectory = "/var/lib/my-app/clamav",
    DetectPotentiallyUnwantedApplications = true,
    AllMatches = true,
    Timeout = TimeSpan.FromMinutes(10)
});
```

Definitions can also be managed explicitly:

```csharp
await clamav.UpdateDefinitions("data/clamav");

var result = await clamav.ScanFile("sample.zip", new ClamavScanOptions
{
    DatabaseDirectory = "data/clamav",
    UpdateDefinitionsIfMissing = false
});
```

## Supported environments

| Operating system | Architecture | Bundled tool |
| --- | --- | --- |
| Windows | x64 | `clamscan.exe` |
| Linux | x64 | `clamscan` |

Other operating systems and architectures throw `PlatformNotSupportedException`.

The native packages are sourced from official [Cisco-Talos/clamav releases](https://github.com/Cisco-Talos/clamav/releases) and are distributed under GPL-2.0-only.
