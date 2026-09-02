[![](https://img.shields.io/nuget/v/soenneker.clamav.util.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.clamav.util/)

# Soenneker.Clamav.Util

A cross-platform .NET API for scanning files and directories with bundled official ClamAV command-line distributions.

## Install

```bash
dotnet add package Soenneker.Clamav.Util
dotnet add package Soenneker.Clamav.Definitions
```

`Soenneker.Clamav.Definitions` is optional but recommended for ephemeral containers. It copies a recent database seed into `Resources/clamav-database`; `freshclam` then updates that seed instead of downloading every full database when a new container starts. Pin the package version for reproducible application builds and update it through your normal dependency-update process.

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

Virus definitions are updated with `freshclam` before the first scan when they are missing and stored in `Resources/clamav-database` beneath the application output directory. Use a custom writable location when appropriate:

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

## Licensing

`Soenneker.Clamav.Util` is MIT-licensed. Its native package dependencies redistribute official ClamAV binaries under GPL-2.0-only; those terms apply to the bundled native payload. Each native package includes the GPL text, upstream third-party notices, and an exact corresponding-source reference in its runtime `SOURCE.txt`.

See the official [Cisco-Talos/clamav releases](https://github.com/Cisco-Talos/clamav/releases) for upstream release and source materials.
