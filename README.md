[![](https://img.shields.io/nuget/v/soenneker.clamav.util.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.clamav.util/)

# Soenneker.Clamav.Util

A cross-platform .NET API for scanning files and directories with bundled official ClamAV command-line distributions.

## Install

```bash
dotnet add package Soenneker.Clamav.Util
```

`Soenneker.Clamav.Util` depends on `Soenneker.Clamav.Definitions`. NuGet restore copies its recent database seed into `Resources/clamav-database`; FreshClam updates that same directory in place, allowing it to download incremental updates instead of every complete database.

## Quick start

```csharp
using Microsoft.Extensions.DependencyInjection;
using Soenneker.Clamav.Util.Abstract;
using Soenneker.Clamav.Util.Registrars;

await using ServiceProvider provider = new ServiceCollection()
    .AddLogging()
    .AddClamavUtilAsSingleton(options => options.MaxConcurrency = 4)
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

Virus definitions are updated with `freshclam` once before the first scan and stored in `Resources/clamav-database` beneath the application output directory. Concurrent first scans share that initialization operation. Use a custom writable location when appropriate:

```csharp
using Soenneker.Clamav.Util.Options;

var result = await clamav.Scan("uploads", new ClamavScanOptions
{
    DatabaseDirectory = "/var/lib/my-app/clamav",
    UpdateDefinitions = true,
    DetectPotentiallyUnwantedApplications = true,
    AllMatches = true,
    Timeout = TimeSpan.FromMinutes(10)
});
```

By default, FreshClam checks for incremental updates to the packaged seed before the first scan for each database directory. Set `UpdateDefinitions` to `false` to skip initialization; the scan will then require an existing database. Call `UpdateDefinitions` explicitly when the definitions need to be refreshed later.

`MaxConcurrency` limits the number of `clamscan` processes within one `ClamavUtil` instance. Singleton registration provides an application-wide limit. Scoped registration creates a separate limit and definition initializer for every scope.

Definitions can also be managed explicitly:

```csharp
await clamav.UpdateDefinitions("data/clamav");

var result = await clamav.ScanFile("sample.zip", new ClamavScanOptions
{
    DatabaseDirectory = "data/clamav",
    UpdateDefinitions = false
});
```

Definition updates are delegated to `Soenneker.Clamav.Freshclam.Util`, which selects the separately packaged Linux or Windows FreshClam runtime.

## Supported environments

| Operating system | Architecture | Bundled tool |
| --- | --- | --- |
| Windows | x64 | `clamscan.exe` |
| Linux | x64 | `clamscan` |

Other operating systems and architectures throw `PlatformNotSupportedException`.

## Licensing

`Soenneker.Clamav.Util` is MIT-licensed. Its native package dependencies redistribute official ClamAV binaries under GPL-2.0-only; those terms apply to the bundled native payload. Each native package includes the GPL text, upstream third-party notices, and an exact corresponding-source reference in its runtime `SOURCE.txt`.

See the official [Cisco-Talos/clamav releases](https://github.com/Cisco-Talos/clamav/releases) for upstream release and source materials.
