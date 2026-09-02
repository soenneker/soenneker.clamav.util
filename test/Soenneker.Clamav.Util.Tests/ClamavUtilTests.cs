using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Soenneker.Clamav.Util.Abstract;
using Soenneker.Clamav.Util.Options;
using Soenneker.Clamav.Util.Results;
using Soenneker.Extensions.Task;
using Soenneker.Extensions.ValueTask;
using Soenneker.Tests.HostedUnit;
using Soenneker.Utils.Directory.Abstract;
using Soenneker.Utils.File.Abstract;

namespace Soenneker.Clamav.Util.Tests;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
public sealed class ClamavUtilTests : HostedUnitTest
{
    private readonly IClamavUtil _util;
    private readonly IDirectoryUtil _directoryUtil;
    private readonly IFileUtil _fileUtil;

    public ClamavUtilTests(Host host) : base(host)
    {
        _util = Resolve<IClamavUtil>(true);
        _directoryUtil = Resolve<IDirectoryUtil>(true);
        _fileUtil = Resolve<IFileUtil>(true);
    }

    [Test]
    public async Task Gets_bundled_version(CancellationToken cancellationToken)
    {
        string version = await _util.GetVersion(cancellationToken: cancellationToken).NoSync();
        await Assert.That(version).StartsWith("ClamAV ");
    }

    [Test]
    public async Task ScanFile_detects_matching_file_signature(CancellationToken cancellationToken)
    {
        const string payload = "Soenneker ClamAV deterministic test payload";
        const string signatureName = "Soenneker.Clamav.Test";
        string directory = await _directoryUtil.CreateTempDirectory(cancellationToken).NoSync();
        string filePath = Path.Combine(directory, "sample.txt");
        string databasePath = Path.Combine(directory, "local.ndb");

        try
        {
            await _fileUtil.Write(filePath, payload, log: false, cancellationToken: cancellationToken).NoSync();
            var signature = $"{signatureName}:0:*:{Convert.ToHexString(Encoding.UTF8.GetBytes(payload))}";
            await _fileUtil.Write(databasePath, signature, log: false, cancellationToken: cancellationToken).NoSync();

            var options = new ClamavScanOptions
            {
                DatabaseDirectory = directory,
                UpdateDefinitions = false
            };

            ClamavScanResult result = await _util.ScanFile(filePath, options, cancellationToken: cancellationToken).NoSync();

            await Assert.That(result.TargetPath).IsEqualTo(Path.GetFullPath(filePath));
            await Assert.That(result.IsInfected).IsTrue();
            await Assert.That(result.IsClean).IsFalse();
            await Assert.That(result.Detections.Count).IsEqualTo(1);
            await Assert.That(result.Detections[0].Path).IsEqualTo(Path.GetFullPath(filePath));
            await Assert.That(result.Detections[0].Signature).IsEqualTo($"{signatureName}.UNOFFICIAL");
        }
        finally
        {
            await _directoryUtil.DeleteIfExists(directory, cancellationToken).NoSync();
        }
    }
}
