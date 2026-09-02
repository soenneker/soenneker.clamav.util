using System.Threading.Tasks;
using Soenneker.Clamav.Util.Abstract;
using Soenneker.Extensions.ValueTask;
using Soenneker.Tests.HostedUnit;

namespace Soenneker.Clamav.Util.Tests;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
public sealed class ClamavUtilTests : HostedUnitTest
{
    private readonly IClamavUtil _util;

    public ClamavUtilTests(Host host) : base(host)
    {
        _util = Resolve<IClamavUtil>(true);
    }

    [Test]
    public async Task Gets_bundled_version()
    {
        string version = await _util.GetVersion().NoSync();
        await Assert.That(version).StartsWith("ClamAV ");
    }

}
