using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Soenneker.Clamav.Util.Abstract;
using Soenneker.Utils.Directory.Registrars;
using Soenneker.Utils.File.Registrars;
using Soenneker.Utils.Process.Registrars;

namespace Soenneker.Clamav.Util.Registrars;

/// <summary>
/// A structured, cross-platform .NET API for malware scanning with bundled ClamAV command-line distributions.
/// </summary>
public static class ClamavUtilRegistrar
{
    /// <summary>
    /// Adds <see cref="IClamavUtil"/> as a singleton service. <para/>
    /// </summary>
    public static IServiceCollection AddClamavUtilAsSingleton(this IServiceCollection services)
    {
        services.AddDirectoryUtilAsSingleton()
                .AddFileUtilAsSingleton()
                .AddProcessUtilAsSingleton()
                .TryAddSingleton<IClamavUtil, ClamavUtil>();

        return services;
    }

    /// <summary>
    /// Adds <see cref="IClamavUtil"/> as a scoped service. <para/>
    /// </summary>
    public static IServiceCollection AddClamavUtilAsScoped(this IServiceCollection services)
    {
        services.AddDirectoryUtilAsScoped()
                .AddFileUtilAsScoped()
                .AddProcessUtilAsScoped()
                .TryAddScoped<IClamavUtil, ClamavUtil>();

        return services;
    }
}
