using Microsoft.OpenApi.Models;

namespace IdentityServer.Api.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddCustomSwaggerGen(this IServiceCollection services)
    {
        services.AddSwaggerGen(c => c.SwaggerDoc("v1", new OpenApiInfo { Title = "Api", Version = "v1" }));

        return services;
    }

    public static void ConfigureValidatedOptions<T>(this IServiceCollection services) where T : class
    {
        services.AddOptions<T>()
                .BindConfiguration(typeof(T).Name)
                .ValidateDataAnnotations()
                .ValidateOnStart();
    }
}
