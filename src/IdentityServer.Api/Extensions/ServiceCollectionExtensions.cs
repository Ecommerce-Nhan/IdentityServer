using IdentityServer.Application.Helpers;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.OpenApi.Models;
using static gRPCServer.User.Protos.UserProtoService;
using static IdentityServer.Shared.Commons.OptionsPattern;

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

    public static IServiceCollection AddGrpcConfiguration(this IServiceCollection services, IConfiguration configuration)
    {
        var authOptions = configuration.GetSection(nameof(AuthOptions)).Get<AuthOptions>()!;
        services.AddSingleton(new ClaimsPrincipalFactory(authOptions.ServerIssuer));
        services.AddGrpcClient<UserProtoServiceClient>(s => s.Address = new Uri(authOptions.UserServiceEndpoint));

        return services;
    }
}
