using IdentityServer.Persistence;
using IdentityServer.Shared.Commons;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;
using System.Text;

namespace IdentityServer.Api.Extensions;

public static class OpenIddictExtensions
{
    public static IServiceCollection AddCustomOpenIddict(this IServiceCollection services, WebApplicationBuilder builder)
    {
        var openIddictOptions = builder.Configuration.GetSection(nameof(OptionsPattern.OpenIddict)).Get<OptionsPattern.OpenIddict>()!;
        services.AddOpenIddict()
                .AddCore(options =>
                {
                    options.UseEntityFrameworkCore()
                           .UseDbContext<ApplicationDbContext>();

                    options.UseQuartz()
                           .SetMinimumAuthorizationLifespan(TimeSpan.FromDays(7))
                           .SetMinimumTokenLifespan(TimeSpan.FromDays(1))
                           .SetMaximumRefireCount(3);
                })
                .AddServer(options =>
                {
                    options.TokenConfiguration();
                    options.SignatureConfiguration(builder.Configuration);

                    options.UseAspNetCore().EnableTokenEndpointPassthrough()
                                           .EnableAuthorizationEndpointPassthrough();
                })
                .AddValidation(options =>
                {
                    options.SetIssuer(openIddictOptions.Issuer);
                    options.UseLocalServer();
                    options.UseAspNetCore();
                });

        return services;
    }

    private static OpenIddictServerBuilder TokenConfiguration(this OpenIddictServerBuilder builder)
    {
        builder.AllowAuthorizationCodeFlow()
               .RequireProofKeyForCodeExchange();

        builder.SetAuthorizationEndpointUris("api/identity/authorize")
               .SetTokenEndpointUris("api/identity/token");

        builder.SetAccessTokenLifetime(TimeSpan.FromDays(1));

        return builder;
    }

    private static OpenIddictServerBuilder SignatureConfiguration(this OpenIddictServerBuilder builder, IConfiguration configuration)
    {
        var openIddictOptions = configuration.GetSection(nameof(OptionsPattern.OpenIddict)).Get<OptionsPattern.OpenIddict>()!;

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(openIddictOptions.KeySignature));
        var signingCert = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        builder.AddSigningCredentials(signingCert);

        builder.AddEphemeralEncryptionKey()
               .AddEphemeralSigningKey()
               .DisableAccessTokenEncryption();

        builder.SetIssuer(openIddictOptions.Issuer);

        return builder;
    }
}
