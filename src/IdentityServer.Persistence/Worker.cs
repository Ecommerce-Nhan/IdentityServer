using IdentityServer.Shared.Commons;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using static IdentityServer.Shared.Commons.Constants;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServer.Persistence;

public class Worker : IHostedService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly OptionsPattern.OpenIddict _options;

    public Worker(IServiceProvider serviceProvider, IOptions<OptionsPattern.OpenIddict> options)
    {
        _serviceProvider = serviceProvider;
        _options = options.Value;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = _serviceProvider.CreateAsyncScope();

        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await context.Database.EnsureCreatedAsync(cancellationToken);

        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        if (await manager.FindByClientIdAsync(ClientConstants.Ecommerce_ClientId, cancellationToken) == null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ApplicationType = ApplicationTypes.Web,
                ClientId = ClientConstants.Ecommerce_ClientId,
                ClientSecret = ClientConstants.Ecommerce_ClientSecret,
                DisplayName = ClientConstants.Ecommerce_DisplayName,
                RedirectUris = { new Uri(_options.RedirectUriCadastral) },
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.Authorization,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles
                },
                Requirements =
                {
                    Requirements.Features.ProofKeyForCodeExchange
                }
            }, cancellationToken);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}