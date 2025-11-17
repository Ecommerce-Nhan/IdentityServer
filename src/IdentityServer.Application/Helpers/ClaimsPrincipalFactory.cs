using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServer.Application.Helpers;

public class ClaimsPrincipalFactory
{
    private readonly string _issuer;

    public ClaimsPrincipalFactory(string issuer)
    {
        _issuer = issuer;
    }

    public ClaimsPrincipal Create(string subject, string? email = null, string? role = null, string? permission = null)
    {
        var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        identity.SetClaim(Claims.Subject, subject);
        identity.SetClaim(Claims.Audience, _issuer);

        if (!string.IsNullOrEmpty(email))
            identity.SetClaim(ClaimTypes.Email, email);

        if (!string.IsNullOrEmpty(role))
            identity.AddClaim(ClaimTypes.Role, role);

        if (!string.IsNullOrEmpty(permission))
            identity.AddClaim("Permission", permission);

        identity.SetDestinations(GetDestinations);

        return new ClaimsPrincipal(identity);
    }

    private static IEnumerable<string> GetDestinations(Claim claim) =>
        claim.Type switch
        {
            Claims.Name or Claims.Subject => new[] { Destinations.AccessToken, Destinations.IdentityToken },
            _ => new[] { Destinations.AccessToken },
        };

}