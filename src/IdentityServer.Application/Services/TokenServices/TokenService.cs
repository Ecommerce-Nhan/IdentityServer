using IdentityServer.Shared.Commons;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using static IdentityServer.Shared.Commons.Constants;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServer.Application.Services.TokenServices;

public class TokenService : ITokenService
{
    private readonly OptionsPattern.OpenIddict _options;

    public TokenService(IOptions<OptionsPattern.OpenIddict> options)
    {
        _options = options.Value;
    }

    public ClaimsPrincipal CreateClaimsPrincipalAsync(OpenIddictRequest request, ClaimsPrincipal? principal)
    {
        var claimsIdentity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        claimsIdentity.SetClaim(Claims.Subject, request.ClientId);
        claimsIdentity.SetClaim(Claims.Audience, _options.Issuer);
        claimsIdentity.SetClaim(ClaimTypes.Email, principal?.FindFirst(Claims.Name)?.Value);
        claimsIdentity.SetDestinations(GetDestinations);

        return new ClaimsPrincipal(claimsIdentity);
    }

    public async Task<IActionResult> HandleTokenRequestAsync(OpenIddictRequest request, HttpContext context)
    {
        var result = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        if (request.IsAuthorizationCodeGrantType())
        {
            var principal = CreateClaimsPrincipalAsync(request, result.Principal);
            return new Microsoft.AspNetCore.Mvc.SignInResult(authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, principal);
        }

        return new BadRequestObjectResult(new
        {
            Errors.UnsupportedGrantType,
            ErrorConstants.GrantType
        });
    }

    private static IEnumerable<string> GetDestinations(Claim claim) =>
        claim.Type switch
        {
            Claims.Name or Claims.Subject => new[] { Destinations.AccessToken, Destinations.IdentityToken },
            _ => new[] { Destinations.AccessToken },
        };
}