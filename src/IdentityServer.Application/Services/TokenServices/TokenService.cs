using IdentityServer.Persistence.Entities;
using IdentityServer.Shared.Commons;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
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
    private readonly UserManager<ApplicationUser> _userManager;

    public TokenService(IOptions<OptionsPattern.OpenIddict> options,
        UserManager<ApplicationUser> userManager)
    {
        _options = options.Value;
        _userManager = userManager;
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
        else if (request.IsPasswordGrantType())
        {
            var user = await ValidateUserAsync(request.Username!, request.Password!);
            if (user == null)
            {
                return new Microsoft.AspNetCore.Mvc.ForbidResult(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            var principal = await CreateClaimsPrincipalFromUser(request, user);
            return new Microsoft.AspNetCore.Mvc.SignInResult(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, principal);
        }

        return new BadRequestObjectResult(new
        {
            Errors.UnsupportedGrantType,
            ErrorConstants.GrantType
        });
    }


    private async Task<ClaimsPrincipal> CreateClaimsPrincipalFromUser(OpenIddictRequest request, ApplicationUser user)
    {
        var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var roleUser = await _userManager.GetRolesAsync(user);
        if (roleUser.Any())
        {
            identity.SetClaim(ClaimTypes.Role, string.Join(", ", roleUser));
        }

        identity.SetClaim(Claims.Subject, user.Id);
        identity.SetClaim(ClaimTypes.Email, user.Email);
        identity.SetClaim(Claims.Audience, _options.Issuer);

        identity.SetDestinations(claim =>
        {
            switch (claim.Type)
            {
                case Claims.Subject:
                case ClaimTypes.Email:
                    return new[] { Destinations.AccessToken, Destinations.IdentityToken };
                default:
                    return new[] { Destinations.AccessToken };
            }
        });

        return new ClaimsPrincipal(identity);
    }

    private async Task<ApplicationUser?> ValidateUserAsync(string username, string password)
    {
        var user = await _userManager.FindByNameAsync(username);
        if (user == null) return null;

        if (!await _userManager.CheckPasswordAsync(user, password))
            return null;

        if (!await _userManager.IsEmailConfirmedAsync(user))
            return null;

        return user;
    }

    private static IEnumerable<string> GetDestinations(Claim claim) =>
        claim.Type switch
        {
            Claims.Name or Claims.Subject => new[] { Destinations.AccessToken, Destinations.IdentityToken },
            _ => new[] { Destinations.AccessToken },
        };
}