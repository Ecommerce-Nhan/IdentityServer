using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using System.Security.Claims;

namespace IdentityServer.Application.Services.TokenServices;

public interface ITokenService
{
    ClaimsPrincipal CreateClaimsPrincipalAsync(OpenIddictRequest request, ClaimsPrincipal userPrincipal);
    Task<IActionResult> HandleTokenRequestAsync(OpenIddictRequest request, HttpContext httpContext);
}