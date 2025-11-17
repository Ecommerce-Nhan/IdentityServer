using gRPCServer.User.Protos;
using IdentityServer.Application.Helpers;
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
using static gRPCServer.User.Protos.UserProtoService;
using static IdentityServer.Shared.Commons.Constants;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServer.Application.Services.TokenServices;

public class TokenService : ITokenService
{
    private readonly OptionsPattern.OpenIddict _options;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly UserProtoServiceClient _userProtoServiceClient;
    private readonly ClaimsPrincipalFactory _claimsPrincipalFactory;

    public TokenService(IOptions<OptionsPattern.OpenIddict> options,
        UserManager<ApplicationUser> userManager,
        UserProtoServiceClient userProtoServiceClient,
        ClaimsPrincipalFactory claimsPrincipalFactory)
    {
        _options = options.Value;
        _userManager = userManager;
        _userProtoServiceClient = userProtoServiceClient;
        _claimsPrincipalFactory = claimsPrincipalFactory;
    }

    public async Task<IActionResult> HandleTokenRequestAsync(OpenIddictRequest request, HttpContext context)
    {
        var result = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        if (request.IsAuthorizationCodeGrantType())
        {
            var principal = CreateClaimsPrincipalAuthenticateFlow(request, result.Principal);
            return new Microsoft.AspNetCore.Mvc.SignInResult(authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, principal);
        }
        else if (request.IsPasswordGrantType())
        {
            var principal = await CreateClaimsPrincipalPasswordFlow(request);
            return new Microsoft.AspNetCore.Mvc.SignInResult(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, principal);
        }

        return new BadRequestObjectResult(new
        {
            Errors.UnsupportedGrantType,
            ErrorConstants.GrantType
        });
    }

    private ClaimsPrincipal CreateClaimsPrincipalAuthenticateFlow(OpenIddictRequest request, ClaimsPrincipal? principal)
    {
        return _claimsPrincipalFactory.Create(
            subject: request.ClientId!,
            email: principal?.FindFirst(Claims.Name)?.Value
        );
    }

    private async Task<ClaimsPrincipal> CreateClaimsPrincipalPasswordFlow(OpenIddictRequest request)
    {
        var loginResponse = await _userProtoServiceClient.LoginAsync(new LoginRequest
        {
            Username = request.Username,
            Password = request.Password
        });

        return _claimsPrincipalFactory.Create(
            subject: request.ClientId!,
            email: request.Username,
            role: loginResponse.UserRole,
            permission: loginResponse.UserPermission
        );
    }
}