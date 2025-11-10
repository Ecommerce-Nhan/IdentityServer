using IdentityServer.Persistence.Entities;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServer.Application.Services.AuthorizeServices;

public class AuthorizeService : IAuthorizeService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    public AuthorizeService(UserManager<ApplicationUser> userManager,
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager)
    {
        _userManager = userManager;
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _scopeManager = scopeManager;
    }
    public async Task<IActionResult> AcceptAsync(HttpContext context)
    {
        var request = context.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");
        var user = await _userManager.GetUserAsync(context.User) ??
            throw new InvalidOperationException("The user details cannot be retrieved.");
        var userId = await _userManager.GetUserIdAsync(user) ??
            throw new InvalidOperationException("The user ID cannot be retrieved.");
        object? application = await _applicationManager.FindByClientIdAsync(request.ClientId!) ??
            throw new InvalidOperationException("Details concerning the calling client application cannot be found.");
        var applicationId = await _applicationManager.GetIdAsync(application) ??
            throw new InvalidOperationException("The application ID cannot be retrieved.");

        IAsyncEnumerable<object> authorizationList = _authorizationManager.FindAsync(
           subject: userId,
           client: applicationId,
           status: Statuses.Valid,
           type: AuthorizationTypes.Permanent,
           scopes: request.GetScopes());
        List<object> authorizations = [];
        await foreach (object auth in authorizationList)
        {
            authorizations.Add(auth);
        }

        bool hasConsentType = await _applicationManager.HasConsentTypeAsync(application, ConsentTypes.External);
        if (authorizations.Count is 0 && hasConsentType)
        {
            return new ForbidResult(
                authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme],
                properties: new AuthenticationProperties(new Dictionary<string, string>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The logged in user is not allowed to access this client application."
                }!));
        }

        ClaimsIdentity identity = new(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
                .SetClaim(ClaimTypes.Email, await _userManager.GetEmailAsync(user))
                .SetClaim(Claims.Name, await _userManager.GetUserNameAsync(user))
                .SetClaim(Claims.PreferredUsername, await _userManager.GetUserNameAsync(user));
        identity.SetScopes(request.GetScopes());

        IAsyncEnumerable<string>? scopeResources = _scopeManager.ListResourcesAsync(identity.GetScopes());
        List<string> resources = [];
        await foreach (string resource in scopeResources)
        {
            resources.Add(resource);
        }
        identity.SetResources(resources);

        object? authorization = authorizations.LastOrDefault();
        authorization ??= await _authorizationManager.CreateAsync(
            identity: identity,
            subject: userId,
            client: applicationId,
            type: AuthorizationTypes.Permanent,
            scopes: identity.GetScopes());

        identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
        identity.SetDestinations(GetDestinations);

        return new Microsoft.AspNetCore.Mvc.SignInResult(authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
    }

    public IActionResult Deny()
    {
        return new ForbidResult();
    }

    public async Task<IActionResult> AuthorizeAsync(HttpContext context)
    {
        var request = context.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");
        var user = await _userManager.GetUserAsync(context.User) ??
            throw new InvalidOperationException("The user details cannot be retrieved.");
        var userId = await _userManager.GetUserIdAsync(user) ??
            throw new InvalidOperationException("The user ID cannot be retrieved.");
        object? application = await _applicationManager.FindByClientIdAsync(request.ClientId!) ??
            throw new InvalidOperationException("Details concerning the calling client application cannot be found.");
        var applicationId = await _applicationManager.GetIdAsync(application) ??
            throw new InvalidOperationException("The application ID cannot be retrieved.");

        IAsyncEnumerable<object> authorizationList = _authorizationManager.FindAsync(
           subject: userId,
           client: applicationId,
           status: Statuses.Valid,
           type: AuthorizationTypes.Permanent,
           scopes: request.GetScopes());
        List<object> authorizations = [];
        await foreach (object auth in authorizationList)
        {
            authorizations.Add(auth);
        }
        var consentType = await _applicationManager.GetConsentTypeAsync(application);
        switch (consentType)
        {
            case ConsentTypes.External when authorizations.Count is 0:
                return new ForbidResult(
                    authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme],
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The logged in user is not allowed to access this client application."
                    }!));

            case ConsentTypes.Implicit:
            case ConsentTypes.External when authorizations.Count is not 0:
            case ConsentTypes.Explicit when authorizations.Count is not 0 && !request.HasPromptValue("consent"):

                ClaimsIdentity identity = new(
                    authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                    nameType: Claims.Name,
                    roleType: Claims.Role);

                identity.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
                    .SetClaim(ClaimTypes.Email, await _userManager.GetEmailAsync(user))
                    .SetClaim(Claims.Name, await _userManager.GetUserNameAsync(user))
                    .SetClaim(Claims.PreferredUsername, await _userManager.GetUserNameAsync(user));

                identity.SetScopes(request.GetScopes());
                IAsyncEnumerable<string>? scopeResources = _scopeManager.ListResourcesAsync(identity.GetScopes());
                List<string> resources = [];
                await foreach (string resource in scopeResources)
                {
                    resources.Add(resource);
                }
                identity.SetResources(resources);

                object? authorization = authorizations.LastOrDefault();
                authorization ??= await _authorizationManager.CreateAsync(
                    identity: identity,
                    subject: userId,
                    client: applicationId,
                    type: AuthorizationTypes.Permanent,
                    scopes: identity.GetScopes());

                identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
                identity.SetDestinations(GetDestinations);

                return new Microsoft.AspNetCore.Mvc.SignInResult(authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));

            case ConsentTypes.Explicit when request.HasPromptValue("None"):
            case ConsentTypes.Systematic when request.HasPromptValue("None"):
                return new ForbidResult(
                    authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme],
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "Interactive user consent is required."
                    }!));

            default:
                string jsonData = $"{{  \"applicationName\": \"{await _applicationManager.GetLocalizedDisplayNameAsync(application)}\", \"scope\": \"{request.Scope}\"  }}";
                context.Session.SetString("ConsentData", jsonData);
                IEnumerable<KeyValuePair<string, StringValues>> parameters = context.Request.HasFormContentType ?
                    context.Request.Form : context.Request.Query;
                return new RedirectResult($"/Consent{QueryString.Create(parameters)}");
        }

    }

    static IEnumerable<string> GetDestinations(Claim claim)
    {
        switch (claim.Type)
        {
            case Claims.Name or Claims.PreferredUsername:
                yield return Destinations.AccessToken;

                if (claim.Subject is not null && claim.Subject.HasScope(Scopes.Profile))
                    yield return Destinations.IdentityToken;

                yield break;

            case ClaimTypes.Email:
                yield return Destinations.AccessToken;

                if (claim.Subject is not null && claim.Subject.HasScope(Scopes.Email))
                    yield return Destinations.IdentityToken;

                yield break;

            case "AspNet.Identity.SecurityStamp": yield break;

            default:
                yield return Destinations.AccessToken;
                yield break;
        }
    }
}