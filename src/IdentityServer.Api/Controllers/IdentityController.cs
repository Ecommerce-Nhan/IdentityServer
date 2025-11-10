using IdentityServer.Application.Services.AuthorizeServices;
using IdentityServer.Application.Services.TokenServices;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using static IdentityServer.Shared.Commons.Constants;

namespace IdentityServer.Api.Controllers;

[Route("api/[controller]/[action]")]
[ApiController]
public class IdentityController : ControllerBase
{
    private readonly ITokenService _tokenSerivce;
    private readonly IAuthorizeService _authorizeService;
    public IdentityController(ITokenService tokenSerivce,
        IAuthorizeService authorizeService)
    {
        _tokenSerivce = tokenSerivce;
        _authorizeService = authorizeService;
    }

    [HttpGet]
    [HttpPost]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize()
    {
        var consentVerified = await VerifyConsent(HttpContext);
        if (consentVerified is not null)
            return consentVerified;

        var request = HttpContext.GetOpenIddictServerRequest()
                      ?? throw new InvalidOperationException(ErrorConstants.OpenIDRequest);
        var result = await HttpContext.AuthenticateAsync();

        if (result == null || !result.Succeeded)
        {
            return Challenge(properties: new AuthenticationProperties
            {
                RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                                     Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList())
            });
        }

        return await _authorizeService.AuthorizeAsync(HttpContext);
    }

    [HttpPost]
    [Consumes("application/x-www-form-urlencoded")]
    [Produces("application/json")]
    public async Task<IActionResult> Token()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
                      ?? throw new InvalidOperationException(ErrorConstants.OpenIDRequest);

        return await _tokenSerivce.HandleTokenRequestAsync(request, HttpContext);
    }

    private async Task<IActionResult?> VerifyConsent(HttpContext httpContext)
    {
        if (httpContext.Request.Method != "POST")
            return null;

        if (httpContext.Request.Form.Where(parameter => parameter.Key == "submit.Accept").Any())
            return await _authorizeService.AcceptAsync(httpContext);

        if (httpContext.Request.Form.Where(parameter => parameter.Key == "submit.Deny").Any())
            return _authorizeService.Deny();

        return null;
    }
}
