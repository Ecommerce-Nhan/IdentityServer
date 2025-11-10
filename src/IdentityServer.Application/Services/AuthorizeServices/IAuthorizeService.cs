using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.Application.Services.AuthorizeServices;

public interface IAuthorizeService
{
    Task<IActionResult> AcceptAsync(HttpContext context);
    IActionResult Deny();
    Task<IActionResult> AuthorizeAsync(HttpContext context);
}