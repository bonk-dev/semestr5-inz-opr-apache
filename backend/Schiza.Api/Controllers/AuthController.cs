using System.Security.Claims;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;

using Schiza.Application;

using ApplicationAuthenticationService = Schiza.Application.IAuthenticationService;

namespace Schiza.Api.Controllers;

[ApiController]
[Route("api/auth")]
public sealed class AuthController(ApplicationAuthenticationService authentication) : ControllerBase
{
    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginRequest request)
    {
        if (!authentication.Authenticate(request.Username, request.Password)) return Unauthorized();
        ClaimsIdentity identity = new([new Claim(ClaimTypes.Name, request.Username), new Claim(ClaimTypes.Role, "Admin")], CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
        return Ok(new { username = request.Username });
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout() { await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme); return NoContent(); }

    [HttpGet("me")]
    public IActionResult Me() => User.Identity?.IsAuthenticated == true ? Ok(new { username = User.Identity.Name }) : Unauthorized();

}

public sealed record LoginRequest(string Username, string Password);
