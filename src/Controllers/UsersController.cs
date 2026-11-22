using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SafeVault.Data;

public class UsersController(UserRepository userRepository) : Controller
{
    [AllowAnonymous]
    [HttpGet]
    public IActionResult Login()
    {
        return View(new LoginViewModel { Username = string.Empty, Password = string.Empty });
    }

    [AllowAnonymous]
    [HttpGet]
    public IActionResult Register()
    {
        return View(new RegisterViewModel
        {
            Username = string.Empty,
            Email = string.Empty,
            Password = string.Empty,
            ConfirmPassword = string.Empty
        });
    }

    [AllowAnonymous]
    [EnableRateLimiting("login")]
    [HttpPost]
    public async Task<IActionResult> Register(RegisterViewModel model, CancellationToken cancellationToken)
    {
        Response.Headers["Cache-Control"] = "no-store";

        if (!ModelState.IsValid)
        {
            return RegistrationFailed(model);
        }

        if (!ValidationHelper.IsValidUsername(model.Username))
        {
            ModelState.AddModelError(nameof(RegisterViewModel.Username), "Username contains unsupported characters.");
            return RegistrationFailed(model);
        }

        if (System.Text.Encoding.UTF8.GetByteCount(model.Password) > 72)
        {
            ModelState.AddModelError(nameof(RegisterViewModel.Password), "Password must not exceed 72 UTF-8 bytes.");
            return RegistrationFailed(model);
        }

        var created = await userRepository.CreateUserAsync(
            model.Username,
            model.Email,
            model.Password,
            cancellationToken);

        if (!created)
        {
            ModelState.AddModelError(nameof(RegisterViewModel.Username), "That username is already in use.");
            return RegistrationFailed(model);
        }

        TempData["RegistrationSuccess"] = "Your account was created. You can now sign in.";
        return RedirectToAction(nameof(Login));
    }

    [AllowAnonymous]
    [EnableRateLimiting("login")]
    [HttpPost]
    public async Task<IActionResult> Login(LoginViewModel model, CancellationToken cancellationToken)
    {
        Response.Headers["Cache-Control"] = "no-store";

        if (!ModelState.IsValid || !ValidationHelper.IsValidUsername(model.Username))
        {
            return LoginFailed(model);
        }

        var user = await userRepository.AuthenticateAsync(
            model.Username,
            model.Password,
            cancellationToken);

        if (user is null)
        {
            return LoginFailed(model);
        }

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Role, user.Role)
        };
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity),
            new AuthenticationProperties { IsPersistent = false });

        Response.Headers["Cache-Control"] = "no-store";
        return RedirectToAction(nameof(LoggedIn));
    }

    [Authorize]
    [HttpGet]
    public IActionResult LoggedIn()
    {
        Response.Headers["Cache-Control"] = "no-store";

        var username = User.Identity?.Name;
        var email = User.FindFirst(ClaimTypes.Email)?.Value;
        var role = User.FindFirst(ClaimTypes.Role)?.Value;
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(email) || string.IsNullOrEmpty(role))
        {
            return Forbid();
        }

        return View(new UserViewModel
        {
            Username = username,
            Email = email,
            Role = role
        });
    }

    [Authorize]
    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        Response.Headers["Cache-Control"] = "no-store";
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction(nameof(Login));
    }

    [AllowAnonymous]
    [HttpGet]
    public IActionResult AccessDenied()
    {
        return View();
    }

    private IActionResult LoginFailed(LoginViewModel model)
    {
        ModelState.Remove(nameof(LoginViewModel.Password));
        model.Password = string.Empty;
        ModelState.AddModelError(string.Empty, "Invalid username or password.");
        return View(model);
    }

    private IActionResult RegistrationFailed(RegisterViewModel model)
    {
        model.Password = string.Empty;
        model.ConfirmPassword = string.Empty;
        return View("Register", model);
    }
}
