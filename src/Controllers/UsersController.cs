using Microsoft.AspNetCore.Mvc;

public class UsersController : Controller
{
    [HttpGet]
    public IActionResult Login()
    {
        return View();
    }

    [HttpPost]
    public IActionResult Login(UserViewModel user)
    {
        if (ModelState.IsValid && ValidationHelper.IsValidUsername(user.Username))
        {
            return RedirectToAction(nameof(LoggedIn), user);
        }

        return View(user);
    }

    [HttpGet]
    public IActionResult LoggedIn(UserViewModel user)
    {
        return View(user);
    }
}