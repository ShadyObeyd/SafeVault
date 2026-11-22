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
        Response.Headers["Cache-Control"] = "no-store";

        if (ModelState.IsValid && ValidationHelper.IsValidUsername(user.Username))
        {
            return View("LoggedIn", user);
        }

        return View(user);
    }
}