using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Security;

[Authorize(Roles = UserRoles.Admin)]
public class AdminController : Controller
{
    [HttpGet]
    public IActionResult Dashboard()
    {
        return View();
    }
}
