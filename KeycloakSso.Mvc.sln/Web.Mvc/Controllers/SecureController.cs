using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Web.Mvc.Controllers
{
    [Authorize]
    public class SecureController : Controller
    {
        public IActionResult Index()
        {
            return Content($"Hello {User.FindFirst("name")?.Value}");
        }

        [Authorize(Roles = "admin")]
        public IActionResult Admin()
        {
            return Content("Admin area");
        }

    }
}
