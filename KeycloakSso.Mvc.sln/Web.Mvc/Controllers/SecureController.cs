using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Web.Core.Services.Abstractions;

namespace Web.Mvc.Controllers
{
    [Authorize]
    public class SecureController : Controller
    {
        private readonly ICurrentUser _currentUser;
        public SecureController(ICurrentUser currentUser)
        {
            _currentUser = currentUser;
        }
        public IActionResult Index()
        {
            return Content($"Hello {_currentUser.Username}");
        }

        [Authorize(Roles = "admin")]
        public IActionResult Admin()
        {
            return Content("Admin area");
        }

    }
}
