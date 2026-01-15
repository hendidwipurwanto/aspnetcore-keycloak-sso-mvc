using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Web.Core.Services.Abstractions;

namespace Web.Mvc.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private readonly ICurrentUser _currentUser;
        public AccountController( ICurrentUser currentUser)
        {
            _currentUser = currentUser;
        }
        public IActionResult Login()
        {
            return Content($"Hello {_currentUser.Username}");
        }
        [HttpPost]
        public IActionResult Logout()
        {
            return SignOut(
                new AuthenticationProperties
                {
                    RedirectUri = "/"
                },
                CookieAuthenticationDefaults.AuthenticationScheme,
                OpenIdConnectDefaults.AuthenticationScheme
            );
        }
    }
}
