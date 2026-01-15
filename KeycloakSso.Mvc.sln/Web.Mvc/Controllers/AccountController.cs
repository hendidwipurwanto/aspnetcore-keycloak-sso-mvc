using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Web.Core.Services.Abstractions;

namespace Web.Mvc.Controllers
{

    public class AccountController : Controller
    {
        private readonly ICurrentUser _currentUser;
        public AccountController( ICurrentUser currentUser)
        {
            _currentUser = currentUser;
        }
        [Authorize]
        public IActionResult Login()
        {
            return Content($"Hello {_currentUser.Username}");
        }
        [HttpGet, HttpPost]
        [Authorize]
        public IActionResult Logout()
        {
            return SignOut(
                new AuthenticationProperties
                {
                    RedirectUri = $"{Request.Scheme}://{Request.Host}/"
                },
                CookieAuthenticationDefaults.AuthenticationScheme,
                OpenIdConnectDefaults.AuthenticationScheme
            );
        }
    }
}
