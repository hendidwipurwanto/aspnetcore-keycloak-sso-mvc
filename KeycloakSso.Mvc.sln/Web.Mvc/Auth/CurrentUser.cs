using Web.Core.Services.Abstractions;

namespace Web.Mvc.Auth
{
    public class CurrentUser : ICurrentUser
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public CurrentUser(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        public string? Username
        {
            get
            {
                var context = _httpContextAccessor.HttpContext;
                if (context == null)
                    return null;

                var principal = context.User;
                if (principal == null || !principal.Identity?.IsAuthenticated == true)
                    return null;

                return principal.FindFirst("preferred_username")?.Value;
            }
        }
    }
}
