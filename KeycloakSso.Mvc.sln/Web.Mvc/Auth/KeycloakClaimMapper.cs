using System.Security.Claims;
using System.Text.Json;

namespace Web.Mvc.Auth
{
    public static class KeycloakClaimMapper
    {
        public static void Map(ClaimsPrincipal principal)
        {
            var identity = principal.Identity as ClaimsIdentity;
            if (identity == null || !identity.IsAuthenticated)
                return;

            MapUsername(identity, principal);
            MapRealmRoles(identity, principal);
        }

        private static void MapUsername(
            ClaimsIdentity identity,
            ClaimsPrincipal principal)
        {
            var preferredUsername =
                principal.FindFirst("preferred_username")?.Value;

            if (!string.IsNullOrWhiteSpace(preferredUsername))
            {
                identity.AddClaim(
                    new Claim(ClaimTypes.Name, preferredUsername)
                );
            }
        }

        private static void MapRealmRoles(
            ClaimsIdentity identity,
            ClaimsPrincipal principal)
        {
            var realmAccess = principal.FindFirst("realm_access");
            if (realmAccess == null)
                return;

            using var doc = JsonDocument.Parse(realmAccess.Value);

            if (!doc.RootElement.TryGetProperty("roles", out var roles))
                return;

            foreach (var role in roles.EnumerateArray())
            {
                var roleName = role.GetString();
                if (!string.IsNullOrWhiteSpace(roleName))
                {
                    identity.AddClaim(
                        new Claim(ClaimTypes.Role, roleName)
                    );
                }
            }
        }
    }
}
