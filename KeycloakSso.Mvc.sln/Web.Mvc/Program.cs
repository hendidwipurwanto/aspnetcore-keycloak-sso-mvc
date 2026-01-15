using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using Web.Core.Services.Abstractions;
using Web.Mvc.Auth;

var builder = WebApplication.CreateBuilder(args);

// =============================
// MVC
// =============================
builder.Services.AddControllersWithViews();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ICurrentUser, CurrentUser>();

// =============================
// Authentication
// =============================
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.Cookie.Name = "keycloak-auth";
    options.ExpireTimeSpan = TimeSpan.FromHours(8);
    options.SlidingExpiration = true;
})
.AddOpenIdConnect(options =>
{
    options.Authority = builder.Configuration["Keycloak:Authority"];
    options.ClientId = builder.Configuration["Keycloak:ClientId"];
    options.ClientSecret = builder.Configuration["Keycloak:ClientSecret"];

    options.ResponseType = OpenIdConnectResponseType.Code;
    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = true;

    options.RequireHttpsMetadata = false; // true in production

    options.TokenValidationParameters = new TokenValidationParameters
    {
        NameClaimType = ClaimTypes.Name,
        RoleClaimType = ClaimTypes.Role
    };

    options.Events = new OpenIdConnectEvents
    {
        OnTokenValidated = context =>
        {
            var identity = context.Principal!.Identity as ClaimsIdentity;
            // Map preferred_username to Name
            var preferredUsername = context.Principal.FindFirst("preferred_username")?.Value;
            if (!string.IsNullOrEmpty(preferredUsername))
            {
                identity!.AddClaim(new Claim(ClaimTypes.Name, preferredUsername));
            }

            // === Keycloak realm roles ===
            var realmAccess = context.Principal.FindFirst("realm_access");
            if (realmAccess != null)
            {
                var roles = System.Text.Json.JsonDocument
                    .Parse(realmAccess.Value)
                    .RootElement
                    .GetProperty("roles")
                    .EnumerateArray()
                    .Select(r => r.GetString());

                foreach (var role in roles!)
                {
                    identity!.AddClaim(new Claim(ClaimTypes.Role, role!));
                }
            }

            return Task.CompletedTask;
        },
        OnRedirectToIdentityProviderForSignOut = context =>
        {
            var idToken = context.HttpContext
            .GetTokenAsync("id_token")
            .GetAwaiter()
            .GetResult();

            var logoutUri =
            $"{options.Authority}/protocol/openid-connect/logout";

            if (!string.IsNullOrEmpty(idToken))
            {
            logoutUri += $"?id_token_hint={idToken}";
            }

            var postLogoutRedirectUri = context.Properties.RedirectUri;
            if (!string.IsNullOrEmpty(postLogoutRedirectUri))
            {
            logoutUri +=
            $"&post_logout_redirect_uri={Uri.EscapeDataString(postLogoutRedirectUri)}";
            }

            context.Response.Redirect(logoutUri);
            context.HandleResponse();

            return Task.CompletedTask;
        }
    };
});

// =============================
// Authorization
// =============================
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy =>
        policy.RequireRole("admin"));
});

var app = builder.Build();

// =============================
// Middleware
// =============================
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

// =============================
// Routes
// =============================
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Account}/{action=index}/{id?}");

app.Run();