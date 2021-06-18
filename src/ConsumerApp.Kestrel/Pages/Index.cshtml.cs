using AspNet.Security.OAuth.OneID;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace ConsumerApp.Kestrel.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;

        public IndexModel(ILogger<IndexModel> logger)
        {
            _logger = logger;
        }

        public async Task OnGet()
        {
            if (User.Identity.IsAuthenticated)
            {
                var properites = await HttpContext.AuthenticateAsync(OneIdAuthenticationDefaults.AuthenticationScheme);

                if (string.IsNullOrEmpty(HttpContext.Session.GetString("original_username")))
                {
                    throw new Exception("Uh oh.");
                }

                var accessToken = await HttpContext.GetTokenAsync("access_token");
                if (string.IsNullOrEmpty(accessToken) && HttpContext.Session.Keys.Contains("access_token"))
                {
                    accessToken = HttpContext.Session.GetString("access_token");
                }

                var refreshToken = await HttpContext.GetTokenAsync("refresh_token");
                if (string.IsNullOrEmpty(refreshToken) && HttpContext.Session.Keys.Contains("refresh_token"))
                {
                    refreshToken = HttpContext.Session.GetString("refresh_token");
                }

                string t = "";
            }
        }
    }
}