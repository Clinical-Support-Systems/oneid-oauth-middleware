using AspNet.Security.OAuth.OneID;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace ConsumerApp.Kestrel.Pages
{
    public class IndexModel : PageModel
    {
        public static string? IdToken { get; set; }

        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }

        public IndexModel()
        {
        }

        public async Task OnGet()
        {
            if (User == null || User.Identity == null) return;

            if (User.Identity.IsAuthenticated!)
            {
                IdToken = await HttpContext.GetTokenAsync("id_token");
                if (string.IsNullOrEmpty(IdToken) && HttpContext.Session.Keys.Contains("id_token"))
                {
                    IdToken = HttpContext.Session.GetString("id_token");
                }

                AccessToken = await HttpContext.GetTokenAsync("access_token");
                if (string.IsNullOrEmpty(AccessToken) && HttpContext.Session.Keys.Contains("access_token"))
                {
                    AccessToken = HttpContext.Session.GetString("access_token");
                }

                RefreshToken = await HttpContext.GetTokenAsync("refresh_token");
                if (string.IsNullOrEmpty(RefreshToken) && HttpContext.Session.Keys.Contains("refresh_token"))
                {
                    RefreshToken = HttpContext.Session.GetString("refresh_token");
                }
            }
        }

        public Task OnPostSubmit()
        {
            return Task.CompletedTask;
        }
    }
}