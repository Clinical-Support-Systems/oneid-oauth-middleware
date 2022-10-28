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
        private readonly ILogger<IndexModel> _logger;

        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }

        public IndexModel(ILogger<IndexModel> logger)
        {
            _logger = logger;
        }

        public async Task OnGet()
        {
            if (User.Identity.IsAuthenticated)
            {
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

        public async Task OnPostSubmit()
        {

            string t = "";
        }
    }
}