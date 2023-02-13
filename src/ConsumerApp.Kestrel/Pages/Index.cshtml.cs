using AspNet.Security.OAuth.OneID;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace ConsumerApp.Kestrel.Pages
{
    public class IndexModel : PageModel
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;

        [BindProperty(SupportsGet = true)]
        public static string? IdToken { get; set; }

        [BindProperty(SupportsGet = true)]
        public string? AccessToken { get; set; }

        [BindProperty(SupportsGet = true)]
        public string? RefreshToken { get; set; }

        public IndexModel(IHttpClientFactory httpClientFactory, IConfiguration configuration)
        {
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
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

        public async Task OnPostSubmit(CancellationToken ct = default)
        {
            using var client = _httpClientFactory.CreateClient(OneIdAuthenticationDefaults.DisplayName);

            if (!string.IsNullOrEmpty(RefreshToken))
            {
                var options = new OneIdAuthenticationOptions()
                {
                    ClientId = _configuration["EHS:ClientId"],
                    CertificateThumbprint = _configuration["EHS:CertificateThumbprint"],
                    ClientSecret = _configuration["EHS:ClientSecret"],
                    Environment = OneIdAuthenticationEnvironment.PartnerSelfTest,
                    CallbackPath = new PathString("/oneid-signin"),
                    CertificateStoreName = StoreName.My,
                    CertificateStoreLocation = StoreLocation.CurrentUser,
                    TokenSaveOptions = OneIdAuthenticationTokenSave.AccessToken | OneIdAuthenticationTokenSave.RefreshToken | OneIdAuthenticationTokenSave.IdToken,
                    ServiceProfileOptions = OneIdAuthenticationServiceProfiles.OLIS | OneIdAuthenticationServiceProfiles.DHDR
                };
                var accessToken = await OneIdHelper.RefreshToken(client, options, RefreshToken, ct);
                AccessToken = accessToken;
                HttpContext.Session.SetString("refresh_token", RefreshToken);
                HttpContext.Session.SetString("access_token", AccessToken);
            }
        }
    }
}