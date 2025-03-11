using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using AspNet.Security.OAuth.OneID;
using ConsumerApp.Kestrel.Pages;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace ConsumerApp.Kestrel.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ILogger<LogoutModel> _logger;
        private readonly IConfiguration _configuration;
        private readonly HttpClient _client;

        public LogoutModel(SignInManager<IdentityUser> signInManager,
                           ILogger<LogoutModel> logger,
                           IConfiguration configuration,
                           IHttpClientFactory httpClientFactory)
        {
            _signInManager = signInManager;
            _logger = logger;
            _configuration = configuration;
            _client = httpClientFactory.CreateClient(OneIdAuthenticationDefaults.DisplayName);
        }

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPost([FromQuery] string? returnUrl = null, bool useRedirect = false)
        {
            await _signInManager.SignOutAsync();
            
            var accessToken = await HttpContext.GetTokenAsync("access_token");
            var accessToken1 = await HttpContext.GetTokenAsync(OneIdAuthenticationDefaults.AuthenticationScheme, "access_token");
            await OneIdHelper.RevokeToken(IndexModel.AccessToken, _configuration["EHS:ClientId"], _client);

            _logger.LogInformation("User logged out.");

            if (useRedirect && !string.IsNullOrEmpty(IndexModel.IdToken))
            {
                if (returnUrl != null)
                {
                    var url = QueryHelpers.AddQueryString("https://login.pst.oneidfederation.ehealthontario.ca/oidc/logout/", "returnurl", returnUrl);
                    return Redirect(url);
                    //var url = OneIdHelper.GetEndSessionUrl(IndexModel.IdToken, postLogoutUri: new Uri(returnUrl));
                    //return Redirect(url);
                }
                else
                {
                    var url = QueryHelpers.AddQueryString("https://login.pst.oneidfederation.ehealthontario.ca/oidc/logout/", "returnurl", $"{Request.Scheme}://{Request.Host}");
                    return Redirect(url);
                    //var url = OneIdHelper.GetEndSessionUrl(IndexModel.IdToken, clientId: _configuration["EHS:ClientId"]);
                    //return Redirect(url);
                }
            }
            else
            {
                if (returnUrl != null)
                {

                    return LocalRedirect(returnUrl);
                }
                else
                {
                    return RedirectToPage();
                }
            }
        }
    }
}
