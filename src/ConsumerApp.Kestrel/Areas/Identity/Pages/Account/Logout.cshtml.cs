using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using AspNet.Security.OAuth.OneID;
using ConsumerApp.Kestrel.Pages;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace ConsumerApp.Kestrel.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ILogger<LogoutModel> _logger;

        public LogoutModel(SignInManager<IdentityUser> signInManager, ILogger<LogoutModel> logger)
        {
            _signInManager = signInManager;
            _logger = logger;
        }

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPost(string? returnUrl = null, bool useRedirect = false)
        {
            await _signInManager.SignOutAsync();

            _logger.LogInformation("User logged out.");
            if (useRedirect && !string.IsNullOrEmpty(IndexModel.IdToken))
            {
                if (returnUrl != null)
                {
                    var url = OneIdHelper.GetEndSessionUrl(IndexModel.IdToken, postLogoutUri: new Uri(returnUrl));
                    return Redirect(url);
                }
                else
                {
                    var url = OneIdHelper.GetEndSessionUrl(IndexModel.IdToken);
                    return Redirect(url);
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
