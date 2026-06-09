using System;
using System.Web;
using System.Web.UI;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

namespace ConsumerApp.Katana.Account
{
    public partial class Confirm : Page
    {
        protected string StatusMessage { get; private set; }

        protected void Page_Load(object sender, EventArgs e)
        {
            var code = IdentityHelper.GetCodeFromRequest(Request);
            var userId = IdentityHelper.GetUserIdFromRequest(Request);
            if (code != null && userId != null)
            {
                var manager = Context.GetOwinContext().GetUserManager<ApplicationUserManager>();
                var result = manager.ConfirmEmail(userId, code);
                if (result.Succeeded)
                {
                    successPanel.Visible = true;
                    return;
                }
            }

            successPanel.Visible = false;
            errorPanel.Visible = true;
        }
    }
}