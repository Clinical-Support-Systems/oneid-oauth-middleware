using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(ConsumerApp.Katana.Startup))]
namespace ConsumerApp.Katana
{
    public partial class Startup {
        public void Configuration(IAppBuilder app) {
            ConfigureAuth(app);
        }
    }
}
