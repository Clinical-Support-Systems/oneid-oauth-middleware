using AspNet.Security.OAuth.OneID;
using ConsumerApp.Kestrel.Data;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.Internal;
using Microsoft.IdentityModel.Logging;
using System.Security.Cryptography.X509Certificates;

namespace ConsumerApp.Kestrel
{
    public class Startup
    {
        public Startup(IConfiguration configuration, IWebHostEnvironment environment)
        {
            Configuration = configuration;
            Environment = environment;
        }

        public IConfiguration Configuration { get; }
        public IWebHostEnvironment Environment { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(
                    Configuration.GetConnectionString("DefaultConnection")));
            services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
                .AddEntityFrameworkStores<ApplicationDbContext>();

            services.AddSession();
            var options = new OneIdAuthenticationOptions()
            {
                ClientId = Configuration["EHS:ClientId"],
                CertificateThumbprint = Configuration["EHS:CertificateThumbprint"],
                ClientSecret = Configuration["EHS:ClientSecret"],
                Environment = OneIdAuthenticationEnvironment.PartnerSelfTest,
                CallbackPath = new("/oneid-signin"),
                CertificateStoreName = StoreName.My,
                CertificateStoreLocation = StoreLocation.CurrentUser,
                TokenSaveOptions = OneIdAuthenticationTokenSave.AccessToken | OneIdAuthenticationTokenSave.RefreshToken | OneIdAuthenticationTokenSave.IdToken,
                ServiceProfileOptions = OneIdAuthenticationServiceProfiles.OLIS | OneIdAuthenticationServiceProfiles.DHDR
            };
            services.AddHttpClient(OneIdAuthenticationDefaults.DisplayName, client =>
            {
                client.DefaultRequestHeaders.Add("User-Agent", OneIdAuthenticationDefaults.UserAgent);
            }).ConfigurePrimaryHttpMessageHandler(handler => new OneIdAuthenticationBackChannelHandler(options));

            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.Lax;
            });

            if (Environment.IsDevelopment())
            {
                services.AddDatabaseDeveloperPageExceptionFilter();
                IdentityModelEventSource.ShowPII = true;
            }

            // Add authentication services
            services.AddAuthentication().AddOneId(OneIdAuthenticationDefaults.AuthenticationScheme, (OneIdAuthenticationOptions options) =>
            {
                options.ClientId = Configuration["EHS:ClientId"];
                options.CertificateThumbprint = Configuration["EHS:CertificateThumbprint"];
                options.ClientSecret = Configuration["EHS:ClientSecret"];
                options.Environment = OneIdAuthenticationEnvironment.PartnerSelfTest;
                options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                options.CorrelationCookie.SameSite = SameSiteMode.Lax;
                options.CallbackPath = new PathString("/oneid-signin");
                options.CertificateStoreName = StoreName.My;
                options.CertificateStoreLocation = StoreLocation.CurrentUser;
                options.TokenSaveOptions = OneIdAuthenticationTokenSave.AccessToken | OneIdAuthenticationTokenSave.RefreshToken | OneIdAuthenticationTokenSave.IdToken;
                options.ServiceProfileOptions = OneIdAuthenticationServiceProfiles.OLIS | OneIdAuthenticationServiceProfiles.DHDR;
            });

            services.AddRazorPages();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseCookiePolicy(new CookiePolicyOptions
            {
                MinimumSameSitePolicy = SameSiteMode.Lax
            });
            app.UseSession();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapRazorPages();
            });
        }
    }
}