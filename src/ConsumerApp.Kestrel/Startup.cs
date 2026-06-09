using System.Net;
using System.Security.Cryptography.X509Certificates;
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
using Microsoft.IdentityModel.Logging;

namespace ConsumerApp.Kestrel
{
    public class Startup
    {
        public Startup(IConfiguration configuration, IWebHostEnvironment environment)
        {
            Configuration = configuration;
            Environment = environment;
        }

        private IConfiguration Configuration { get; }
        private IWebHostEnvironment Environment { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(
                    Configuration.GetConnectionString("DefaultConnection")));
            services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
                .AddEntityFrameworkStores<ApplicationDbContext>();

            services.AddSession();

            var options = new OneIdAuthenticationOptions
            {
                ClientId = Configuration.GetValue("EHS:AuthClientId", string.Empty),
                CertificateThumbprint = Configuration.GetValue("EHS:CertificateThumbprint", string.Empty),
                CertificatePassword =
                    new NetworkCredential("", Configuration.GetValue("EHS:CertificatePassword", string.Empty))
                        .SecurePassword,
                ClientSecret = Configuration.GetValue("EHS:ClientSecret", string.Empty),
                Environment = OneIdAuthenticationEnvironment.PartnerSelfTest,
                CallbackPath = new PathString("/oneid-signin"),
                CertificateStoreName = StoreName.My,
                CertificateStoreLocation = StoreLocation.CurrentUser,
                TokenSaveOptions = OneIdAuthenticationTokenSave.AccessToken |
                                   OneIdAuthenticationTokenSave.RefreshToken | OneIdAuthenticationTokenSave.IdToken,
                ServiceProfileOptions =
                    OneIdAuthenticationServiceProfiles.OLIS | OneIdAuthenticationServiceProfiles.DHDR,
                SaveTokens = false
            };
            services.AddHttpClient(OneIdAuthenticationDefaults.DisplayName,
                    client =>
                    {
                        client.DefaultRequestHeaders.Add("User-Agent", OneIdAuthenticationDefaults.UserAgent);
                    })
                .ConfigurePrimaryHttpMessageHandler(_ => new OneIdAuthenticationBackChannelHandler(options));

            services.Configure<CookiePolicyOptions>(policyOptions =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                policyOptions.CheckConsentNeeded = _ => true;
                policyOptions.MinimumSameSitePolicy = SameSiteMode.Lax;
            });

            if (Environment.IsDevelopment())
            {
                services.AddDatabaseDeveloperPageExceptionFilter();
                IdentityModelEventSource.ShowPII = true;
            }

            // Add authentication services
            services.AddAuthentication().AddOneId(OneIdAuthenticationDefaults.AuthenticationScheme,
                authenticationOptions =>
                {
                    authenticationOptions.ClientId = Configuration.GetValue("EHS:AuthClientId", string.Empty);
                    authenticationOptions.CertificateThumbprint =
                        Configuration.GetValue("EHS:CertificateThumbprint", string.Empty);
                    authenticationOptions.CertificatePassword =
                        new NetworkCredential("", Configuration.GetValue("EHS:CertificatePassword", string.Empty))
                            .SecurePassword;
                    authenticationOptions.ClientSecret = Configuration.GetValue("EHS:ClientSecret", string.Empty);
                    authenticationOptions.Environment = OneIdAuthenticationEnvironment.PartnerSelfTest;
                    authenticationOptions.CorrelationCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                    authenticationOptions.CorrelationCookie.SameSite = SameSiteMode.Lax;
                    authenticationOptions.CallbackPath = new PathString("/oneid-signin");
                    authenticationOptions.CertificateStoreName = StoreName.My;
                    authenticationOptions.SaveTokens = true;
                    authenticationOptions.CertificateStoreLocation = StoreLocation.CurrentUser;
                    authenticationOptions.TokenSaveOptions = OneIdAuthenticationTokenSave.AccessToken |
                                                             OneIdAuthenticationTokenSave.RefreshToken |
                                                             OneIdAuthenticationTokenSave.IdToken;
                    authenticationOptions.ServiceProfileOptions = OneIdAuthenticationServiceProfiles.OLIS |
                                                                  OneIdAuthenticationServiceProfiles.DHDR;
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

            app.UseEndpoints(endpoints => { endpoints.MapRazorPages(); });
        }
    }
}