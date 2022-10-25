#if NETCORE
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace AspNet.Security.OAuth.OneID
{
    public class OneIdAuthenticationPostConfigureOptions : IPostConfigureOptions<OneIdAuthenticationOptions>
    {
        private readonly ILoggerFactory _loggerFactory;
        private readonly IHttpClientFactory _httpClientFactory;

        public OneIdAuthenticationPostConfigureOptions(ILoggerFactory loggerFactory,
            IHttpClientFactory httpClientFactory)
        {
            _loggerFactory = loggerFactory;
            _httpClientFactory = httpClientFactory;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "<Pending>")]
        public void PostConfigure(string name, OneIdAuthenticationOptions options)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException($"'{nameof(name)}' cannot be null or empty.", nameof(name));
            }

            if (options is null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (string.IsNullOrEmpty(options.TokenValidationParameters.ValidAudience) && !string.IsNullOrEmpty(options.ClientId))
            {
                options.TokenValidationParameters.ValidateAudience = true;
                options.TokenValidationParameters.ValidAudience = options.ClientId;

                options.TokenValidationParameters.ValidateIssuer = true;
                options.TokenValidationParameters.ValidIssuer = options.ClaimsIssuer;

                options.TokenValidationParameters.ValidateIssuerSigningKey = true;
            }

            //            // As seen in:
            //            // github.com/dotnet/aspnetcore/blob/master/src/Security/Authentication/OpenIdConnect/src/OpenIdConnectPostConfigureOptions.cs#L71-L102
            //            // need this now to successfully instantiate ConfigurationManager below.
            //            if (options.Backchannel == null)
            //            {
            //#pragma warning disable CA2000 // Dispose objects before losing scope
            //                options.Backchannel = new HttpClient(options.BackchannelHttpHandler ?? new HttpClientHandler());
            //#pragma warning restore CA2000 // Dispose objects before losing scope
            //                options.Backchannel.DefaultRequestHeaders.UserAgent.ParseAdd(OneIdAuthenticationDefaults.UserAgent);
            //                options.Backchannel.Timeout = options.BackchannelTimeout;
            //                options.Backchannel.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
            //            }

            if (options.TokenValidator is null)
            {
                options.TokenValidator = new DefaultOneIdTokenValidator(
                    _loggerFactory.CreateLogger<DefaultOneIdTokenValidator>());
            }

            if (options.ConfigurationManager == null)
            {
                if (string.IsNullOrEmpty(options.MetadataEndpoint))
                {
                    throw new InvalidOperationException($"The MetadataEndpoint must be set on the {nameof(OneIdAuthenticationOptions)} instance.");
                }

                options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                    options.MetadataEndpoint,
                    new OpenIdConnectConfigurationRetriever(),
                    new HttpDocumentRetriever(_httpClientFactory.CreateClient())) // Specifically the default backchannel handler isn't usable for this, just use a regular httpclient back retriever
                {
                    AutomaticRefreshInterval = TimeSpan.FromDays(1),
                    RefreshInterval = TimeSpan.FromSeconds(30)
                };
            }

            if (options.SecurityTokenHandler == null)
            {
                options.SecurityTokenHandler = new JsonWebTokenHandler();
            }
        }
    }
}
#endif