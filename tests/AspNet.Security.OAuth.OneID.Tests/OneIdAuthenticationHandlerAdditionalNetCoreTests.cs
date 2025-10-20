using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using AspNet.Security.OAuth.OneID;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace AspNet.Security.OAuth.Providers.Tests
{
    // Additional tests for OneIdAuthenticationHandler
    public class OneIdAuthenticationHandlerAdditionalNetCoreTests
    {
#if NET8_0_OR_GREATER
        private static TestOneIdAuthenticationHandler CreateHandler(OneIdAuthenticationOptions? options = null, HttpContext? httpContext = null)
        {
            options ??= new OneIdAuthenticationOptions
            {
                ClaimsIssuer = "issuer",
                TokenEndpoint = "https://example.com/token",
                AuthorizationEndpoint = "https://example.com/auth",
                CallbackPath = "/signin-oneid",
                ClientId = "client",
                ClientSecret = "secret",
                SaveTokens = true,
                TokenSaveOptions = OneIdAuthenticationTokenSave.IdToken | OneIdAuthenticationTokenSave.AccessToken | OneIdAuthenticationTokenSave.RefreshToken
            };
            options.Backchannel = new HttpClient(new FakeBackchannelHandler());

            var optionsMonitor = new StaticOptionsMonitor<OneIdAuthenticationOptions>(options);
            var loggerFactory = LoggerFactory.Create(b => b.AddFilter("*", LogLevel.Trace).AddConsole());
            var encoder = UrlEncoder.Default;

            var handler = new TestOneIdAuthenticationHandler(optionsMonitor, loggerFactory, encoder);

            httpContext ??= new DefaultHttpContext();
            httpContext.RequestServices = new ServiceCollection().AddLogging().BuildServiceProvider();

            var scheme = new AuthenticationScheme(OneIdAuthenticationDefaults.AuthenticationScheme, OneIdAuthenticationDefaults.DisplayName, typeof(TestOneIdAuthenticationHandler));
            handler.InitializeAsync(scheme, httpContext).GetAwaiter().GetResult();
            return handler;
        }

        private static string CreateJwt(Dictionary<string, object> claims)
        {
            string headerJson = "{\"alg\":\"none\"}";
            string payloadJson = JsonSerializer.Serialize(claims);
            string header = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
            string payload = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
            return $"{header}.{payload}."; // No signature part needed for parsing claims
        }

        private static string Base64UrlEncode(byte[] bytes)
        {
            var base64 = Convert.ToBase64String(bytes).TrimEnd('=');
            base64 = base64.Replace('+', '-').Replace('/', '_');
            return base64;
        }

        [Fact]
        public void BuildChallengeUrl_AddsExpectedQueryParameters()
        {
            var handler = CreateHandler();
            var props = new AuthenticationProperties();
            var url = handler.BuildChallengeUrlPublic(props, "https://app.example.com/signin");
            Assert.Contains("aud=", url);
            Assert.Contains("_profile=", url);
        }

        [Fact]
        public void BuildChallengeUrl_Throws_On_EmptyRedirect()
        {
            var handler = CreateHandler();
            var props = new AuthenticationProperties();
            var ex = Assert.Throws<ArgumentException>(() => handler.BuildChallengeUrlPublic(props, string.Empty));
            Assert.Equal("redirectUri", ex.ParamName);
        }

        [Fact]
        public void ExtractClaimsFromToken_ReturnsClaims()
        {
            var handler = CreateHandler();
            var jwt = CreateJwt(new Dictionary<string, object>
            {
                ["sub"] = "user-subject",
                ["email"] = "user@example.com",
                ["given_name"] = "John",
                ["family_name"] = "Doe",
                ["phoneNumber"] = "1234567890",
                ["username"] = "jdoe"
            });

            var claims = handler.ExtractClaimsFromTokenPublic(jwt).ToList();
            Assert.Contains(claims, c => c.Type == ClaimTypes.NameIdentifier && c.Value == "user-subject");
            Assert.Contains(claims, c => c.Type == ClaimTypes.Email && c.Value == "user@example.com");
            Assert.Contains(claims, c => c.Type == ClaimTypes.GivenName && c.Value == "John");
            Assert.Contains(claims, c => c.Type == ClaimTypes.Name && c.Value == "Doe");
            Assert.Contains(claims, c => c.Type == ClaimTypes.HomePhone && c.Value == "1234567890");
            Assert.Contains(claims, c => c.Type == ClaimTypes.Actor && c.Value == "jdoe");
        }

        [Fact]
        public void ExtractClaimsFromToken_Throws_On_Empty()
        {
            var handler = CreateHandler();
            var ex = Assert.Throws<ArgumentException>(() => handler.ExtractClaimsFromTokenPublic(string.Empty));
            Assert.Equal("idToken", ex.ParamName);
        }

        [Fact]
        public async Task CreateTicketAsync_FallbackActorFromAccessToken()
        {
            var handler = CreateHandler();

            // id token without actor claim
            var idJwt = CreateJwt(new Dictionary<string, object>
            {
                ["sub"] = "user-subject"
            });
            var accessJwt = CreateJwt(new Dictionary<string, object>
            {
                ["username"] = "accessUser"
            });

            var json = $"{{\"id_token\":\"{idJwt}\",\"access_token\":\"{accessJwt}\",\"refresh_token\":\"r123\",\"token_type\":\"Bearer\",\"expires_in\":3600}}";
            using var doc = JsonDocument.Parse(json);
            var tokens = OAuthTokenResponse.Success(doc);

            var identity = new ClaimsIdentity();
            var props = new AuthenticationProperties();

            var ticket = await handler.CreateTicketAsyncPublic(identity, props, tokens);
            Assert.NotNull(ticket);
            Assert.Contains(identity.Claims, c => c.Type == ClaimTypes.Actor && c.Value == "accessUser");
        }

        [Fact]
        public async Task CreateTicketAsync_DoesNotDuplicateActorClaim()
        {
            var handler = CreateHandler();

            var idJwt = CreateJwt(new Dictionary<string, object>
            {
                ["sub"] = "user-subject",
                ["username"] = "idUser"
            });
            var accessJwt = CreateJwt(new Dictionary<string, object>
            {
                ["username"] = "accessUser"
            });
            var json = $"{{\"id_token\":\"{idJwt}\",\"access_token\":\"{accessJwt}\",\"refresh_token\":\"r123\",\"token_type\":\"Bearer\",\"expires_in\":3600}}";
            using var doc = JsonDocument.Parse(json);
            var tokens = OAuthTokenResponse.Success(doc);

            var identity = new ClaimsIdentity();
            var props = new AuthenticationProperties();
            await handler.CreateTicketAsyncPublic(identity, props, tokens);

            var actorClaims = identity.Claims.Where(c => c.Type == ClaimTypes.Actor).ToList();
            Assert.Single(actorClaims);
            Assert.Equal("idUser", actorClaims[0].Value);
        }

        [Fact]
        public async Task CreateTicketAsync_SavesRequestedTokens()
        {
            var options = new OneIdAuthenticationOptions
            {
                ClaimsIssuer = "issuer",
                TokenEndpoint = "https://example.com/token",
                AuthorizationEndpoint = "https://example.com/auth",
                CallbackPath = "/signin-oneid",
                ClientId = "client",
                ClientSecret = "secret",
                SaveTokens = true,
                TokenSaveOptions = OneIdAuthenticationTokenSave.IdToken | OneIdAuthenticationTokenSave.AccessToken
            };
            var handler = CreateHandler(options);

            var idJwt = CreateJwt(new Dictionary<string, object> { ["sub"] = "user-subject" });
            var accessJwt = CreateJwt(new Dictionary<string, object> { ["username"] = "idUser" });
            var json = $"{{\"id_token\":\"{idJwt}\",\"access_token\":\"{accessJwt}\",\"refresh_token\":\"r123\",\"token_type\":\"Bearer\",\"expires_in\":3600}}";
            using var doc = JsonDocument.Parse(json);
            var tokens = OAuthTokenResponse.Success(doc);

            var identity = new ClaimsIdentity();
            var props = new AuthenticationProperties();
            await handler.CreateTicketAsyncPublic(identity, props, tokens);

            var stored = props.GetTokens().ToList();
            Assert.Contains(stored, t => t.Name == "id_token" && t.Value == idJwt);
            Assert.Contains(stored, t => t.Name == "access_token" && t.Value == accessJwt);
            Assert.DoesNotContain(stored, t => t.Name == "refresh_token");
        }
#endif
    }

#if NET8_0_OR_GREATER
    internal sealed class TestOneIdAuthenticationHandler : OneIdAuthenticationHandler
    {
        public TestOneIdAuthenticationHandler(IOptionsMonitor<OneIdAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder)
            : base(options, logger, encoder) { }

        public string BuildChallengeUrlPublic(AuthenticationProperties properties, string redirectUri) => base.BuildChallengeUrl(properties, redirectUri);
        public Task<AuthenticationTicket> CreateTicketAsyncPublic(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens) => base.CreateTicketAsync(identity, properties, tokens);
        public IEnumerable<Claim> ExtractClaimsFromTokenPublic(string token) => base.ExtractClaimsFromToken(token);
    }

    internal sealed class StaticOptionsMonitor<TOptions> : IOptionsMonitor<TOptions> where TOptions : class
    {
        private readonly TOptions _options;
        public StaticOptionsMonitor(TOptions options) => _options = options;
        public TOptions CurrentValue => _options;
        public TOptions Get(string? name) => _options;
        public IDisposable OnChange(Action<TOptions, string?> listener) => new NoopDisposable();
        private sealed class NoopDisposable : IDisposable { public void Dispose() { } }
    }

    internal sealed class FakeBackchannelHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, System.Threading.CancellationToken cancellationToken)
        {
            // Always return success with empty JSON
            var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent("{}", Encoding.UTF8, "application/json")
            };
            return Task.FromResult(response);
        }
    }
#endif
}
