using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;
using AspNet.Security.OAuth.OneID;
using AspNet.Security.OAuth.Providers.Tests.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace AspNet.Security.OAuth.Providers.Tests
{
    /// <summary>
    /// Regression tests for the default Core token validator (<see cref="DefaultOneIdTokenValidator"/>,
    /// reached via <see cref="OneIdAuthenticationOptions.TokenValidator"/>) and for the default
    /// <see cref="OneIdAuthenticationEvents.ValidateIdToken"/> dispatch behavior. Every case here uses a
    /// synthetic RSA key pair and a static, in-memory OpenID Connect configuration/JWKS - no live
    /// network, certificate store, or Ontario Health credentials are used.
    /// </summary>
    public class OneIdTokenValidatorTests
    {
#if NET8_0_OR_GREATER
        private static (IOneIdTokenValidator Validator, OneIdAuthenticationOptions Options) CreateValidator(
            OpenIdConnectConfiguration configuration,
            IHttpClientFactory? httpClientFactory = null)
        {
            var services = new ServiceCollection();
            services.AddLogging();

            var builder = services.AddAuthentication();
            builder.AddOneId(o =>
            {
                o.ClientId = SyntheticOneIdTokens.Audience;
                o.ClientSecret = "synthetic-secret";
                o.ServiceProfileOptions = OneIdAuthenticationServiceProfiles.OLIS;
                o.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(configuration);
            });

            if (httpClientFactory is not null)
            {
                services.RemoveAll<IHttpClientFactory>();
                services.AddSingleton(httpClientFactory);
            }

            var provider = services.BuildServiceProvider();
            var monitor = provider.GetRequiredService<IOptionsMonitor<OneIdAuthenticationOptions>>();

            // Resolving the options runs Configure + PostConfigure, which is what installs the
            // default TokenValidator - no reflection or InternalsVisibleTo needed.
            var options = monitor.Get(OneIdAuthenticationDefaults.AuthenticationScheme);

            return (options.TokenValidator!, options);
        }

        private static OneIdValidateIdTokenContext CreateContext(OneIdAuthenticationOptions options, string idToken, string? expectedNonce)
        {
            var httpContext = new DefaultHttpContext();
            var scheme = new AuthenticationScheme(OneIdAuthenticationDefaults.AuthenticationScheme, OneIdAuthenticationDefaults.DisplayName, typeof(OneIdAuthenticationHandler));
            return new OneIdValidateIdTokenContext(httpContext, scheme, options, idToken, expectedNonce);
        }

        [Fact]
        public async Task ValidateAsync_ValidSignedToken_Succeeds()
        {
            var signingKey = SyntheticOneIdTokens.CreateSigningKey();
            var jwks = SyntheticOneIdTokens.CreateJsonWebKeySet(signingKey);
            var configuration = SyntheticOneIdTokens.CreateConfiguration(SyntheticOneIdTokens.Issuer, jwks);
            var (validator, options) = CreateValidator(configuration);

            var now = DateTime.UtcNow;
            const string nonce = "expected-nonce";
            var token = SyntheticOneIdTokens.CreateSignedToken(
                signingKey, SyntheticOneIdTokens.Issuer, options.ClientId, SyntheticOneIdTokens.Subject,
                nonce, now.AddMinutes(-5), now.AddMinutes(30));

            var context = CreateContext(options, token, nonce);

            await validator.ValidateAsync(context);
        }

        [Fact]
        public async Task ValidateAsync_WrongAudience_Throws()
        {
            var signingKey = SyntheticOneIdTokens.CreateSigningKey();
            var jwks = SyntheticOneIdTokens.CreateJsonWebKeySet(signingKey);
            var configuration = SyntheticOneIdTokens.CreateConfiguration(SyntheticOneIdTokens.Issuer, jwks);
            var (validator, options) = CreateValidator(configuration);

            var now = DateTime.UtcNow;
            var token = SyntheticOneIdTokens.CreateSignedToken(
                signingKey, SyntheticOneIdTokens.Issuer, "unexpected-audience", SyntheticOneIdTokens.Subject,
                "nonce", now.AddMinutes(-5), now.AddMinutes(30));

            var context = CreateContext(options, token, "nonce");

            await Assert.ThrowsAsync<SecurityTokenValidationException>(() => validator.ValidateAsync(context));
        }

        [Fact]
        public async Task ValidateAsync_WrongIssuer_Throws()
        {
            var signingKey = SyntheticOneIdTokens.CreateSigningKey();
            var jwks = SyntheticOneIdTokens.CreateJsonWebKeySet(signingKey);
            var configuration = SyntheticOneIdTokens.CreateConfiguration(SyntheticOneIdTokens.Issuer, jwks);
            var (validator, options) = CreateValidator(configuration);

            var now = DateTime.UtcNow;
            var token = SyntheticOneIdTokens.CreateSignedToken(
                signingKey, "https://not-the-trusted-issuer.example", options.ClientId, SyntheticOneIdTokens.Subject,
                "nonce", now.AddMinutes(-5), now.AddMinutes(30));

            var context = CreateContext(options, token, "nonce");

            await Assert.ThrowsAsync<SecurityTokenValidationException>(() => validator.ValidateAsync(context));
        }

        [Fact]
        public async Task ValidateAsync_ExpiredToken_Throws()
        {
            var signingKey = SyntheticOneIdTokens.CreateSigningKey();
            var jwks = SyntheticOneIdTokens.CreateJsonWebKeySet(signingKey);
            var configuration = SyntheticOneIdTokens.CreateConfiguration(SyntheticOneIdTokens.Issuer, jwks);
            var (validator, options) = CreateValidator(configuration);

            var now = DateTime.UtcNow;
            var token = SyntheticOneIdTokens.CreateSignedToken(
                signingKey, SyntheticOneIdTokens.Issuer, options.ClientId, SyntheticOneIdTokens.Subject,
                "nonce", now.AddHours(-2), now.AddHours(-1));

            var context = CreateContext(options, token, "nonce");

            await Assert.ThrowsAsync<SecurityTokenValidationException>(() => validator.ValidateAsync(context));
        }

        [Fact]
        public async Task ValidateAsync_NotYetValidToken_Throws()
        {
            var signingKey = SyntheticOneIdTokens.CreateSigningKey();
            var jwks = SyntheticOneIdTokens.CreateJsonWebKeySet(signingKey);
            var configuration = SyntheticOneIdTokens.CreateConfiguration(SyntheticOneIdTokens.Issuer, jwks);
            var (validator, options) = CreateValidator(configuration);

            var now = DateTime.UtcNow;
            var token = SyntheticOneIdTokens.CreateSignedToken(
                signingKey, SyntheticOneIdTokens.Issuer, options.ClientId, SyntheticOneIdTokens.Subject,
                "nonce", now.AddHours(1), now.AddHours(2));

            var context = CreateContext(options, token, "nonce");

            await Assert.ThrowsAsync<SecurityTokenValidationException>(() => validator.ValidateAsync(context));
        }

        [Fact]
        public async Task ValidateAsync_AbsentExpectedNonce_Throws()
        {
            var signingKey = SyntheticOneIdTokens.CreateSigningKey();
            var jwks = SyntheticOneIdTokens.CreateJsonWebKeySet(signingKey);
            var configuration = SyntheticOneIdTokens.CreateConfiguration(SyntheticOneIdTokens.Issuer, jwks);
            var (validator, options) = CreateValidator(configuration);

            var now = DateTime.UtcNow;
            var token = SyntheticOneIdTokens.CreateSignedToken(
                signingKey, SyntheticOneIdTokens.Issuer, options.ClientId, SyntheticOneIdTokens.Subject,
                "token-nonce", now.AddMinutes(-5), now.AddMinutes(30));

            // No nonce was recorded on the authentication request (e.g. lost/never-set state).
            var context = CreateContext(options, token, expectedNonce: null);

            var ex = await Assert.ThrowsAsync<SecurityTokenValidationException>(() => validator.ValidateAsync(context));
            Assert.Contains("Expected nonce", ex.Message, StringComparison.Ordinal);
        }

        [Fact]
        public async Task ValidateAsync_MissingTokenNonce_Throws()
        {
            var signingKey = SyntheticOneIdTokens.CreateSigningKey();
            var jwks = SyntheticOneIdTokens.CreateJsonWebKeySet(signingKey);
            var configuration = SyntheticOneIdTokens.CreateConfiguration(SyntheticOneIdTokens.Issuer, jwks);
            var (validator, options) = CreateValidator(configuration);

            var now = DateTime.UtcNow;
            // Token carries no nonce claim at all.
            var token = SyntheticOneIdTokens.CreateSignedToken(
                signingKey, SyntheticOneIdTokens.Issuer, options.ClientId, SyntheticOneIdTokens.Subject,
                nonce: null, now.AddMinutes(-5), now.AddMinutes(30));

            var context = CreateContext(options, token, expectedNonce: "expected-nonce");

            var ex = await Assert.ThrowsAsync<SecurityTokenValidationException>(() => validator.ValidateAsync(context));
            Assert.Contains("nonce", ex.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task ValidateAsync_MismatchedNonce_Throws()
        {
            var signingKey = SyntheticOneIdTokens.CreateSigningKey();
            var jwks = SyntheticOneIdTokens.CreateJsonWebKeySet(signingKey);
            var configuration = SyntheticOneIdTokens.CreateConfiguration(SyntheticOneIdTokens.Issuer, jwks);
            var (validator, options) = CreateValidator(configuration);

            var now = DateTime.UtcNow;
            var token = SyntheticOneIdTokens.CreateSignedToken(
                signingKey, SyntheticOneIdTokens.Issuer, options.ClientId, SyntheticOneIdTokens.Subject,
                "token-nonce", now.AddMinutes(-5), now.AddMinutes(30));

            var context = CreateContext(options, token, expectedNonce: "different-nonce");

            await Assert.ThrowsAsync<SecurityTokenValidationException>(() => validator.ValidateAsync(context));
        }

        [Fact]
        public async Task ValidateAsync_UnsignedToken_Throws()
        {
            var signingKey = SyntheticOneIdTokens.CreateSigningKey();
            var jwks = SyntheticOneIdTokens.CreateJsonWebKeySet(signingKey);
            var configuration = SyntheticOneIdTokens.CreateConfiguration(SyntheticOneIdTokens.Issuer, jwks);
            var (validator, options) = CreateValidator(configuration);

            var now = DateTime.UtcNow;
            var token = SyntheticOneIdTokens.CreateUnsignedToken(
                SyntheticOneIdTokens.Issuer, options.ClientId, SyntheticOneIdTokens.Subject,
                "nonce", now.AddMinutes(-5), now.AddMinutes(30));

            var context = CreateContext(options, token, "nonce");

            await Assert.ThrowsAsync<SecurityTokenValidationException>(() => validator.ValidateAsync(context));
        }

        [Fact]
        public async Task ValidateAsync_WrongRsaSigningKey_Throws()
        {
            var trustedKey = SyntheticOneIdTokens.CreateSigningKey();
            var untrustedKey = SyntheticOneIdTokens.CreateSigningKey(keyId: "untrusted-key");
            var jwks = SyntheticOneIdTokens.CreateJsonWebKeySet(trustedKey);
            var configuration = SyntheticOneIdTokens.CreateConfiguration(SyntheticOneIdTokens.Issuer, jwks);
            var (validator, options) = CreateValidator(configuration);

            var now = DateTime.UtcNow;
            var token = SyntheticOneIdTokens.CreateSignedToken(
                untrustedKey, SyntheticOneIdTokens.Issuer, options.ClientId, SyntheticOneIdTokens.Subject,
                "nonce", now.AddMinutes(-5), now.AddMinutes(30));

            var context = CreateContext(options, token, "nonce");

            await Assert.ThrowsAsync<SecurityTokenValidationException>(() => validator.ValidateAsync(context));
        }

        [Fact]
        public async Task ValidateAsync_MissingDiscoveryIssuer_Throws()
        {
            var signingKey = SyntheticOneIdTokens.CreateSigningKey();
            var jwks = SyntheticOneIdTokens.CreateJsonWebKeySet(signingKey);
            // Issuer intentionally left empty, as if the discovery document omitted it.
            var configuration = SyntheticOneIdTokens.CreateConfiguration(string.Empty, jwks);
            var (validator, options) = CreateValidator(configuration);

            var context = CreateContext(options, "irrelevant-token-value", "nonce");

            var ex = await Assert.ThrowsAsync<SecurityTokenValidationException>(() => validator.ValidateAsync(context));
            Assert.Contains("issuer is missing", ex.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task ValidateAsync_EmptyKeySet_Throws()
        {
            // A non-null but empty JsonWebKeySet must not trigger the fallback HTTP fetch path -
            // it should fail fast with a clear diagnostic instead.
            var configuration = SyntheticOneIdTokens.CreateConfiguration(SyntheticOneIdTokens.Issuer, new JsonWebKeySet());
            var (validator, options) = CreateValidator(configuration);

            var context = CreateContext(options, "irrelevant-token-value", "nonce");

            var ex = await Assert.ThrowsAsync<SecurityTokenValidationException>(() => validator.ValidateAsync(context));
            Assert.Contains("Unable to load OneID signing keys", ex.Message, StringComparison.Ordinal);
        }

        [Fact]
        public async Task ValidateAsync_FetchesJwksFromFallbackUri_WhenDiscoveryOmitsKeySet()
        {
            var signingKey = SyntheticOneIdTokens.CreateSigningKey();
            var jwks = SyntheticOneIdTokens.CreateJsonWebKeySet(signingKey);

            // JsonWebKeySet is deliberately omitted (null) so the validator falls back to fetching
            // it directly from JwksUri - this is the one test in this suite that exercises that path.
            var configuration = SyntheticOneIdTokens.CreateConfiguration(SyntheticOneIdTokens.Issuer, jsonWebKeySet: null, jwksUri: "https://synthetic.oneid.tests/jwks");

            var fakeHandler = new FakeJsonResponseHandler(SyntheticOneIdTokens.SerializeJwks(jwks));
            var httpClientFactory = new FakeHttpClientFactory(fakeHandler);

            var (validator, options) = CreateValidator(configuration, httpClientFactory);

            var now = DateTime.UtcNow;
            const string nonce = "expected-nonce";
            var token = SyntheticOneIdTokens.CreateSignedToken(
                signingKey, SyntheticOneIdTokens.Issuer, options.ClientId, SyntheticOneIdTokens.Subject,
                nonce, now.AddMinutes(-5), now.AddMinutes(30));

            var context = CreateContext(options, token, nonce);

            await validator.ValidateAsync(context);
        }

        [Fact]
        public async Task ValidateAsync_DefaultOptions_RejectsTokenSignedWithUnadvertisedSymmetricKey()
        {
            // Guards against the alg-confusion class of bug that task 008 removed: default options
            // must never seed a trusted symmetric key, so a token forged with an arbitrary symmetric
            // key is rejected even though ValidateIssuerSigningKey defaults to true.
            Assert.Null(new OneIdAuthenticationOptions().TokenValidationParameters.IssuerSigningKey);

            var signingKey = SyntheticOneIdTokens.CreateSigningKey();
            var jwks = SyntheticOneIdTokens.CreateJsonWebKeySet(signingKey); // RSA keys only.
            var configuration = SyntheticOneIdTokens.CreateConfiguration(SyntheticOneIdTokens.Issuer, jwks);
            var (validator, options) = CreateValidator(configuration);

            var symmetricKey = new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32));
            var now = DateTime.UtcNow;
            var token = SyntheticOneIdTokens.CreateSignedToken(
                symmetricKey, SecurityAlgorithms.HmacSha256, SyntheticOneIdTokens.Issuer, options.ClientId,
                SyntheticOneIdTokens.Subject, "nonce", now.AddMinutes(-5), now.AddMinutes(30));

            var context = CreateContext(options, token, "nonce");

            await Assert.ThrowsAsync<SecurityTokenValidationException>(() => validator.ValidateAsync(context));
        }

        [Fact]
        public async Task ValidateAsync_DoesNotMutateCallerSuppliedTokenValidationParameters()
        {
            var signingKey = SyntheticOneIdTokens.CreateSigningKey();
            var jwks = SyntheticOneIdTokens.CreateJsonWebKeySet(signingKey);
            var configuration = SyntheticOneIdTokens.CreateConfiguration(SyntheticOneIdTokens.Issuer, jwks);
            var (validator, options) = CreateValidator(configuration);

            var originalValidIssuer = options.TokenValidationParameters.ValidIssuer;
            Assert.False(string.IsNullOrEmpty(originalValidIssuer));
            Assert.NotEqual(SyntheticOneIdTokens.Issuer, originalValidIssuer);
            Assert.Null(options.TokenValidationParameters.IssuerSigningKeys);

            var now = DateTime.UtcNow;
            const string nonce = "expected-nonce";
            var token = SyntheticOneIdTokens.CreateSignedToken(
                signingKey, SyntheticOneIdTokens.Issuer, options.ClientId, SyntheticOneIdTokens.Subject,
                nonce, now.AddMinutes(-5), now.AddMinutes(30));

            var context = CreateContext(options, token, nonce);
            await validator.ValidateAsync(context);

            // The clone used internally is overwritten with the discovery issuer/JWKS - the
            // caller-supplied instance on the options object must be untouched by that.
            Assert.Equal(originalValidIssuer, options.TokenValidationParameters.ValidIssuer);
            Assert.Null(options.TokenValidationParameters.IssuerSigningKeys);
        }

        [Fact]
        public async Task ValidateIdToken_UsesConfiguredCustomValidator()
        {
            var events = new OneIdAuthenticationEvents();
            var customValidator = new RecordingTokenValidator();
            var options = new OneIdAuthenticationOptions { TokenValidator = customValidator };
            var context = CreateContext(options, "token", "nonce");

            await events.ValidateIdToken(context);

            Assert.True(customValidator.WasCalled);
        }

        [Fact]
        public async Task ValidateIdToken_ThrowsWhenValidatorMissing()
        {
            var events = new OneIdAuthenticationEvents();
            var options = new OneIdAuthenticationOptions(); // TokenValidator intentionally left unset.
            var context = CreateContext(options, "token", "nonce");

            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => events.ValidateIdToken(context));
            Assert.Contains(nameof(OneIdAuthenticationOptions.TokenValidator), ex.Message, StringComparison.Ordinal);
        }

        private sealed class RecordingTokenValidator : IOneIdTokenValidator
        {
            public bool WasCalled { get; private set; }

            public Task ValidateAsync(OneIdValidateIdTokenContext context)
            {
                WasCalled = true;
                return Task.CompletedTask;
            }
        }
#endif
    }
}
