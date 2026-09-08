#if NET8_0_OR_GREATER
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace AspNet.Security.OAuth.Providers.Tests.Infrastructure
{
    /// <summary>
    /// Builds synthetic RSA-signed OneID ID tokens, matching OpenID Connect discovery/JWKS
    /// configuration, and supporting fakes so <c>DefaultOneIdTokenValidator</c> can be exercised
    /// end-to-end without any live network, certificate store or Ontario Health credentials.
    /// </summary>
    internal static class SyntheticOneIdTokens
    {
        public const string Issuer = "https://synthetic.oneid.tests/issuer";
        public const string Audience = "synthetic-client";
        public const string Subject = "synthetic-subject";
        public const string KeyId = "synthetic-key-1";

        /// <summary>
        /// Creates a disposable RSA key pair (private + public) usable as OneID's synthetic signing key.
        /// </summary>
        public static RsaSecurityKey CreateSigningKey(string keyId = KeyId)
        {
            var rsa = RSA.Create(2048);
            return new RsaSecurityKey(rsa) { KeyId = keyId };
        }

        /// <summary>
        /// Builds a JWKS containing only the public half of <paramref name="signingKey"/>, as a real
        /// discovery endpoint would publish.
        /// </summary>
        public static JsonWebKeySet CreateJsonWebKeySet(RsaSecurityKey signingKey)
        {
            ArgumentNullException.ThrowIfNull(signingKey);

            var publicRsa = RSA.Create();
            publicRsa.ImportParameters(signingKey.Rsa!.ExportParameters(includePrivateParameters: false));
            var publicKey = new RsaSecurityKey(publicRsa) { KeyId = signingKey.KeyId };

            var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(publicKey);
            jwk.KeyId = signingKey.KeyId;

            var jwks = new JsonWebKeySet();
            jwks.Keys.Add(jwk);
            return jwks;
        }

        /// <summary>
        /// Builds a minimal trusted <see cref="OpenIdConnectConfiguration"/> as would be returned by
        /// the OneID discovery document, with a matching JWKS attached (unless deliberately omitted to
        /// exercise the fallback JWKS fetch).
        /// </summary>
        public static OpenIdConnectConfiguration CreateConfiguration(string issuer, JsonWebKeySet? jsonWebKeySet, string jwksUri = "")
        {
            var configuration = new OpenIdConnectConfiguration
            {
                Issuer = issuer,
                JwksUri = jwksUri,
            };

            if (jsonWebKeySet is not null)
            {
                configuration.JsonWebKeySet = jsonWebKeySet;
            }

            return configuration;
        }

        /// <summary>
        /// Creates a signed RS256 OneID-shaped ID token.
        /// </summary>
        public static string CreateSignedToken(
            RsaSecurityKey signingKey,
            string issuer,
            string audience,
            string subject,
            string? nonce,
            DateTime notBefore,
            DateTime expires) =>
            CreateSignedToken(signingKey, SecurityAlgorithms.RsaSha256, issuer, audience, subject, nonce, notBefore, expires);

        /// <summary>
        /// Creates a signed OneID-shaped ID token using an arbitrary key/algorithm pair. Used to prove
        /// that keys and algorithms not advertised by the trusted JWKS are rejected (e.g. a symmetric
        /// key an attacker might otherwise try to use in an algorithm-confusion attack).
        /// </summary>
        public static string CreateSignedToken(
            SecurityKey signingKey,
            string algorithm,
            string issuer,
            string audience,
            string subject,
            string? nonce,
            DateTime notBefore,
            DateTime expires)
        {
            var claims = new List<Claim> { new("sub", subject) };
            if (nonce is not null)
            {
                claims.Add(new Claim("nonce", nonce));
            }

            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = issuer,
                Audience = audience,
                Subject = new ClaimsIdentity(claims),
                NotBefore = notBefore,
                Expires = expires,
                IssuedAt = DateTime.UtcNow,
                SigningCredentials = new SigningCredentials(signingKey, algorithm),
            };

            return new JsonWebTokenHandler().CreateToken(descriptor);
        }

        /// <summary>
        /// Creates an unsigned ("alg":"none") OneID-shaped ID token.
        /// </summary>
        public static string CreateUnsignedToken(
            string issuer,
            string audience,
            string subject,
            string? nonce,
            DateTime notBefore,
            DateTime expires)
        {
            var claims = new List<Claim> { new("sub", subject) };
            if (nonce is not null)
            {
                claims.Add(new Claim("nonce", nonce));
            }

            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = issuer,
                Audience = audience,
                Subject = new ClaimsIdentity(claims),
                NotBefore = notBefore,
                Expires = expires,
                IssuedAt = DateTime.UtcNow,
            };

            return new JsonWebTokenHandler().CreateToken(descriptor);
        }

        /// <summary>
        /// Hand-serializes a JWKS document (RSA keys only) in the shape a discovery endpoint would
        /// return, for use with <see cref="FakeHttpClientFactory"/> in the deliberately-faked fallback
        /// JWKS fetch test.
        /// </summary>
        public static string SerializeJwks(JsonWebKeySet jwks)
        {
            ArgumentNullException.ThrowIfNull(jwks);

            var keys = new List<string>();
            foreach (var key in jwks.Keys)
            {
                keys.Add(string.Format(
                    CultureInfo.InvariantCulture,
                    "{{\"kty\":\"{0}\",\"kid\":\"{1}\",\"use\":\"sig\",\"n\":\"{2}\",\"e\":\"{3}\"}}",
                    key.Kty,
                    key.KeyId,
                    key.N,
                    key.E));
            }

            return "{\"keys\":[" + string.Join(",", keys) + "]}";
        }
    }

    /// <summary>
    /// An <see cref="IConfigurationManager{T}"/> that always returns a pre-built configuration, so
    /// tests never perform real discovery-document HTTP calls.
    /// </summary>
    internal sealed class StaticConfigurationManager<T> : IConfigurationManager<T>
        where T : class
    {
        private readonly T _configuration;

        public StaticConfigurationManager(T configuration) => _configuration = configuration;

        public Task<T> GetConfigurationAsync(CancellationToken cancel) => Task.FromResult(_configuration);

        public void RequestRefresh()
        {
            // No-op: the synthetic configuration never changes within a test.
        }
    }

    /// <summary>
    /// An <see cref="IHttpClientFactory"/> that always returns an <see cref="HttpClient"/> backed by a
    /// fixed <see cref="HttpMessageHandler"/>, used for the one deliberately-faked JWKS fallback fetch.
    /// </summary>
    internal sealed class FakeHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpMessageHandler _handler;

        public FakeHttpClientFactory(HttpMessageHandler handler) => _handler = handler;

        public HttpClient CreateClient(string name) => new(_handler, disposeHandler: false);
    }

    /// <summary>
    /// An <see cref="HttpMessageHandler"/> that always returns a fixed JSON body, used to simulate a
    /// JWKS endpoint response.
    /// </summary>
    internal sealed class FakeJsonResponseHandler : HttpMessageHandler
    {
        private readonly string _json;

        public FakeJsonResponseHandler(string json) => _json = json;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_json, Encoding.UTF8, "application/json"),
            };
            return Task.FromResult(response);
        }
    }
}
#endif
