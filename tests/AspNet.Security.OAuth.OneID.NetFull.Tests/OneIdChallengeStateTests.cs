using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using AspNet.Security.OAuth.OneID.NetFull.Tests.Infrastructure;
using Shouldly;
using Xunit;

namespace AspNet.Security.OAuth.OneID.NetFull.Tests
{
    /// <summary>
    /// Executes the Framework (net48, OWIN/Katana, <c>NETFULL</c>) build of
    /// <c>OneIdAuthenticationHandler</c> and locks in the challenge-state invariant that task 003
    /// fixed: the "state" query parameter of the authorization redirect must, once unprotected,
    /// contain both the PKCE code verifier and the expected nonce, because
    /// <c>Options.StateDataFormat.Protect(properties)</c> must run after both are written into the
    /// properties dictionary.
    /// </summary>
    /// <remarks>
    /// Every test here uses a synthetic <see cref="ChallengeTestHost"/>: an in-memory
    /// <c>Microsoft.Owin.Testing.TestServer</c>, a fake backchannel handler that throws if it is ever
    /// invoked (see <see cref="NetworkForbiddenHandler"/>), and a byte-value round-tripping
    /// <c>IDataProtector</c> (see <see cref="PassthroughDataProtector"/>). No test in this class
    /// performs outbound HTTP, touches a certificate store, or exercises token exchange, JWKS
    /// discovery, or issuer validation - those remain uncovered and are tracked separately (the full
    /// callback path needs the discovery-transport and trusted-issuer decisions from task 006).
    /// </remarks>
    public class OneIdChallengeStateTests
    {
        // Mirrors the private constants in OneIdAuthenticationHandler.NetFull.cs (not part of the
        // public API, so there is no other way to name these keys from outside the assembly).
        private const string PkceCodeVerifierProperty = "oneid_pkce_code_verifier";
        private const string NonceProperty = "oneid_expected_nonce";

        [Fact]
        public async Task Challenge_Returns_Redirect_To_Authorization_Endpoint()
        {
            using var host = new ChallengeTestHost();

            using var response = await host.ChallengeAsync();

            response.StatusCode.ShouldBe(HttpStatusCode.Found);
            response.Headers.Location.ShouldNotBeNull();
            response.Headers.Location!.AbsoluteUri.ShouldStartWith(host.Options.AuthorizationEndpoint);
        }

        [Fact]
        public async Task Challenge_State_Contains_Pkce_Verifier_And_Matching_Nonce()
        {
            using var host = new ChallengeTestHost();

            using var response = await host.ChallengeAsync();
            var query = ParseQuery(response.Headers.Location!.Query);

            var properties = host.Unprotect(query["state"]);

            properties.ShouldNotBeNull();
            properties!.Dictionary.ShouldContainKey(PkceCodeVerifierProperty);
            properties.Dictionary[PkceCodeVerifierProperty].ShouldNotBeNullOrWhiteSpace();

            properties.Dictionary.ShouldContainKey(NonceProperty);
            var nonceInState = properties.Dictionary[NonceProperty];
            nonceInState.ShouldNotBeNullOrWhiteSpace();
            nonceInState.ShouldBe(query["nonce"]);
        }

        [Fact]
        public async Task Challenge_CodeChallenge_Matches_Recomputed_Pkce_Verifier()
        {
            using var host = new ChallengeTestHost();

            using var response = await host.ChallengeAsync();
            var query = ParseQuery(response.Headers.Location!.Query);

            var properties = host.Unprotect(query["state"]);
            var verifier = properties!.Dictionary[PkceCodeVerifierProperty];

            query["code_challenge_method"].ShouldBe("S256");
            query["code_challenge"].ShouldBe(ComputeCodeChallenge(verifier));
        }

        [Fact]
        public async Task Challenge_Twice_Produces_Distinct_Verifiers_And_Nonces()
        {
            using var host = new ChallengeTestHost();

            using var first = await host.ChallengeAsync();
            using var second = await host.ChallengeAsync();

            var firstQuery = ParseQuery(first.Headers.Location!.Query);
            var secondQuery = ParseQuery(second.Headers.Location!.Query);

            var firstProperties = host.Unprotect(firstQuery["state"]);
            var secondProperties = host.Unprotect(secondQuery["state"]);

            var firstVerifier = firstProperties!.Dictionary[PkceCodeVerifierProperty];
            var secondVerifier = secondProperties!.Dictionary[PkceCodeVerifierProperty];
            firstVerifier.ShouldNotBe(secondVerifier);

            var firstNonce = firstProperties.Dictionary[NonceProperty];
            var secondNonce = secondProperties.Dictionary[NonceProperty];
            firstNonce.ShouldNotBe(secondNonce);
        }

        [Fact]
        public async Task Challenge_Preserves_Correlation_Value_And_Original_RedirectUri()
        {
            using var host = new ChallengeTestHost();

            using var response = await host.ChallengeAsync(returnUrl: "/dashboard");
            var query = ParseQuery(response.Headers.Location!.Query);

            var properties = host.Unprotect(query["state"]);

            properties!.RedirectUri.ShouldBe("/dashboard");

            var correlationKey = properties.Dictionary.Keys
                .FirstOrDefault(key => key.IndexOf("Correlation", StringComparison.OrdinalIgnoreCase) >= 0);
            correlationKey.ShouldNotBeNull();
            properties.Dictionary[correlationKey!].ShouldNotBeNullOrWhiteSpace();
        }

        [Fact]
        public async Task Challenge_Verifier_Does_Not_Appear_As_Bare_Query_Parameter()
        {
            using var host = new ChallengeTestHost();

            using var response = await host.ChallengeAsync();
            var location = response.Headers.Location!.AbsoluteUri;
            var query = ParseQuery(response.Headers.Location!.Query);

            var properties = host.Unprotect(query["state"]);
            var verifier = properties!.Dictionary[PkceCodeVerifierProperty];

            query.Values.ShouldNotContain(verifier);
            location.ShouldNotContain(verifier);
        }

        private static string ComputeCodeChallenge(string verifier)
        {
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(verifier));
            return Convert.ToBase64String(hash)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }

        private static IReadOnlyDictionary<string, string> ParseQuery(string query)
        {
            if (query.Length > 0 && query[0] == '?')
            {
                query = query.Substring(1);
            }

            var result = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var pair in query.Split('&'))
            {
                if (pair.Length == 0)
                {
                    continue;
                }

                var separatorIndex = pair.IndexOf('=');
                var key = separatorIndex >= 0 ? pair.Substring(0, separatorIndex) : pair;
                var value = separatorIndex >= 0 ? pair.Substring(separatorIndex + 1) : string.Empty;
                result[Uri.UnescapeDataString(key)] = Uri.UnescapeDataString(value);
            }

            return result;
        }
    }
}
