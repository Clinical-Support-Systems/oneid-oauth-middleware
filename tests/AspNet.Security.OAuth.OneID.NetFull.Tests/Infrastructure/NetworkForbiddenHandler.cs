using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace AspNet.Security.OAuth.OneID.NetFull.Tests.Infrastructure
{
    /// <summary>
    /// A fake backchannel <see cref="HttpMessageHandler"/> that never touches the network.
    /// The challenge tests in this project only exercise
    /// <c>OneIdAuthenticationHandler.ApplyResponseChallengeAsync</c>, which never sends an outbound
    /// HTTP request, so this handler should never be invoked. If it ever is, it throws instead of
    /// silently making a real request, keeping the tests hermetic.
    /// </summary>
    internal sealed class NetworkForbiddenHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException(
                $"Unexpected backchannel HTTP request to '{request?.RequestUri}'. Challenge tests must not perform network calls.");
        }
    }
}
