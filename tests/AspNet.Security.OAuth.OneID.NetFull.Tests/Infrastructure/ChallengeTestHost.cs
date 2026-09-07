using System;
using System.Net.Http;
using System.Threading.Tasks;
using AspNet.Security.OAuth.OneID;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Testing;
using Owin;

namespace AspNet.Security.OAuth.OneID.NetFull.Tests.Infrastructure
{
    /// <summary>
    /// Wires up a minimal Katana (OWIN) application, registered the same way
    /// <c>ConsumerApp.Katana</c> registers OneID (<c>app.UseOneIdAuthentication(options)</c>), plus a
    /// single endpoint that issues an authentication challenge for the OneID scheme. Everything here
    /// runs in-memory via <see cref="TestServer"/>; no socket, certificate store, or DNS lookup is used.
    /// </summary>
    internal sealed class ChallengeTestHost : IDisposable
    {
        /// <summary>
        /// The path that triggers a 401 challenge for the OneID authentication type.
        /// </summary>
        public const string LoginPath = "/login";

        /// <summary>
        /// A deliberately non-loopback request host. The Framework handler's callback path derives a
        /// "host without prefix" via a regex (see OneIdAuthenticationHandler.NetFull.cs around line 145)
        /// whose behavior on loopback hosts is a separate, unresolved question tracked by task 006. Using
        /// "app.example.test" here keeps that question out of these tests.
        /// </summary>
        public const string RequestHost = "app.example.test";

        private const string ExternalSignInAuthenticationType = "Test.ExternalCookie";

        private readonly TestServer _server;
        private bool _isDisposed;

        public ChallengeTestHost(string clientId = "synthetic-client-id")
        {
            Protector = new PassthroughDataProtector();
            StateDataFormat = new PropertiesDataFormat(Protector);

            Options = new OneIdAuthenticationOptions
            {
                ClientId = clientId,
                Environment = OneIdAuthenticationEnvironment.Development,
                StateDataFormat = StateDataFormat,
                BackchannelHttpHandler = new NetworkForbiddenHandler(),
                ServiceProfileOptions = OneIdAuthenticationServiceProfiles.OLIS,
            };

            _server = TestServer.Create(app =>
            {
                // OneIdAuthenticationMiddleware falls back to the app's default "sign in as"
                // authentication type when Options.SignInAsAuthenticationType is not set (see
                // OneIdAuthenticationMiddleware.cs). Katana requires that default to be registered by
                // some external sign-in cookie middleware; without it, construction throws. A real
                // Katana host sets this via app.UseExternalSignInCookie(...) (see
                // ConsumerApp.Katana/App_Start/Startup.Auth.cs) - mirror the minimum of that here.
                app.SetDefaultSignInAsAuthenticationType(ExternalSignInAuthenticationType);

                app.UseOneIdAuthentication(Options);

                app.Use(async (context, next) =>
                {
                    if (context.Request.Path == new PathString(LoginPath))
                    {
                        var properties = new AuthenticationProperties();

                        var returnUrl = context.Request.Query["returnUrl"];
                        if (!string.IsNullOrEmpty(returnUrl))
                        {
                            properties.RedirectUri = returnUrl;
                        }

                        context.Authentication.Challenge(properties, OneIdAuthenticationDefaults.AuthenticationScheme);
                        context.Response.StatusCode = 401;
                        return;
                    }

                    await next().ConfigureAwait(false);
                });
            });
        }

        /// <summary>
        /// The <see cref="IDataProtector"/> supplied to <see cref="Options"/>. It round-trips a byte
        /// snapshot of whatever <see cref="StateDataFormat"/> serializes - never a live reference to the
        /// original <see cref="AuthenticationProperties"/> instance the handler built.
        /// </summary>
        public PassthroughDataProtector Protector { get; }

        /// <summary>
        /// The exact <see cref="ISecureDataFormat{AuthenticationProperties}"/> instance the handler uses
        /// to Protect/Unprotect the "state" query parameter. Tests reuse this same instance to unprotect
        /// the state captured from a real redirect, mirroring what the callback handler itself does.
        /// </summary>
        public PropertiesDataFormat StateDataFormat { get; }

        public OneIdAuthenticationOptions Options { get; }

        /// <summary>
        /// Issues a GET to <see cref="LoginPath"/> on <see cref="RequestHost"/>, which triggers a 401
        /// challenge for the OneID authentication type and, in turn,
        /// <c>OneIdAuthenticationHandler.ApplyResponseChallengeAsync</c>.
        /// </summary>
        public async Task<HttpResponseMessage> ChallengeAsync(string? returnUrl = null)
        {
            var path = returnUrl is null
                ? LoginPath
                : LoginPath + "?returnUrl=" + Uri.EscapeDataString(returnUrl);

            using var request = new HttpRequestMessage(HttpMethod.Get, "http://" + RequestHost + path);
            return await _server.HttpClient.SendAsync(request).ConfigureAwait(false);
        }

        /// <summary>
        /// Unprotects a "state" value using the exact same <see cref="StateDataFormat"/> the handler used
        /// to protect it.
        /// </summary>
        public AuthenticationProperties? Unprotect(string state) => StateDataFormat.Unprotect(state);

        public void Dispose()
        {
            if (_isDisposed)
            {
                return;
            }

            _server.Dispose();
            _isDisposed = true;
        }
    }
}
