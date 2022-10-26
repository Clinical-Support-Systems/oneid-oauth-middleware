//
// OneIdAuthenticationHandler.NetCore.cs
//
// Authors: Kori Francis <twitter.com/korifrancis>
// Copyright (C) 2020 Clinical Support Systems, Inc. All rights reserved.
//
//  THIS FILE IS LICENSED UNDER THE MIT LICENSE AS OUTLINED IMMEDIATELY BELOW:
//
//  Permission is hereby granted, free of charge, to any person obtaining a
//  copy of this software and associated documentation files (the "Software"),
//  to deal in the Software without restriction, including without limitation
//  the rights to use, copy, modify, merge, publish, distribute, sublicense,
//  and/or sell copies of the Software, and to permit persons to whom the
//  Software is furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//  DEALINGS IN THE SOFTWARE.
//

#if NETCORE

using AspNet.Security.OAuth.OneID.Provider;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using static AspNet.Security.OAuth.OneID.OneIdAuthenticationConstants;

namespace AspNet.Security.OAuth.OneID
{
    /// <summary>
    /// The OneId oauth/oidc authentication handler
    /// </summary>
    public class OneIdAuthenticationHandler : OAuthHandler<OneIdAuthenticationOptions>
    {
        private readonly JwtSecurityTokenHandler _tokenHandler;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="options">The options</param>
        /// <param name="logger">The logger</param>
        /// <param name="encoder">The encoder</param>
        /// <param name="clock">The clock skew</param>
        /// <param name="tokenHandler">The security token handler</param>
        public OneIdAuthenticationHandler(IOptionsMonitor<OneIdAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock, JwtSecurityTokenHandler tokenHandler) : base(options, logger, encoder, clock)
        {
            if (options is null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (logger is null)
            {
                throw new ArgumentNullException(nameof(logger));
            }

            if (encoder is null)
            {
                throw new ArgumentNullException(nameof(encoder));
            }

            if (clock is null)
            {
                throw new ArgumentNullException(nameof(clock));
            }

            _tokenHandler = tokenHandler ?? throw new ArgumentNullException(nameof(tokenHandler));
        }

        /// <inheritdoc />
        protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
        {
            if (properties is null)
            {
                throw new ArgumentNullException(nameof(properties));
            }

            if (string.IsNullOrEmpty(redirectUri))
            {
                throw new ArgumentException($"'{nameof(redirectUri)}' cannot be null or empty.", nameof(redirectUri));
            }

            //            var uri = new Uri(redirectUri);
            //            string subdomain = null;

            //            if (uri.HostNameType == UriHostNameType.Dns)
            //            {
            //                var host = uri.Host;
            //                if (host.Count(f => f == '.') > 1)
            //                {
            //                    subdomain = host.Split('.')[0];
            //                }
            //            }

            //            string challengeUrl = null;

            //            if (!string.IsNullOrEmpty(subdomain))
            //            {
            //                properties.SetString("subdomain", subdomain);

            //                // challenge without the subdomain
            //#if NET5_0_OR_GREATER
            //                challengeUrl = base.BuildChallengeUrl(properties, redirectUri.Replace(subdomain + ".", string.Empty, StringComparison.InvariantCulture));
            //#else
            //                challengeUrl = base.BuildChallengeUrl(properties, redirectUri.Replace(subdomain + ".", string.Empty));
            //#endif
            //            }
            //            else
            //            {
            //                challengeUrl = base.BuildChallengeUrl(properties, redirectUri);
            //            }
            var challengeUrl = base.BuildChallengeUrl(properties, redirectUri);
            challengeUrl = QueryHelpers.AddQueryString(challengeUrl, "aud", ClaimNames.ApiAudience);
            challengeUrl = QueryHelpers.AddQueryString(challengeUrl, "_profile", Options.GetServiceProfileOptionsString());

            return challengeUrl;
        }

        /// <summary>
        /// The handler calls methods on the events which give the application control at certain points where processing is occurring.
        /// If it is not provided a default instance is supplied which does nothing when the methods are called.
        /// </summary>
        protected new OneIdAuthenticationEvents Events
        {
            get { return (OneIdAuthenticationEvents)base.Events; }
            set { base.Events = value; }
        }

        /// <inheritdoc />
        protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new OneIdAuthenticationEvents());

        /// <inheritdoc />
        protected override async Task<AuthenticationTicket> CreateTicketAsync(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
        {
            if (identity is null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            if (properties is null)
            {
                throw new ArgumentNullException(nameof(properties));
            }

            if (tokens is null)
            {
                throw new ArgumentNullException(nameof(tokens));
            }

            // TODO: UserInfo content is empty.
            //string address = QueryHelpers.AddQueryString(Options.UserInfo, "access_token", tokens.AccessToken!);

            //using var request = new HttpRequestMessage(HttpMethod.Get, address);
            //request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            //using var userInfoResponse = await Backchannel.SendAsync(request, HttpCompletionOption.ResponseContentRead, Context.RequestAborted);
            //if (!userInfoResponse.IsSuccessStatusCode)
            //{
            //    Logger.LogUserInfoFailure(userInfoResponse.StatusCode, userInfoResponse.Headers.ToString(), await userInfoResponse.Content.ReadAsStringAsync(Context.RequestAborted));
            //    throw new HttpRequestException("An error occurred while retrieving the user profile.");
            //}

            //var payloadString = await userInfoResponse.Content.ReadAsStringAsync(Context.RequestAborted);
            //using var payload = JsonDocument.Parse(payloadString);

            _ = ProcessIdTokenAndGetContactIdentifier(tokens, properties);

            var idToken = tokens.Response!.RootElement.GetString("id_token");

            if (string.IsNullOrWhiteSpace(idToken))
            {
                throw new InvalidOperationException("No OneID ID token was returned in the OAuth token response.");
            }

            if (Logger.IsEnabled(LogLevel.Trace))
            {
                Logger.LogIdToken(idToken);
                Logger.LogAccessToken(tokens.AccessToken);
                Logger.LogRefreshToken(tokens.RefreshToken);
                Logger.LogTokenType(tokens.TokenType);
                Logger.LogTokenExpiry(tokens.ExpiresIn);
                Logger.LogTokenResponse(tokens.Response?.RootElement);
            }

            //if (string.IsNullOrEmpty(contextId))
            //{
            //    throw new InvalidOperationException("An error occurred trying to obtain the context identifier from the current user's identity claims.");
            //}

            if (Options.ValidateTokens)
            {
                var validateIdContext = new OneIdValidateIdTokenContext(Context, Scheme, Options, idToken);
                await Events.ValidateIdToken(validateIdContext);
            }

            foreach (var claim in ExtractClaimsFromToken(idToken))
            {
                identity.AddClaim(claim);
            }

            var principal = new ClaimsPrincipal(identity);

            var context = new OAuthCreatingTicketContext(principal, properties, Context, Scheme, Options, Backchannel, tokens, tokens.Response!.RootElement);

            //List<AuthenticationToken> exactTokens = context.Properties.GetTokens().ToList();

            if (Context.Features.Get<ISessionFeature>() != null)
            {
                if (!string.IsNullOrEmpty(principal.Identity?.Name))
                    context.HttpContext.Session.SetString("original_username", principal.Identity.Name);

                // Store the received tokens somewhere, if we should
                if (!string.IsNullOrEmpty(context.AccessToken) && ((Options.TokenSaveOptions & OneIdAuthenticationTokenSave.AccessToken) == OneIdAuthenticationTokenSave.AccessToken))
                    context.HttpContext.Session.SetString("access_token", context.AccessToken);

                if (!string.IsNullOrEmpty(context.RefreshToken) && ((Options.TokenSaveOptions & OneIdAuthenticationTokenSave.RefreshToken) == OneIdAuthenticationTokenSave.RefreshToken))
                    context.HttpContext.Session.SetString("refresh_token", context.RefreshToken);
            }

            context.RunClaimActions();

            await Events.CreatingTicket(context).ConfigureAwait(false);
            return new AuthenticationTicket(context.Principal!, context.Properties, Scheme.Name);
        }

        /// <inheritdoc/>
        protected override async Task<OAuthTokenResponse> ExchangeCodeAsync(OAuthCodeExchangeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            using var request = new HttpRequestMessage(HttpMethod.Post, Options.TokenEndpoint);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/x-www-form-urlencoded"));
            request.Headers.UserAgent.ParseAdd(OneIdAuthenticationDefaults.UserAgent);

            if (!context.Properties.Items.ContainsKey("code_verifier"))
            {
                throw new InvalidOperationException("code_verifier is missing");
            }

            var parameters = new Dictionary<string, string>
            {
                ["redirect_uri"] = context.RedirectUri,
                ["grant_type"] = "authorization_code",
                ["client_id"] = Options.ClientId,
                ["code"] = context.Code,
                ["code_verifier"] = context.Properties.Items["code_verifier"] ?? ""
            };

            request.Content = new FormUrlEncodedContent(parameters.AsEnumerable() as IEnumerable<KeyValuePair<string?, string?>>);

            using var response = await Backchannel.SendAsync(request, Context.RequestAborted).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                string errorBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                Logger.LogBackchannelFailure(response.StatusCode, response.Headers.ToString(), errorBody);

                return OAuthTokenResponse.Failed(new OneIdAuthenticationException($"An error occurred while retrieving an access token. The remote server returned a {response.StatusCode} response with the following payload: {response.Headers} {errorBody}"));
            }

            var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync().ConfigureAwait(false));

            return OAuthTokenResponse.Success(payload);
        }

        /// <summary>
        /// Extract the security claims from the id token.
        /// </summary>
        /// <param name="token">The json token content</param>
        /// <returns>The list of claims</returns>
        protected virtual IEnumerable<Claim> ExtractClaimsFromToken(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                throw new ArgumentException($"'{nameof(token)}' cannot be null or empty.", nameof(token));
            }

            try
            {
                var retVal = new List<Claim>();

                if (_tokenHandler.CanReadToken(token))
                {
                    var securityToken = _tokenHandler.ReadJwtToken(token);

                    if (securityToken == null || securityToken.Claims == null)
                    {
                        throw new InvalidOperationException($"'{nameof(securityToken)}' cannot be null or have no claims.");
                    }

                    retVal = new(securityToken.Claims)
                    {
                        new Claim(ClaimTypes.NameIdentifier, securityToken.Subject, ClaimValueTypes.String, ClaimsIssuer),
                    };

                    var address = securityToken.Claims.FirstOrDefault(x => x.Type == "email")?.Value;
                    if (!string.IsNullOrEmpty(address))
                    {
                        retVal.Add(new Claim(ClaimTypes.Email, address, ClaimValueTypes.String, Options.ClaimsIssuer));
                    }

                    var givenName = securityToken.Claims.FirstOrDefault(x => x.Type == "given_name")?.Value;
                    if (!string.IsNullOrEmpty(givenName))
                    {
                        retVal.Add(new Claim(ClaimTypes.GivenName, givenName, ClaimValueTypes.String, Options.ClaimsIssuer));
                    }

                    var familyName = securityToken.Claims.FirstOrDefault(x => x.Type == "family_name")?.Value;
                    if (!string.IsNullOrEmpty(familyName))
                    {
                        retVal.Add(new Claim(ClaimTypes.Name, familyName, ClaimValueTypes.String, Options.ClaimsIssuer));
                    }

                    var phoneNumber = securityToken.Claims.FirstOrDefault(x => x.Type == "phoneNumber")?.Value;
                    if (!string.IsNullOrEmpty(phoneNumber))
                    {
                        retVal.Add(new Claim(ClaimTypes.HomePhone, phoneNumber, ClaimValueTypes.String, Options.ClaimsIssuer));
                    }
                }


                return retVal;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to parse JWT for claims from OneID token.", ex);
            }
        }



        private static void SaveIdToken(AuthenticationProperties properties, string idToken)
        {
            if (properties is null)
            {
                throw new ArgumentNullException(nameof(properties));
            }

            if (string.IsNullOrEmpty(idToken))
            {
                throw new ArgumentException($"'{nameof(idToken)}' cannot be null or empty.", nameof(idToken));
            }

            if (!string.IsNullOrWhiteSpace(idToken))
            {
                // Get the currently available tokens
                var tokens = properties.GetTokens().ToList();

                // Add the extra token
                tokens.Add(new AuthenticationToken() { Name = "id_token", Value = idToken });

                // Overwrite store with original tokens with the new additional token
                properties.StoreTokens(tokens);
            }
        }

        /// <summary>
        /// Save tokens if required and get the context identifier.
        /// </summary>
        /// <param name="tokens">The tokens</param>
        /// <param name="properties">The authentication properties.</param>
        /// <param name="identity">The claims identity</param>
        /// <returns></returns>
        private string? ProcessIdTokenAndGetContactIdentifier(OAuthTokenResponse tokens, AuthenticationProperties properties)
        {
            if (tokens is null)
            {
                throw new ArgumentNullException(nameof(tokens));
            }

            if (Options.SaveTokens)
            {
                var idToken = tokens.Response!.RootElement.GetString("id_token");

                // Save id_token as well.
                if ((Options.TokenSaveOptions & OneIdAuthenticationTokenSave.IdToken) == OneIdAuthenticationTokenSave.IdToken && !string.IsNullOrEmpty(idToken))
                {
                    SaveIdToken(properties, idToken);
                }
            }

            //if (tokens.Response != null)
            //{
            //    using var stream = new MemoryStream();
            //    using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });
            //    tokens.Response.WriteTo(writer);
            //    writer.Flush();
            //    string json = Encoding.UTF8.GetString(stream.ToArray());

            //    // Hmm, do we need to do something with serviceEntitlements here?
            //}

            return "";
        }
    }
}
#endif