#region License, Terms and Conditions

//
// OneIdAuthenticationHandler.NetFull.cs
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

#endregion License, Terms and Conditions

#if !NETCORE

using AspNet.Security.OAuth.OneID.Provider;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using static AspNet.Security.OAuth.OneID.OneIdAuthenticationConstants;

namespace AspNet.Security.OAuth.OneID
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1823:Avoid unused private fields", Justification = "<Pending>")]
    public class OneIdAuthenticationHandler : AuthenticationHandler<OneIdAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string StateCookie = ".AspNet.Correlation.OneID";
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;
        private static PkceCode? _pkceCode;
        private static readonly RandomNumberGenerator CryptoRandom = RandomNumberGenerator.Create();
        private const string CorrelationPrefix = ".AspNetCore.Correlation.";
        private const string CorrelationProperty = ".xsrf";
        private const string CorrelationMarker = "N";
        private const string NonceProperty = "N";

        public OneIdAuthenticationHandler(ILogger logger, HttpClient httpClient)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "<Pending>")]
        protected override async Task<AuthenticationTicket?> AuthenticateCoreAsync()
        {
            AuthenticationProperties? properties = null;

            try
            {
                string? code = null;
                string? state = null;

                var query = Request.Query;

                var values = query.GetValues(nameof(code));
                if (values?.Count == 1)
                    code = values[0];

                values = query.GetValues(nameof(state));
                if (values?.Count == 1)
                    state = values[0];

                state = Request.Cookies[StateCookie];

                properties = Options.StateDataFormat?.Unprotect(state);

                if (properties == null)
                    return null;

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                    return new AuthenticationTicket(null, properties);

                if (string.IsNullOrWhiteSpace(code))
                {
                    return new AuthenticationTicket(null, properties);
                }

                var tokenRequestContext = new OneIdTokenRequestContext(Context, Options, state, code, properties);
                await Options.Provider.TokenRequest(tokenRequestContext).ConfigureAwait(false);

                string host = Request.Host.Value;
                string? hostWithoutPrefix = null;

                if (Options.Tlds != null)
                {
                    foreach (var tld in Options.Tlds)
                    {
                        Regex regex = new($"(?<=\\.|)\\w+\\.{tld}$");
                        Match match = regex.Match(host);

                        if (match.Success)
                            hostWithoutPrefix = match.Groups[0].Value;
                    }
                }

                //second/third levels not provided or not found -- try single-level
                if (string.IsNullOrWhiteSpace(hostWithoutPrefix))
                {
                    Regex regex = new("(?<=\\.|)\\w+\\.\\w+$");
                    Match match = regex.Match(host);

                    if (match.Success)
                        hostWithoutPrefix = match.Groups[0].Value;
                }

                var requestPrefix = Request.Scheme + Uri.SchemeDelimiter + hostWithoutPrefix + Request.PathBase;
                var redirectUri = requestPrefix + Options.CallbackPath;
                var body = new Dictionary<string, string>
                {
                    { OneIdAuthenticationConstants.OAuth2Constants.RedirectUri, redirectUri },
                    { OneIdAuthenticationConstants.OAuth2Constants.GrantType, OneIdAuthenticationConstants.OAuth2Constants.AuthorizationCode },
                    { OneIdAuthenticationConstants.OAuth2Constants.ClientId, Uri.EscapeDataString(Options.ClientId) },
                    { OneIdAuthenticationConstants.OAuth2Constants.Code, Uri.EscapeDataString(code) },
                    { OneIdAuthenticationConstants.OAuth2Constants.CodeVerifier, Uri.EscapeDataString(_pkceCode?.CodeVerifier) },
                };

                // Request the token
                using var requestMessage = new HttpRequestMessage(HttpMethod.Post, Options.TokenEndpoint);
                requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                requestMessage.Content = new FormUrlEncodedContent(body);
                var tokenResponse = await _httpClient.SendAsync(requestMessage).ConfigureAwait(false);
                var text = await tokenResponse.Content.ReadAsStringAsync().ConfigureAwait(false);

                // Check if there was an error in the response
                if (!tokenResponse.IsSuccessStatusCode)
                {
                    var status = tokenResponse.StatusCode;
                    if (status == HttpStatusCode.BadRequest)
                    {
                        // Deserialize and Log Error
                        var errorResponse = JsonConvert.DeserializeObject<TokenEndpoint>(text);
                        //this.LogErrorResult(errorResponse.Error, errorResponse.ErrorDescription); // TODO: fix
                    }

                    // Throw error
                    tokenResponse.EnsureSuccessStatusCode();
                }

                var token = await tokenResponse.Content.ReadAsStringAsync().ConfigureAwait(false);
                var response = JsonConvert.DeserializeObject<TokenEndpoint>(text);

                if (response == null)
                    throw new InvalidOperationException("Unexpected response.");

                string accessToken = response.AccessToken;
                string idToken = response.IdToken;
                string refreshToken = response.RefreshToken;

                var idTokenContent = new JwtSecurityTokenHandler().ReadJwtToken(idToken).Payload;

                var context = new OneIdAuthenticatedContext(Context, response, idTokenContent, accessToken, idToken, refreshToken)
                {
                    Identity = new ClaimsIdentity(
                        Options.AuthenticationType,
                        ClaimsIdentity.DefaultNameClaimType,
                        ClaimsIdentity.DefaultRoleClaimType)
                };

                if (!string.IsNullOrEmpty(context.Id))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString, Options.AuthenticationType));
                }

                if (!string.IsNullOrEmpty(context.Email))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, XmlSchemaString, Options.AuthenticationType));
                }

                if (!string.IsNullOrEmpty(context.PhoneNumber))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.HomePhone, context.PhoneNumber, XmlSchemaString, Options.AuthenticationType));
                }

                if (!string.IsNullOrEmpty(context.GivenName))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.GivenName, context.GivenName, XmlSchemaString, Options.AuthenticationType));
                }

                if (!string.IsNullOrEmpty(context.FamilyName))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Surname, context.FamilyName, XmlSchemaString, Options.AuthenticationType));
                }

                context.Properties = properties;

                await Options.Provider.Authenticated(context).ConfigureAwait(false);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                LogErrorResult("Authentication failed", ex.Message, ex);
            }
            return new AuthenticationTicket(null, properties);
        }

        /// <summary>
        /// Only here because I can't see why this normal method fails
        /// </summary>
        /// <param name="properties"></param>
        /// <param name="logger"></param>
        /// <returns></returns>
        private bool ValidateOurCorrelationId(AuthenticationProperties properties,
                                     ILogger logger)
        {
            if (properties == null)
            {
                throw new ArgumentNullException(nameof(properties));
            }

            string correlationCookie = Request.Cookies[StateCookie];
            if (string.IsNullOrWhiteSpace(correlationCookie))
            {
                logger.WriteWarning("{0} cookie not found.", StateCookie);
                return false;
            }

            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = Request.IsSecure
            };

            Response.Cookies.Delete(StateCookie, cookieOptions);

            if (!properties.Dictionary.TryGetValue(
                StateCookie,
                out string correlationExtra))
            {
                logger.WriteWarning("{0} state property not found.", StateCookie);
                return false;
            }

            properties.Dictionary.Remove(StateCookie);

            if (!string.Equals(correlationCookie, correlationExtra, StringComparison.Ordinal))
            {
                logger.WriteWarning("{0} correlation cookie and state property mismatch.",
                                        StateCookie);
                return false;
            }

            return true;
        }

        /// <summary>The log error result.</summary>
        /// <param name="error">The error.</param>
        /// <param name="errorDescription">The error description.</param>
        /// <param name="ex">The exception</param>
        private void LogErrorResult(string error, string errorDescription, Exception ex)
        {
            _logger.WriteError(string.Format(CultureInfo.InvariantCulture, "OneId error occurred. error: {0} description: {1}", error, errorDescription), ex);
        }

        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync().ConfigureAwait(false);
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                var ticket = await AuthenticateAsync().ConfigureAwait(false);

                if (ticket == null)
                {
                    _logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                var context = new OneIdReturnEndpointContext(Context, ticket)
                {
                    RedirectUri = ticket.Properties.RedirectUri,
                    SignInAsAuthenticationType = Options.SignInAsAuthenticationType
                };
                ticket.Properties.RedirectUri = null;

                await Options.Provider.ReturnEndpoint(context).ConfigureAwait(false);

                if (context.Identity != null && context.SignInAsAuthenticationType != null)
                {
                    var identity = context.Identity;
                    if (!string.Equals(identity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                    {
                        identity = new ClaimsIdentity(identity.Claims, context.SignInAsAuthenticationType, identity.NameClaimType, identity.RoleClaimType);
                    }

                    Context.Authentication.SignIn(context.Properties, identity);
                }
                if (!context.IsRequestCompleted && context.RedirectUri != null)
                {
                    if (context.Identity == null)
                    {
                        // add a redirect hint that sign-in failed in some way
                        context.RedirectUri = WebUtilities.AddQueryString(context.RedirectUri, "error", "access_denied");
                    }
                    Response.Redirect(context.RedirectUri);
                    context.RequestCompleted();
                }

                return context.IsRequestCompleted;
            }
            return false;
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.CompletedTask;
            }

            var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge == null)
            {
                return Task.FromResult<object?>(null);
            }

            string host = Request.Host.Value;
            string? hostWithoutPrefix = null;

            if (Options.Tlds != null)
            {
                foreach (var tld in Options.Tlds)
                {
                    Regex regex = new($"(?<=\\.|)\\w+\\.{tld}$");
                    Match match = regex.Match(host);

                    if (match.Success)
                        hostWithoutPrefix = match.Groups[0].Value;
                }
            }

            //second/third levels not provided or not found -- try single-level
            if (string.IsNullOrWhiteSpace(hostWithoutPrefix))
            {
                Regex regex = new("(?<=\\.|)\\w+\\.\\w+$");
                Match match = regex.Match(host);

                if (match.Success)
                    hostWithoutPrefix = match.Groups[0].Value;
            }

            string baseUri =
                Request.Scheme +
                Uri.SchemeDelimiter +
                hostWithoutPrefix +
                Request.PathBase;

            string currentUri =
                baseUri +
                Request.Path +
                Request.QueryString;

            string redirectUri =
                baseUri +
                Options.CallbackPath;

            var properties = challenge.Properties;
            if (string.IsNullOrEmpty(properties.RedirectUri))
                properties.RedirectUri = currentUri;

            // OAuth2 10.12 CSRF
            GenerateCorrelationId(properties);

            string scope = string.Join(" ", Options.Scope);

            string state = Options.StateDataFormat!.Protect(properties);

            // First generate the PKCE verifier and challenge
            _pkceCode = PkceCode.GeneratePKCECodes();

            // Add nonce
            var nonce = Guid.NewGuid().ToString();

            var explicitParameters = new Dictionary<string, string>
                {
                    { OneIdAuthenticationConstants.OAuth2Constants.ResponseType, OneIdAuthenticationConstants.OAuth2Constants.Code },
                    { OneIdAuthenticationConstants.OAuth2Constants.ClientId, Uri.EscapeDataString(Options.ClientId) },
                    { OneIdAuthenticationConstants.OAuth2Constants.RedirectUri, Uri.EscapeDataString(redirectUri) },
                    { OneIdAuthenticationConstants.OAuth2Constants.Scope, Uri.EscapeDataString(scope) },
                    { OneIdAuthenticationConstants.OAuth2Constants.State, Uri.EscapeDataString(state) },
                    { OneIdAuthenticationConstants.OAuth2Constants.Nonce, Uri.EscapeDataString(nonce) },
                    { OneIdAuthenticationConstants.OAuth2Constants.CodeChallenge, Uri.EscapeDataString(_pkceCode.CodeChallenge) },
                    { OneIdAuthenticationConstants.OAuth2Constants.CodeChallengeMethod, Uri.EscapeDataString("S256") },
                    { OneIdAuthenticationConstants.OAuth2Constants.Audience, Uri.EscapeDataString(ClaimNames.ApiAudience) },
                    { OneIdAuthenticationConstants.OAuth2Constants.Profile, Uri.EscapeDataString(Options.GetServiceProfileOptionsString()) },
                };

            var requestParameters = MergeAdditionalKeyValuePairsIntoExplicitKeyValuePairs(explicitParameters, Options.AdditionalParameters);
            var authorizationEndpoint = Options.AuthorizationEndpoint + requestParameters.ToQueryString();

            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = Request.IsSecure
            };

            var context = new OneIdApplyRedirectContext(Context, Options, new Uri(authorizationEndpoint), properties);

            context.Response.Cookies.Append(StateCookie, state, cookieOptions);

            Options.Provider.ApplyRedirect(context);

            return Task.CompletedTask;
        }

        /// <summary>Merges additional into explicit properties keeping all explicit properties intact</summary>
        /// <param name="explicitProperties">The explicit Properties.</param>
        /// <param name="additionalProperties">The additional Properties.</param>
        /// <returns>The <see cref="Dictionary{String,String}"/>.</returns>
        private static Dictionary<string, string> MergeAdditionalKeyValuePairsIntoExplicitKeyValuePairs(
            Dictionary<string, string> explicitProperties,
            Dictionary<string, string>? additionalProperties = null)
        {
            var merged = explicitProperties;

            // no need to iterate if additional is null
            if (additionalProperties != null)
            {
                merged = explicitProperties.Concat(additionalProperties.Where(add => !explicitProperties.ContainsKey(add.Key)))
                        .Where(a => !string.IsNullOrEmpty(a.Value))
                        .ToDictionary(final => final.Key, final => final.Value);
            }

            return merged;
        }

        protected void GenerateOurCorrelationId(AuthenticationProperties properties)
        {
            if (properties == null)
            {
                throw new ArgumentNullException(nameof(properties));
            }

            const string correlationKey = StateCookie;

            var nonceBytes = new byte[32];
            CryptoRandom.GetBytes(nonceBytes);
            string correlationId = TextEncodings.Base64Url.Encode(nonceBytes);

            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = Request.IsSecure
            };

            properties.Dictionary[correlationKey] = correlationId;

            Response.Cookies.Append(correlationKey, correlationId, cookieOptions);
        }
    }
}

#endif