#region License, Terms and Conditions

//
// OneIdAuthenticationHandler.cs
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

using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Diagnostics.Contracts;
using static AspNet.Security.OAuth.OneID.OneIdAuthenticationConstants;
using System.Net.Http.Headers;
using System.Collections.Generic;
using System.Net;
using Newtonsoft.Json;
using System.Globalization;
using System.Linq;
using System.IdentityModel.Tokens.Jwt;
using AspNet.Security.OAuth.OneID.Provider;

#if NETCORE

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Security.Claims;

#elif NETFULL
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;
using System.Security.Claims;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin;
#endif

namespace AspNet.Security.OAuth.OneID
{
#if NETCORE

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
            Contract.Requires(options != null);
            Contract.Requires(logger != null);
            Contract.Requires(encoder != null);
            Contract.Requires(clock != null);

            _tokenHandler = tokenHandler;
        }

        /// <inheritdoc />
        protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
        {
            string challengeUrl = base.BuildChallengeUrl(properties, redirectUri);

            challengeUrl = QueryHelpers.AddQueryString(challengeUrl, "aud", ClaimNames.ApiAudience);
            challengeUrl = QueryHelpers.AddQueryString(challengeUrl, "_profile", ProfileNames.DiagnosticSearchProfile);

            return challengeUrl;
        }

        /// <inheritdoc />
        protected override async Task<AuthenticationTicket> CreateTicketAsync(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
        {
            var contextId = ProcessIdTokenAndGetContactIdentifier(tokens, properties, identity);

            string idToken = tokens.Response.RootElement.GetString("id_token");

            if (Logger.IsEnabled(LogLevel.Trace))
            {
                Logger.LogTrace("Access Token: {AccessToken}", tokens.AccessToken);
                Logger.LogTrace("Refresh Token: {RefreshToken}", tokens.RefreshToken);
                Logger.LogTrace("Token Type: {TokenType}", tokens.TokenType);
                Logger.LogTrace("Expires In: {ExpiresIn}", tokens.ExpiresIn);
                Logger.LogTrace("Response: {TokenResponse}", tokens.Response.RootElement);
                Logger.LogTrace("ID Token: {IdToken}", idToken);
            }

            if (string.IsNullOrWhiteSpace(idToken))
            {
                throw new InvalidOperationException("No OneID ID token was returned in the OAuth token response.");
            }

            if (string.IsNullOrEmpty(contextId))
            {
                throw new InvalidOperationException("An error occurred trying to obtain the context identifier from the current user's identity claims.");
            }

            if (Options.ValidateTokens)
            {
                var validateIdContext = new OneIdValidateIdTokenContext(Context, Scheme, Options, idToken);
                //await Options.Events.ValidateIdToken(validateIdContext);
            }

            foreach (var claim in ExtractClaimsFromToken(idToken))
            {
                identity.AddClaim(claim);
            }

            var principal = new ClaimsPrincipal(identity);

            var context = new OneIdAuthenticatedContext(principal, properties, Context, Scheme, Options, Backchannel, tokens, tokens.Response.RootElement);

            List<AuthenticationToken> exactTokens = context.Properties.GetTokens().ToList();

            // Store the received tokens somewhere, if we should
            if ((Options.TokenSaveOptions & OneIdAuthenticationTokenSave.AccessToken) == OneIdAuthenticationTokenSave.AccessToken)
            {
                context.HttpContext.Session.SetString("access_token", context.AccessToken);
            }
            if ((Options.TokenSaveOptions & OneIdAuthenticationTokenSave.RefreshToken) == OneIdAuthenticationTokenSave.RefreshToken)
            {
                context.HttpContext.Session.SetString("refresh_token", context.RefreshToken);
            }

            context.RunClaimActions();

            await Events.CreatingTicket(context);
            return new AuthenticationTicket(context.Principal, context.Properties, Scheme.Name);
        }

        /// <summary>
        /// Extract the security claims from the id token.
        /// </summary>
        /// <param name="token">The json token content</param>
        /// <returns>The list of claims</returns>
        protected virtual IEnumerable<Claim> ExtractClaimsFromToken(string token)
        {
            try
            {
                var securityToken = _tokenHandler.ReadJwtToken(token);

                var retVal = new List<Claim>(securityToken.Claims)
                {
                    new Claim(ClaimTypes.NameIdentifier, securityToken.Subject, ClaimValueTypes.String, ClaimsIssuer),
                };

                string address = securityToken.Claims.FirstOrDefault(x => x.Type == "email")?.Value;
                if (!string.IsNullOrEmpty(address))
                {
                    retVal.Add(new Claim(ClaimTypes.Email, address, ClaimValueTypes.String, Options.ClaimsIssuer));
                }

                string givenName = securityToken.Claims.FirstOrDefault(x => x.Type == "given_name")?.Value;
                if (!string.IsNullOrEmpty(givenName))
                {
                    retVal.Add(new Claim(ClaimTypes.GivenName, givenName, ClaimValueTypes.String, Options.ClaimsIssuer));
                }

                string familyName = securityToken.Claims.FirstOrDefault(x => x.Type == "family_name")?.Value;
                if (!string.IsNullOrEmpty(familyName))
                {
                    retVal.Add(new Claim(ClaimTypes.Name, familyName, ClaimValueTypes.String, Options.ClaimsIssuer));
                }

                string phoneNumber = securityToken.Claims.FirstOrDefault(x => x.Type == "phoneNumber")?.Value;
                if (!string.IsNullOrEmpty(phoneNumber))
                {
                    retVal.Add(new Claim(ClaimTypes.HomePhone, phoneNumber, ClaimValueTypes.String, Options.ClaimsIssuer));
                }

                return retVal;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to parse JWT for claims from Apple ID token.", ex);
            }
        }

        /// <inheritdoc/>
        protected override async Task<OAuthTokenResponse> ExchangeCodeAsync(OAuthCodeExchangeContext context)
        {
            Contract.Requires(context != null);

            using var request = new HttpRequestMessage(HttpMethod.Post, Options.TokenEndpoint);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/x-www-form-urlencoded"));
            request.Headers.UserAgent.ParseAdd(OneIdAuthenticationDefaults.UserAgent);

            var parameters = new Dictionary<string, string>
            {
                ["redirect_uri"] = context.RedirectUri,
                ["grant_type"] = "authorization_code",
                ["client_id"] = Options.ClientId,
                ["code"] = context.Code,
                ["code_verifier"] = context.Properties.Items["code_verifier"]
            };

            request.Content = new FormUrlEncodedContent(parameters);

            using var response = await Backchannel.SendAsync(request, Context.RequestAborted);

            if (!response.IsSuccessStatusCode)
            {
                Logger.LogError("An error occurred while retrieving an access token: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync());

                return OAuthTokenResponse.Failed(new Exception("An error occurred while retrieving an access token."));
            }

            var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

            return OAuthTokenResponse.Success(payload);
        }

        /// <summary>
        /// Save tokens if required and get the context identifier.
        /// </summary>
        /// <param name="tokens">The tokens</param>
        /// <param name="properties">The authentication properties.</param>
        /// <param name="identity">The claims identity</param>
        /// <returns></returns>
        private string ProcessIdTokenAndGetContactIdentifier(OAuthTokenResponse tokens, AuthenticationProperties properties, ClaimsIdentity identity)
        {
            var idToken = tokens.Response.RootElement.GetString("id_token");

            if (Options.SaveTokens)
            {
                // Save id_token as well.
                if ((Options.TokenSaveOptions & OneIdAuthenticationTokenSave.IdToken) == OneIdAuthenticationTokenSave.IdToken && !string.IsNullOrEmpty(idToken))
                {
                    SaveIdToken(properties, idToken);
                }
            }

            //var tokenValidationResult = await ValidateAsync(idToken, Options.TokenValidationParameters);

            var contextIdentifier = tokens.Response.RootElement.GetString("contextSessionId");

            return contextIdentifier;
        }

        //private async Task<TokenValidationResult> ValidateAsync(
        //    string idToken,
        //    TokenValidationParameters validationParameters)
        //{
        //    Contract.Requires(idToken != null);
        //    Contract.Requires(validationParameters != null);

        //    if (Options.SecurityTokenHandler == null)
        //    {
        //        throw new InvalidOperationException("The options SecurityTokenHandler is null.");
        //    }

        //    if (!Options.SecurityTokenHandler.CanValidateToken)
        //    {
        //        throw new NotSupportedException($"The configured {nameof(JsonWebTokenHandler)} cannot validate tokens.");
        //    }

        //    if (Options.ConfigurationManager == null)
        //    {
        //        throw new InvalidOperationException($"An OpenID Connect configuration manager has not been set on the {nameof(SuperOfficeAuthenticationOptions)} instance.");
        //    }

        //    var openIdConnectConfiguration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
        //    validationParameters.IssuerSigningKeys = openIdConnectConfiguration.JsonWebKeySet.Keys;

        //    try
        //    {
        //        var result = Options.SecurityTokenHandler.ValidateToken(idToken, validationParameters);

        //        if (result.Exception != null || !result.IsValid)
        //        {
        //            throw new SecurityTokenValidationException("SuperOffice ID token validation failed.", result.Exception);
        //        }

        //        return result;
        //    }
        //    catch (Exception ex)
        //    {
        //        throw new SecurityTokenValidationException("SuperOffice ID token validation failed.", ex);
        //    }
        //}

        private void SaveIdToken(AuthenticationProperties properties, string idToken)
        {
            Contract.Requires(properties != null);
            Contract.Requires(idToken != null);

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
    }

#elif NETFULL

    public class OneIdAuthenticationHandler : AuthenticationHandler<OneIdAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string StateCookie = ".AspNet.Correlation.OneID";
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;
        public static PKCECode _pkceCode;

        public OneIdAuthenticationHandler(ILogger logger, HttpClient httpClient)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string code = null;
                string state = null;

                var query = Request.Query;

                var values = query.GetValues(nameof(code));
                if (values != null && values.Count == 1)
                    code = values[0];

                values = query.GetValues(nameof(state));
                if (values != null && values.Count == 1)
                    state = values[0];

                state = Request.Cookies[StateCookie];

                properties = Options.StateDataFormat.Unprotect(state);

                if (properties == null)
                    return null;

                // OAuth2 10.12 CSRF
                if (!ValidateOurCorrelationId(properties, _logger))
                    return new AuthenticationTicket(null, properties);

                if (string.IsNullOrWhiteSpace(code))
                {
                    return new AuthenticationTicket(null, properties);
                }

                var tokenRequestContext = new OneIdTokenRequestContext(this.Context, this.Options, state, code, properties);
                await this.Options.Provider.TokenRequest(tokenRequestContext);

                var requestPrefix = Request.Scheme + Uri.SchemeDelimiter + this.Request.Host + this.Request.PathBase;
                var redirectUri = requestPrefix + Options.CallbackPath;
                var body = new Dictionary<string, string>
                {
                    { OneIdAuthenticationConstants.OAuth2Constants.RedirectUri, redirectUri },
                    { OneIdAuthenticationConstants.OAuth2Constants.GrantType, OneIdAuthenticationConstants.OAuth2Constants.AuthorizationCode },
                    { OneIdAuthenticationConstants.OAuth2Constants.ClientId, Uri.EscapeDataString(this.Options.ClientId) },
                    //{ OneIdAuthenticationConstants.OAuth2Constants.Scope, string.Join(" ", Options.Scope) },
                    { OneIdAuthenticationConstants.OAuth2Constants.Code, Uri.EscapeDataString(code) },
                    { OneIdAuthenticationConstants.OAuth2Constants.CodeVerifier, Uri.EscapeDataString(_pkceCode.CodeVerifier) },
                };

                // Request the token
                var requestMessage = new HttpRequestMessage(HttpMethod.Post, this.Options.TokenEndpoint);
                requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                requestMessage.Content = new FormUrlEncodedContent(body);
                var tokenResponse = await _httpClient.SendAsync(requestMessage);
                var text = await tokenResponse.Content.ReadAsStringAsync();

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

                var token = await tokenResponse.Content.ReadAsStringAsync();
                var response = JsonConvert.DeserializeObject<TokenEndpoint>(text);

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
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString, this.Options.AuthenticationType));
                }

                if (!string.IsNullOrEmpty(context.Email))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, XmlSchemaString, this.Options.AuthenticationType));
                }

                if (!string.IsNullOrEmpty(context.PhoneNumber))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.HomePhone, context.PhoneNumber, XmlSchemaString, this.Options.AuthenticationType));
                }

                if (!string.IsNullOrEmpty(context.GivenName))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.GivenName, context.GivenName, XmlSchemaString, this.Options.AuthenticationType));
                }

                if (!string.IsNullOrEmpty(context.FamilyName))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Surname, context.FamilyName, XmlSchemaString, this.Options.AuthenticationType));
                }

                context.Properties = properties;

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError("Authentication failed", ex);
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
                throw new ArgumentNullException("properties");
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

            string correlationExtra;
            if (!properties.Dictionary.TryGetValue(
                StateCookie,
                out correlationExtra))
            {
                logger.WriteWarning("{0} state property not found.", StateCookie);
                return false;
            }

            properties.Dictionary.Remove(StateCookie);

            if (!string.Equals(correlationCookie, correlationExtra, StringComparison.Ordinal))
            {
                logger.WriteWarning("{0} correlation cookie and state property mismatch.",
                                        StateCookie);
                return true; // HACK
            }

            return true;
        }

        /// <summary>The log error result.</summary>
        /// <param name="error">The error.</param>
        /// <param name="errorDescription">The error description.</param>
        private void LogErrorResult(string error, string errorDescription)
        {
            _logger.WriteError(string.Format(CultureInfo.InvariantCulture, "OneId error occurred. error: {0} description: {1}", error, errorDescription));
        }

        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                var ticket = await AuthenticateAsync();

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

                await Options.Provider.ReturnEndpoint(context);

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
                return Task.FromResult<object>(null);
            }

            string baseUri =
                Request.Scheme +
                Uri.SchemeDelimiter +
                Request.Host +
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

            string state = Options.StateDataFormat.Protect(properties);

            // First generate the PKCE verifier and challenge
            _pkceCode = PKCECode.GeneratePKCECodes();

            // Add nonce
            var nonce = Guid.NewGuid().ToString();

            var explicitParameters = new Dictionary<string, string>
                {
                    { OneIdAuthenticationConstants.OAuth2Constants.ResponseType, OneIdAuthenticationConstants.OAuth2Constants.Code },
                    { OneIdAuthenticationConstants.OAuth2Constants.ClientId, Uri.EscapeDataString(this.Options.ClientId) },
                    { OneIdAuthenticationConstants.OAuth2Constants.RedirectUri, Uri.EscapeDataString(redirectUri) },
                    { OneIdAuthenticationConstants.OAuth2Constants.Scope, Uri.EscapeDataString(scope) },
                    { OneIdAuthenticationConstants.OAuth2Constants.State, Uri.EscapeDataString(state) },
                    { OneIdAuthenticationConstants.OAuth2Constants.Nonce, Uri.EscapeDataString(nonce) },
                    { OneIdAuthenticationConstants.OAuth2Constants.CodeChallenge, Uri.EscapeDataString(_pkceCode.CodeChallenge) },
                    { OneIdAuthenticationConstants.OAuth2Constants.CodeChallengeMethod, Uri.EscapeDataString("S256") },
                    { OneIdAuthenticationConstants.OAuth2Constants.Audience, Uri.EscapeDataString(ClaimNames.ApiAudience) },
                    { OneIdAuthenticationConstants.OAuth2Constants.Profile, Uri.EscapeDataString(ProfileNames.DiagnosticSearchProfile) },
                };

            var requestParameters = MergeAdditionalKeyValuePairsIntoExplicitKeyValuePairs(explicitParameters, this.Options.AdditionalParameters);
            var authorizationEndpoint = this.Options.AuthorizationEndpoint + requestParameters.ToQueryString();

            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = Request.IsSecure
            };

            var context = new OneIdApplyRedirectContext(Context, Options, authorizationEndpoint, properties);

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
            Dictionary<string, string> additionalProperties = null)
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
    }

#endif
}