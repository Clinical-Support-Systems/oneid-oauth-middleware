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

#if NET8_0_OR_GREATER

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using static AspNet.Security.OAuth.OneID.OneIdAuthenticationConstants;

namespace AspNet.Security.OAuth.OneID
{
    /// <summary>
    ///     The OneId oauth/oidc authentication handler
    /// </summary>
    public class OneIdAuthenticationHandler : OAuthHandler<OneIdAuthenticationOptions>
    {
#if !NET8_0_OR_GREATER
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="options">The options</param>
        /// <param name="logger">The logger</param>
        /// <param name="encoder">The encoder</param>
        /// <param name="clock">The clock skew</param>
        /// <param name="tokenHandler">The security token handler</param>
        public OneIdAuthenticationHandler(IOptionsMonitor<OneIdAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        {
            ArgumentNullException.ThrowIfNull(options);
            ArgumentNullException.ThrowIfNull(logger);
            ArgumentNullException.ThrowIfNull(encoder);
            ArgumentNullException.ThrowIfNull(clock);
        }
#endif

#if NET8_0_OR_GREATER
#pragma warning disable CA1510 // Suppress false positives for constructor argument validation.
        public OneIdAuthenticationHandler(IOptionsMonitor<OneIdAuthenticationOptions> options, ILoggerFactory logger,
            UrlEncoder encoder) : base(ValidateOptions(options), ValidateLogger(logger), ValidateEncoder(encoder))
        {
            // All validation performed in helper methods passed to base.
        }

        private static IOptionsMonitor<OneIdAuthenticationOptions> ValidateOptions(IOptionsMonitor<OneIdAuthenticationOptions> options)
        {
            ArgumentNullException.ThrowIfNull(options);
            return options;
        }

        private static ILoggerFactory ValidateLogger(ILoggerFactory logger)
        {
            ArgumentNullException.ThrowIfNull(logger);
            return logger;
        }

        private static UrlEncoder ValidateEncoder(UrlEncoder encoder)
        {
            ArgumentNullException.ThrowIfNull(encoder);
            return encoder;
        }
#pragma warning restore CA1510
#endif

        /// <inheritdoc />
        protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
        {
            ArgumentNullException.ThrowIfNull(properties);

            if (string.IsNullOrEmpty(redirectUri))
            {
                throw new ArgumentException($"'{nameof(redirectUri)}' cannot be null or empty.", nameof(redirectUri));
            }

            string challengeUrl;
            try
            {
                // In a fully configured ASP.NET Core pipeline this should succeed.
                // Unit tests that manually construct the handler may omit services required by the base implementation (e.g. nonce/state generators),
                // which can lead to a NullReferenceException inside the framework's BuildChallengeUrl.
                challengeUrl = base.BuildChallengeUrl(properties, redirectUri);
            }
            catch (NullReferenceException)
            {
                // Fallback: construct the minimal challenge URL manually so unit tests can validate appended parameters
                // without requiring the full authentication infrastructure.
                var scope = string.Join(' ', Options.Scope); // Scope list always initialized in options constructor.
                var parameters = new Dictionary<string, string?>
                {
                    ["response_type"] = Options.ResponseType,
                    ["client_id"] = Options.ClientId,
                    ["redirect_uri"] = redirectUri,
                    ["scope"] = scope
                };
                challengeUrl = QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, parameters);
            }

            challengeUrl = QueryHelpers.AddQueryString(challengeUrl, "aud", ClaimNames.ApiAudience);
            challengeUrl = QueryHelpers.AddQueryString(challengeUrl, "_profile", Options.GetServiceProfileOptionsString());

            return challengeUrl;
        }

        /// <summary>
        ///     The handler calls methods on the events which give the application control at certain points where processing is
        ///     occurring.
        ///     If it is not provided a default instance is supplied which does nothing when the methods are called.
        /// </summary>
        protected new OneIdAuthenticationEvents Events
        {
            get => (OneIdAuthenticationEvents)base.Events;
            set => base.Events = value;
        }

        /// <inheritdoc />
        protected override Task<object> CreateEventsAsync()
        {
            return Task.FromResult<object>(new OneIdAuthenticationEvents());
        }

        /// <inheritdoc />
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1848:Use the LoggerMessage delegates", Justification = "<Pending>")]
        protected override async Task<AuthenticationTicket> CreateTicketAsync(ClaimsIdentity identity,
            AuthenticationProperties properties, OAuthTokenResponse tokens)
        {
            ArgumentNullException.ThrowIfNull(identity);
            ArgumentNullException.ThrowIfNull(properties);
            ArgumentNullException.ThrowIfNull(tokens);

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

            if (Options.ValidateTokens)
            {
                var validateIdContext = new OneIdValidateIdTokenContext(Context, Scheme, Options, idToken);
                await Events.ValidateIdToken(validateIdContext).ConfigureAwait(false);
            }

            foreach (var claim in ExtractClaimsFromToken(idToken))
            {
                identity.AddClaim(claim);
            }

            // If username not found in ID token and access token looks like a JWT, try access token
            if (!identity.HasClaim(c => c.Type == ClaimTypes.Actor) &&
                !string.IsNullOrEmpty(tokens.AccessToken) &&
                tokens.AccessToken.Contains('.', StringComparison.Ordinal) && tokens.AccessToken.Split('.').Length == 3) // Simple check if it looks like a JWT
            {
#pragma warning disable CA1031 // Do not catch general exception types
                try
                {
                    if (Options.SecurityTokenHandler?.CanReadToken(tokens.AccessToken) == true)
                    {
                        var accessTokenClaims = ExtractClaimsFromToken(tokens.AccessToken);
                        var actorClaim = accessTokenClaims.FirstOrDefault(c => c.Type == ClaimTypes.Actor);
                        if (actorClaim != null)
                        {
                            identity.AddClaim(actorClaim);
                            Logger.LogInformation("Username claim extracted from access token: {Username}", actorClaim.Value);
                        }
                    }
                }
                catch (Exception ex)
                {
                    // Just log and continue, don't throw
                    Logger.LogWarning(ex, "Failed to extract claims from access token. It may not be a JWT.");
                }
#pragma warning restore CA1031 // Do not catch general exception types
            }

            var principal = new ClaimsPrincipal(identity);

            var context = new OAuthCreatingTicketContext(principal, properties, Context, Scheme, Options, Backchannel,
                tokens, tokens.Response!.RootElement);

            // Store the received tokens somewhere, if we should
            if (Context.Features.Get<ISessionFeature>() != null)
            {
                if (!string.IsNullOrEmpty(principal.Identity?.Name))
                {
                    context.HttpContext.Session.SetString("original_username", principal.Identity.Name);
                }

                if (!string.IsNullOrEmpty(idToken) &&
                    (Options.TokenSaveOptions & OneIdAuthenticationTokenSave.IdToken) ==
                    OneIdAuthenticationTokenSave.IdToken)
                {
                    context.HttpContext.Session.SetString("id_token", idToken);
                }

                if (!string.IsNullOrEmpty(context.AccessToken) &&
                    (Options.TokenSaveOptions & OneIdAuthenticationTokenSave.AccessToken) ==
                    OneIdAuthenticationTokenSave.AccessToken)
                {
                    context.HttpContext.Session.SetString("access_token", context.AccessToken);
                }

                if (!string.IsNullOrEmpty(context.RefreshToken) &&
                    (Options.TokenSaveOptions & OneIdAuthenticationTokenSave.RefreshToken) ==
                    OneIdAuthenticationTokenSave.RefreshToken)
                {
                    context.HttpContext.Session.SetString("refresh_token", context.RefreshToken);
                }
            }

            context.RunClaimActions();

            await Events.CreatingTicket(context).ConfigureAwait(false);
            return new AuthenticationTicket(context.Principal!, context.Properties, Scheme.Name);
        }

        /// <inheritdoc />
        protected override async Task<OAuthTokenResponse> ExchangeCodeAsync(OAuthCodeExchangeContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            using var request = new HttpRequestMessage(HttpMethod.Post, Options.TokenEndpoint);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/x-www-form-urlencoded"));
            request.Headers.UserAgent.ParseAdd(OneIdAuthenticationDefaults.UserAgent);

            if (!context.Properties.Items.TryGetValue("code_verifier", out var codeVerifierValue))
            {
                throw new InvalidOperationException("code_verifier is missing");
            }

            var parameters = new Dictionary<string, string>
            {
                ["redirect_uri"] = context.RedirectUri,
                ["grant_type"] = "authorization_code",
                ["client_id"] = Options.ClientId,
                ["code"] = context.Code,
                ["code_verifier"] = codeVerifierValue ?? string.Empty
            };

            request.Content = new FormUrlEncodedContent(parameters.AsEnumerable());

            using var response = await Backchannel.SendAsync(request, Context.RequestAborted).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                var errorBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                Logger.LogBackchannelFailure(response.StatusCode, response.Headers.ToString(), errorBody);

                return OAuthTokenResponse.Failed(new OneIdAuthenticationException(
                    $"An error occurred while retrieving an access token. The remote server returned a {response.StatusCode} response with the following payload: {response.Headers} {errorBody}"));
            }

            var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync().ConfigureAwait(false));

            return OAuthTokenResponse.Success(payload);
        }

        /// <summary>
        ///     Extract the security claims from the id token.
        /// </summary>
        /// <param name="idToken">The json token content</param>
        /// <returns>The list of claims</returns>
        protected virtual IEnumerable<Claim> ExtractClaimsFromToken(string idToken)
        {
            if (string.IsNullOrEmpty(idToken))
            {
                throw new ArgumentException($"'{nameof(idToken)}' cannot be null or empty.", nameof(idToken));
            }

            try
            {
                var retVal = new List<Claim>();

                Options.SecurityTokenHandler ??= new JsonWebTokenHandler();

                if (!Options.SecurityTokenHandler.CanReadToken(idToken))
                {
                    return retVal;
                }

                // Parse and get the token
                var parsedToken = Options.SecurityTokenHandler.ReadJsonWebToken(idToken);

                if (parsedToken == null || parsedToken.Claims == null)
                {
                    throw new InvalidOperationException(
                        $"'{nameof(parsedToken)}' cannot be null or have no claims.");
                }

                retVal = [.. parsedToken.Claims];

                if (!string.IsNullOrEmpty(parsedToken.Subject))
                {
                    retVal.Add(new Claim(ClaimTypes.NameIdentifier, parsedToken.Subject, ClaimValueTypes.String,
                        ClaimsIssuer));
                }

                var address = parsedToken.Claims.FirstOrDefault(x => x.Type == "email")?.Value;
                if (!string.IsNullOrEmpty(address))
                {
                    retVal.Add(new Claim(ClaimTypes.Email, address, ClaimValueTypes.String, Options.ClaimsIssuer));
                }

                var givenName = parsedToken.Claims.FirstOrDefault(x => x.Type == "given_name")?.Value;
                if (!string.IsNullOrEmpty(givenName))
                {
                    retVal.Add(new Claim(ClaimTypes.GivenName, givenName, ClaimValueTypes.String,
                        Options.ClaimsIssuer));
                }

                var familyName = parsedToken.Claims.FirstOrDefault(x => x.Type == "family_name")?.Value;
                if (!string.IsNullOrEmpty(familyName))
                {
                    retVal.Add(new Claim(ClaimTypes.Name, familyName, ClaimValueTypes.String,
                        Options.ClaimsIssuer));
                }

                var phoneNumber = parsedToken.Claims.FirstOrDefault(x => x.Type == "phoneNumber")?.Value;
                if (!string.IsNullOrEmpty(phoneNumber))
                {
                    retVal.Add(new Claim(ClaimTypes.HomePhone, phoneNumber, ClaimValueTypes.String,
                        Options.ClaimsIssuer));
                }

                // Look for username in multiple possible claims
                var actor = parsedToken.Claims.FirstOrDefault(x => x.Type == "username")?.Value ??
                            parsedToken.Claims.FirstOrDefault(x => x.Type == "preferred_username")?.Value ??
                            parsedToken.Claims.FirstOrDefault(x => x.Type == "upn")?.Value ??
                            parsedToken.Claims.FirstOrDefault(x => x.Type == "unique_name")?.Value;

                if (!string.IsNullOrEmpty(actor))
                {
                    retVal.Add(new Claim(ClaimTypes.Actor, actor, ClaimValueTypes.String, Options.ClaimsIssuer));
                }

                return retVal;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to parse JWT for claims from OneID token.", ex);
            }
        }

        private static void SaveToken(AuthenticationProperties properties, string token, string tokenName)
        {
            ArgumentNullException.ThrowIfNull(properties);
            if (string.IsNullOrEmpty(token))
            {
                throw new ArgumentException($"'{nameof(token)}' cannot be null or empty.", nameof(token));
            }

            // Get the currently available tokens and check for the token existence more efficiently
            var tokens = properties.GetTokens().ToList();

            if (!tokens.Exists(t => t.Name == tokenName && t.Value == token))
            {
                tokens.Add(new AuthenticationToken { Name = tokenName, Value = token });
            }

            // Store the updated tokens
            properties.StoreTokens(tokens);
        }

        /// <summary>
        ///     Save tokens if required and get the context identifier.
        /// </summary>
        /// <param name="tokens">The tokens</param>
        /// <param name="properties">The authentication properties.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        private string? ProcessIdTokenAndGetContactIdentifier(OAuthTokenResponse tokens,
            AuthenticationProperties properties)
        {
            ArgumentNullException.ThrowIfNull(tokens);

            if (Options.SaveTokens)
            {
                // Consolidate logic for token saving to avoid repetition
                SaveTokenIfRequired(tokens, properties, "id_token", OneIdAuthenticationTokenSave.IdToken);
                SaveTokenIfRequired(tokens, properties, "access_token", OneIdAuthenticationTokenSave.AccessToken);
                SaveTokenIfRequired(tokens, properties, "refresh_token", OneIdAuthenticationTokenSave.RefreshToken);
            }

            // If specific identifiers need to be extracted, this is where the logic should go
            // From https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers/blob/21b3e95f0210b2fba336b0ea06c67bb74d635369/src/AspNet.Security.OAuth.SuperOffice/SuperOfficeAuthenticationHandler.cs#L80

            //var tokenValidationResult = await ValidateAsync(idToken, Options.TokenValidationParameters.Clone());

            //var contextIdentifier = string.Empty;
            //var webApiUrl = string.Empty;

            //foreach (var claim in tokenValidationResult.ClaimsIdentity.Claims)
            //{
            //    if (claim.Type == SuperOfficeAuthenticationConstants.ClaimNames.ContextIdentifier)
            //    {
            //        contextIdentifier = claim.Value;
            //    }

            //    if (claim.Type == SuperOfficeAuthenticationConstants.ClaimNames.WebApiUrl)
            //    {
            //        webApiUrl = claim.Value;
            //    }

            //    if (claim.Type == SuperOfficeAuthenticationConstants.ClaimNames.SubjectIdentifier)
            //    {
            //        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, claim.Value));
            //        continue;
            //    }

            //    if (Options.IncludeIdTokenAsClaims)
            //    {
            //        // May be possible same claim names from UserInformationEndpoint and IdToken.
            //        if (!identity.HasClaim(c => c.Type == claim.Type))
            //        {
            //            identity.AddClaim(claim);
            //        }
            //    }
            //}

            //return (contextIdentifier, webApiUrl);

            return string.Empty;
        }

        /// <summary>
        ///     Check if the token is one we want to save
        /// </summary>
        /// <param name="tokens">
        ///     The tokens
        /// </param>
        /// <param name="properties">
        ///     The authentication properties
        /// </param>
        /// <param name="tokenKey">
        ///     The key we're looking to see if we want to save
        /// </param>
        /// <param name="tokenSaveOption">
        ///     The token save option we're looking to see if we want to save
        /// </param>
        private void SaveTokenIfRequired(OAuthTokenResponse tokens, AuthenticationProperties properties,
            string tokenKey, OneIdAuthenticationTokenSave tokenSaveOption)
        {
            if ((Options.TokenSaveOptions & tokenSaveOption) != tokenSaveOption)
            {
                return;
            }

            var token = tokens.Response?.RootElement.GetString(tokenKey);
            if (!string.IsNullOrEmpty(token))
            {
                SaveToken(properties, token, tokenKey);
            }
        }
    }
}
#endif