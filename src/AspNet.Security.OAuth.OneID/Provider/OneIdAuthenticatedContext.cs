#region License, Terms and Conditions

//
// OneIdAutenticatedContext.cs
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

using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Claims;
using System.Globalization;
using System;
using System.Collections.Generic;

#if NETFULL
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
#elif NETCORE

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using System.Text.Json;

#endif

namespace AspNet.Security.OAuth.OneID.Provider
{
    /// <summary>
    /// The OneId authenticated context
    /// </summary>
    public sealed class OneIdAuthenticatedContext :
#if NETCORE
        OAuthCreatingTicketContext
#else
BaseContext
#endif
    {
#if NETCORE

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="principal">The principal</param>
        /// <param name="properties">The properties</param>
        /// <param name="context">The context</param>
        /// <param name="scheme">The authentication scheme, ie. OneId</param>
        /// <param name="options">The options</param>
        /// <param name="backchannel">The backchannel</param>
        /// <param name="tokens">The tokens</param>
        /// <param name="user">The user data from the id token</param>
        public OneIdAuthenticatedContext(ClaimsPrincipal principal, AuthenticationProperties properties, HttpContext context, AuthenticationScheme scheme, OAuthOptions options, HttpClient backchannel, OAuthTokenResponse tokens, JsonElement user) : base(principal, properties, context, scheme, options, backchannel, tokens, user)
        {
#if NETCORE
            ArgumentNullException.ThrowIfNull(options);

            ArgumentNullException.ThrowIfNull(tokens);
#else
if (options is null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (tokens is null)
            {
                throw new ArgumentNullException(nameof(tokens));
            }
#endif

            Context = context;
            Principal = principal;
            Properties = properties;

            ParsedResponse = user.ToObject<TokenEndpoint>();

            if (options.SaveTokens)
            {
                var authTokens = new List<AuthenticationToken>();

                if ((((OneIdAuthenticationOptions)options).TokenSaveOptions & OneIdAuthenticationTokenSave.AccessToken) == OneIdAuthenticationTokenSave.AccessToken && !string.IsNullOrEmpty(tokens.AccessToken))
                {
                    authTokens.Add(new AuthenticationToken() { Name = "access_token", Value = tokens.AccessToken });
                }

                if ((((OneIdAuthenticationOptions)options).TokenSaveOptions & OneIdAuthenticationTokenSave.RefreshToken) == OneIdAuthenticationTokenSave.RefreshToken && !string.IsNullOrEmpty(tokens.RefreshToken))
                {
                    authTokens.Add(new AuthenticationToken() { Name = "refresh_token", Value = tokens.RefreshToken });
                }

                if (!string.IsNullOrEmpty(tokens.TokenType))
                {
                    authTokens.Add(new AuthenticationToken() { Name = "token_type", Value = tokens.TokenType });
                }

                if (!string.IsNullOrEmpty(tokens.ExpiresIn) && int.TryParse(tokens.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out int value))
                {
                    // https://www.w3.org/TR/xmlschema-2/#dateTime
                    // https://msdn.microsoft.com/en-us/library/az4se3k1(v=vs.110).aspx
                    var expiresAt = DateTime.UtcNow + TimeSpan.FromSeconds(value);

                    authTokens.Add(new AuthenticationToken()
                    {
                        Name = "expires_at",
                        Value = expiresAt.ToString("o", CultureInfo.InvariantCulture),
                    });
                }

                Properties.StoreTokens(authTokens);
            }

            Email = user.GetString("email");
            Id = user.GetString("sub");
            GivenName = user.GetString("given_name");
            FamilyName = user.GetString("family_name");
            PhoneNumber = user.GetString("phoneNumber");
        }

        /// <summary>
        /// The http context
        /// </summary>
        public HttpContext Context { get; }

#endif

#if NETFULL
        public OneIdAuthenticatedContext(IOwinContext context, TokenEndpoint response, JwtPayload user, string accessToken, string idToken, string refreshToken)
            : base(context)
        {
            if (user is null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            Context = context;
            ParsedResponse = response;

            AccessToken = accessToken;
            IdentityToken = idToken;
            RefreshToken = refreshToken;

            user.TryGetValue("email", out var email);
            Email = email.ToString();

            user.TryGetValue("sub", out var id);
            Id = id.ToString();

            user.TryGetValue("given_name", out var givenName);
            GivenName = givenName.ToString();

            user.TryGetValue("family_name", out var familyName);
            FamilyName = familyName.ToString();

            user.TryGetValue("phoneNumber", out var phoneNumber);
            PhoneNumber = phoneNumber.ToString();
        }

        public IOwinContext Context { get; }

        public ClaimsIdentity? Identity { get; set; }
        public AuthenticationProperties? Properties { get; set; }
        /// <summary>
        /// Gets the refresh token.
        /// </summary>
        public string RefreshToken { get; }

        /// <summary>
        /// Gets the access token
        /// </summary>
        public string AccessToken { get; }
#endif

        /// <summary>
        /// The parsed response
        /// </summary>
        public TokenEndpoint? ParsedResponse { get; }

        /// <summary>
        /// Gets the identity token.
        /// </summary>
        public string? IdentityToken { get; }

        /// <summary>
        /// First name
        /// </summary>
        public string? GivenName { get; }

        /// <summary>
        /// Last name
        /// </summary>
        public string? FamilyName { get; }


        /// <summary>
        /// Username
        /// </summary>
        public string? UserName { get; }

        /// <summary>
        /// User identifier
        /// </summary>
        public string? Id { get; }

        /// <summary>
        /// User email address
        /// </summary>
        public string? Email { get; }

        /// <summary>
        /// Phone number
        /// </summary>
        public string? PhoneNumber { get; }
    }
}