#region License, Terms and Conditions

//
// OneIdAuthenticationOptions.cs
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
using System.Globalization;
using System.Security;
using static AspNet.Security.OAuth.OneID.OneIdAuthenticationConstants;
using System.Collections.Generic;
using System.Net.Http;

#if NETCORE

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

#elif NETFULL

using Microsoft.Owin;
using Microsoft.Owin.Security;
using AspNet.Security.OAuth.OneID.Provider;

#endif

namespace AspNet.Security.OAuth.OneID
{
    /// <summary>
    /// Defines a set of options used by <see cref="OneIdAuthenticationHandler"/>.
    /// </summary>
    public class OneIdAuthenticationOptions :
#if NETCORE
        OAuthOptions
#elif NETFULL
        AuthenticationOptions
#endif
    {
        private OneIdAuthenticationEnvironment _environment;
        private string _authority;

        /// <summary>
        /// Constructor
        /// </summary>
        public OneIdAuthenticationOptions()
#if NETFULL
             : base(OneIdAuthenticationDefaults.DisplayName)
#endif
        {
#if NETCORE
            Environment = OneIdAuthenticationDefaults.Environment;
            ClaimsIssuer = OneIdAuthenticationDefaults.Issuer;
            CallbackPath = CallbackPath != null ? CallbackPath : new PathString(OneIdAuthenticationDefaults.CallbackPath);
            SaveTokens = false;
            SignInScheme = IdentityConstants.ExternalScheme;
            ResponseType = OpenIdConnectResponseType.Code;
            GetClaimsFromUserInfoEndpoint = false;
            UsePkce = true;
            BackchannelHttpHandler = new OneIdAuthenticationBackChannelHandler(this);
            TokenValidationParameters = new TokenValidationParameters()
            {
                ValidateAudience = true,
                ValidAudience = ClientId,

                ValidateIssuer = false,
                ValidIssuers = new[] { Authority },
                IssuerSigningKeyValidator = (sk, st, tvp) =>
                {
                    return true;
                },

                NameClaimType = "name",
                RoleClaimType = "groups",

                SignatureValidator = (token, validationParameters) =>
                {
                    validationParameters.RequireSignedTokens = false;
                    var tokenHandler = new JwtSecurityTokenHandler();
                    return tokenHandler.ReadToken(token);
                },

                RequireExpirationTime = true,
                ValidateLifetime = true,
                RequireSignedTokens = true,
            };

            Scope.Clear();
            Scope.Add("openid");
            Scope.Add(ScopeNames.DiagnosticReport);

            ClaimActions.MapJsonKey(ClaimTypes.Email, "email");
            ClaimActions.MapJsonKey(ClaimTypes.GivenName, "given_name");
            ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "sub");
            ClaimActions.MapJsonKey(ClaimTypes.Surname, "family_name");

#elif NETFULL
            AuthenticationType = OneIdAuthenticationDefaults.DisplayName;
            Caption = OneIdAuthenticationDefaults.DisplayName;
            AuthenticationMode = AuthenticationMode.Passive;
            CallbackPath = new PathString(OneIdAuthenticationDefaults.CallbackPath);
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            Scope = new List<string>
            {
                "openid",
                ScopeNames.DiagnosticReport
            };
#endif

            UpdateEndpoints();
        }

        /// <summary>
        ///     Gets or sets additional values set in this property will be appended to the authorization request.
        /// </summary>
        public Dictionary<string, string> AdditionalParameters { get; set; }

        /// <summary>
        /// Authority, which depends on the environment
        /// </summary>
        public string Authority
        {
            get
            {
                if (string.IsNullOrEmpty(_authority))
                {
                    var env = GetEnvironment();
                    _authority = string.Format(CultureInfo.InvariantCulture,
                       FormatStrings.Authority,
                       env);
                }

                return _authority;
            }
            set => _authority = value;
        }

        /// <summary>
        /// The thumbprint of the PKI certificate pre-configured with eHealth Ontario
        /// </summary>
        public string CertificateThumbprint { get; set; }

        /// <summary>
        /// Certificate filename, if not using thumbprint
        /// </summary>
        public string CertificateFilename { get; set; }

        /// <summary>
        /// Certificate password, if not using thumbprint
        /// </summary>
        public SecureString CertificatePassword { get; set; }

        /// <summary>
        /// Response type
        /// </summary>
        public string ResponseType { get; private set; }

        /// <summary>
        /// Get claims from the user info endpoint? no.
        /// </summary>

        public bool GetClaimsFromUserInfoEndpoint { get; private set; }

        /// <summary>
        /// Validate tokens?
        /// </summary>
        public bool ValidateTokens { get; internal set; }

        /// <summary>
        /// Token validation parameterd
        /// </summary>
        public object TokenValidationParameters { get; internal set; }

        /// <summary>
        /// Gets or sets the target online environment to either development, stage or production.
        /// The default value is <see cref="OneIdAuthenticationEnvironment.Development"/>.
        /// </summary>
        public OneIdAuthenticationEnvironment Environment
        {
            get
            {
                return _environment;
            }

            set
            {
                _environment = value;
                UpdateEndpoints();
            }
        }

        /// <summary>
        /// Audience
        /// </summary>
        public string Audience
        {
            get
            {
                string env = GetEnvironment();
                return string.Format(CultureInfo.InvariantCulture, FormatStrings.Audience, env);
            }
        }

#if NETFULL
        public string AuthorizationEndpoint { get; private set; }
        public string TokenEndpoint { get; private set; }
        public string ClaimsIssuer { get; private set; }

        public string ClientId { get; set; }

        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
        public IOneIdAuthenticationProvider Provider { get; set; }

        public string SignInAsAuthenticationType { get; set; }
        public IList<string> Scope { get; }
        public PathString CallbackPath { get; set; }

        /// <summary>
        /// Gets or sets the HttpMessageHandler used to communicate with OneId.
        /// This cannot be set at the same time as BackchannelCertificateValidator unless the value
        /// can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>Gets or sets the authentication handler.</summary>
        public IOneIdAuthenticationHandlerFactory AuthenticationHandlerFactory { get; set; }

        /// <summary>
        /// Gets or sets timeout value in milliseconds for back channel communications with OneId.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        /// Get or sets the text that the user can display on a sign in user interface.
        /// </summary>
        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }
#endif

        /// <summary>
        /// Used to determine current target environment.
        /// </summary>
        /// <returns>Returns the online environment, i.e. development, stage, production.</returns>
        private string GetEnvironment()
        {
            return _environment switch
            {
                OneIdAuthenticationEnvironment.Development => "dev",
                OneIdAuthenticationEnvironment.QualityAssurance => "qa",
                OneIdAuthenticationEnvironment.PartnerSelfTest => "pst",
                OneIdAuthenticationEnvironment.Production => "prod",
                _ => throw new NotSupportedException("Environment property must be set to either Development, QualityAssurance, PartnerSelfTest or Production.")
            };
        }

        private void UpdateEndpoints()
        {
            string env = GetEnvironment();

            AuthorizationEndpoint = string.Format(CultureInfo.InvariantCulture,
               FormatStrings.AuthorizeEndpoint,
               env);

            TokenEndpoint = string.Format(CultureInfo.InvariantCulture,
                FormatStrings.TokenEndpoint,
                env);

            ClaimsIssuer = string.Format(CultureInfo.InvariantCulture,
                FormatStrings.ClaimsIssuer,
                env);

            if (_environment == OneIdAuthenticationEnvironment.Production)
            {
                // unlike all other environments, prod simply removes the domain
                // ie. you won't see login.prod.oneidfederation.ehealthontario.ca, just login.oneidfederation.ehealthontario.ca
                AuthorizationEndpoint = AuthorizationEndpoint.Replace(".prod", string.Empty);
                TokenEndpoint = TokenEndpoint.Replace(".prod", string.Empty);
                ClaimsIssuer = ClaimsIssuer.Replace(".prod", string.Empty);
            }
        }

#if NETCORE

        /// <inheritdoc/>
        public override void Validate()
        {
            ClientSecret = Guid.NewGuid().ToString(); // HACK, base.Validate is checking to see thast ClientSecret isn't empty. Ron Popeil this (set and then forget).
            base.Validate();
            ClientSecret = null;
        }

#endif
    }
}