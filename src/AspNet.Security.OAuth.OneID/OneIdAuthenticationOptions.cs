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
using System.Security.Cryptography.X509Certificates;
using System.Collections.ObjectModel;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

#if NET8_0_OR_GREATER
using Microsoft.IdentityModel.Protocols;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

#elif !NETCORE

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
#if NET8_0_OR_GREATER
        OAuthOptions
#elif !NETCORE
        AuthenticationOptions
#endif
    {
        private OneIdAuthenticationEnvironment _environment = OneIdAuthenticationEnvironment.PartnerSelfTest;
        private string _authority = string.Empty;
        private OneIdAuthenticationServiceProfiles _serviceProfileOptions = OneIdAuthenticationDefaults.ServiceProfiles;
        private string _audience = string.Empty;

        /// <summary>
        /// Constructor
        /// </summary>
        public OneIdAuthenticationOptions()
#if !NETCORE
             : base(OneIdAuthenticationDefaults.DisplayName)
#endif
        {
#if NET8_0_OR_GREATER
            Environment = OneIdAuthenticationDefaults.Environment;
            ClaimsIssuer = OneIdAuthenticationDefaults.Issuer;
            CallbackPath = CallbackPath != null ? CallbackPath : new PathString(OneIdAuthenticationDefaults.CallbackPath);
            SaveTokens = false;
            SignInScheme = IdentityConstants.ExternalScheme;
            ResponseType = OpenIdConnectResponseType.Code;
            UsePkce = true;
            BackchannelHttpHandler = new OneIdAuthenticationBackChannelHandler(this);
            CertificateStoreLocation = StoreLocation.LocalMachine;
            CertificateStoreName = StoreName.My;
            Events = new OneIdAuthenticationEvents();

            UpdateEndpoints();

            TokenValidationParameters = new TokenValidationParameters()
            {
                ValidateAudience = true,
                ValidAudience = ClientId,

                ValidateIssuer = true,
                ValidIssuer = Authority,

                ValidateLifetime = true,

                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Convert.FromBase64String("iGlWMW7KNH1FOIMRSUluC7PPCu6K9zdQTrP1I4Cl5q0=")),

                NameClaimType = ClaimTypes.NameIdentifier,
                RoleClaimType = "groups"
            };

            // Profile, email and offline_access scopes are not supported by OneID
            Scope.Clear();
            Scope.Add("openid");

            if ((_serviceProfileOptions & OneIdAuthenticationServiceProfiles.OLIS) == OneIdAuthenticationServiceProfiles.OLIS)
            {
                Scope.Add(ScopeNames.DiagnosticReport);
            }

            if ((_serviceProfileOptions & OneIdAuthenticationServiceProfiles.DHDR) == OneIdAuthenticationServiceProfiles.DHDR)
            {
                Scope.Add(ScopeNames.MedicationDispense);
            }

            ClaimActions.MapJsonKey(ClaimTypes.Email, "email");
            ClaimActions.MapJsonKey(ClaimTypes.GivenName, "given_name");
            ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "sub");
            ClaimActions.MapJsonKey(ClaimTypes.Surname, "family_name");
            ClaimActions.MapJsonKey(ClaimTypes.Actor, "username");

            // Add a custom claim action that maps the email claim from the ID token if
            // it was not otherwise provided in the user endpoint response.
            ClaimActions.Add(new OneIdAuthenticationClaimAction(this));

#elif !NETCORE
            AuthenticationType = OneIdAuthenticationDefaults.DisplayName;
            Caption = OneIdAuthenticationDefaults.DisplayName;
            AuthenticationMode = AuthenticationMode.Passive;
            CallbackPath = new PathString(OneIdAuthenticationDefaults.CallbackPath);
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            ResponseType = "code";

            Scope = new List<string>
            {
                "openid"
            };

            ServiceProfileOptions = OneIdAuthenticationDefaults.ServiceProfiles;

            if ((ServiceProfileOptions & OneIdAuthenticationServiceProfiles.OLIS) == OneIdAuthenticationServiceProfiles.OLIS)
            {
                Scope.Add(ScopeNames.DiagnosticReport);
            }

            if ((ServiceProfileOptions & OneIdAuthenticationServiceProfiles.DHDR) == OneIdAuthenticationServiceProfiles.DHDR)
            {
                Scope.Add(ScopeNames.MedicationDispense);
            }
#endif

            TokenSaveOptions = OneIdAuthenticationDefaults.TokenSave;

            UpdateEndpoints();
        }

        /// <summary>
        ///     Gets or sets additional values set in this property will be appended to the authorization request.
        /// </summary>
        public Dictionary<string, string> AdditionalParameters { get; } = new();

        /// <summary>
        /// For the purposes of removing subdomains from the request and restoring them for the redirect once complete
        /// Add second and third level TLDs that might be expected (ie. (host).uk is 1st, (host).co.uk is a 2nd, (host).k12.ma.us is a third)
        /// </summary>
        public ReadOnlyCollection<string>? Tlds { get; set; }

        /// <summary>
        /// Authority, which depends on the environment
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1863:Use 'CompositeFormat'", Justification = "<Pending>")]
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
        /// Gets or sets the security token validator to use.
        /// </summary>
        public JsonWebTokenHandler? SecurityTokenHandler { get; set; }

        /// <summary>
        /// When SaveTokens is true, this let's you specify which tokens get persisted non-session (ie. cookie)
        /// </summary>
        public OneIdAuthenticationTokenSave TokenSaveOptions { get; set; }

        /// <summary>
        /// None is specified as default an so will not work
        /// </summary>
        public OneIdAuthenticationServiceProfiles ServiceProfileOptions
        {
            get => _serviceProfileOptions;
            set
            {
                _serviceProfileOptions = value;

                if (!Scope.Contains("openid")) Scope.Add("openid");

                if ((_serviceProfileOptions & OneIdAuthenticationServiceProfiles.OLIS) == OneIdAuthenticationServiceProfiles.OLIS)
                {
                    Scope.Add(ScopeNames.DiagnosticReport);
                }

                if ((_serviceProfileOptions & OneIdAuthenticationServiceProfiles.DHDR) == OneIdAuthenticationServiceProfiles.DHDR)
                {
                    Scope.Add(ScopeNames.MedicationDispense);
                }
            }
        }

        public string GetServiceProfileOptionsString()
        {
            var retVal = string.Empty;

            if ((_serviceProfileOptions & OneIdAuthenticationServiceProfiles.OLIS) == OneIdAuthenticationServiceProfiles.OLIS)
            {
                retVal += ProfileNames.DiagnosticSearchProfile;
            }

            if ((_serviceProfileOptions & OneIdAuthenticationServiceProfiles.DHDR) == OneIdAuthenticationServiceProfiles.DHDR)
            {
                retVal += $"{(string.IsNullOrEmpty(retVal) ? string.Empty : " ")}{ProfileNames.MedicationSearchProfile}";
            }

            return retVal;
        }

        /// <summary>
        /// The thumbprint of the PKI certificate pre-configured with eHealth Ontario
        /// </summary>
        public string? CertificateThumbprint { get; set; }

        public StoreLocation CertificateStoreLocation { get; set; }
        public StoreName CertificateStoreName { get; set; }

        /// <summary>
        /// Certificate filename, if not using thumbprint
        /// </summary>
        public string? CertificateFilename { get; set; }

        /// <summary>
        /// Certificate password, if not using thumbprint
        /// </summary>
        public SecureString? CertificatePassword { get; set; }

        /// <summary>
        /// Response type
        /// </summary>
        public string ResponseType { get; }

        /// <summary>
        /// Validate tokens?
        /// </summary>
        public bool ValidateTokens { get; set; } = true;

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
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1863:Use 'CompositeFormat'", Justification = "<Pending>")]
        public string Audience
        {
            get
            {
                if (string.IsNullOrEmpty(_audience))
                {
                    var env = GetEnvironment();
                    _audience = string.Format(CultureInfo.InvariantCulture,
                       FormatStrings.Audience,
                       env);
                }

                return _audience;
            }
            set => _audience = value;
        }

        public string EndSessionEndpoint { get; private set; } = string.Empty;
        public string MetadataEndpoint { get; private set; } = string.Empty;

#if !NETCORE
        public string AuthorizationEndpoint { get; private set; } = string.Empty;
        public string TokenEndpoint { get; private set; } = string.Empty;
        public string ClaimsIssuer { get; private set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string ClientSecret { get; set; } = string.Empty;

        public ISecureDataFormat<AuthenticationProperties>? StateDataFormat { get; set; }
        public IOneIdAuthenticationProvider Provider { get; set; } = new OneIdAuthenticationProvider();

        public string SignInAsAuthenticationType { get; set; } = string.Empty;
        public IList<string> Scope { get; }
        public PathString CallbackPath { get; set; }

        /// <summary>
        /// Gets or sets the HttpMessageHandler used to communicate with OneId.
        /// This cannot be set at the same time as BackchannelCertificateValidator unless the value
        /// can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler? BackchannelHttpHandler { get; set; }

        /// <summary>Gets or sets the authentication handler.</summary>
        public IOneIdAuthenticationHandlerFactory? AuthenticationHandlerFactory { get; set; }

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

#else
        /// <summary>
        /// UserInformationEndpoint, which depends on the environment
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1863:Use 'CompositeFormat'", Justification = "<Pending>")]
        public string UserInfo
        {
            get
            {
                if (string.IsNullOrEmpty(UserInformationEndpoint))
                {
                    var env = GetEnvironment();
                    UserInformationEndpoint = string.Format(CultureInfo.InvariantCulture,
                       FormatStrings.UserInfoEndpoint,
                       env);
                }

                return UserInformationEndpoint;
            }
            set => UserInformationEndpoint = value;
        }

        /// <summary>
        /// Gets or sets the <see cref="OneIdAuthenticationEvents"/> used to handle authentication events.
        /// </summary>
        public new OneIdAuthenticationEvents Events
        {
            get => (OneIdAuthenticationEvents)base.Events;
            set => base.Events = value;
        }

        /// <summary>
        /// Gets or sets the configuration manager responsible for retrieving, caching, and refreshing the
        /// OpenId configuration from metadata. If not provided, then one will be created using the <see cref="MetadataEndpoint"/>
        /// and <see cref="RemoteAuthenticationOptions.Backchannel"/> properties.
        /// </summary>
        public IConfigurationManager<OpenIdConnectConfiguration>? ConfigurationManager { get; set; }

        /// <summary>
        /// Gets or sets the parameters used to validate identity tokens.
        /// </summary>
        /// <remarks>Contains the types and definitions required for validating a token.</remarks>
        public TokenValidationParameters TokenValidationParameters { get; }

        /// <summary>
        /// Gets or sets the <see cref="IOneIdTokenValidator"/> to use.
        /// </summary>
        public IOneIdTokenValidator? TokenValidator { get; set; }

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

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1863:Use 'CompositeFormat'", Justification = "<Pending>")]
        private void UpdateEndpoints()
        {
            string env = GetEnvironment();
            
            Audience = string.Format(CultureInfo.InvariantCulture, FormatStrings.Audience, env);
            Authority = string.Format(CultureInfo.InvariantCulture, FormatStrings.Authority, env);

            AuthorizationEndpoint = string.Format(CultureInfo.InvariantCulture,
               FormatStrings.AuthorizeEndpoint,
               env);

            TokenEndpoint = string.Format(CultureInfo.InvariantCulture,
                FormatStrings.TokenEndpoint,
                env);

            ClaimsIssuer = string.Format(CultureInfo.InvariantCulture,
                FormatStrings.ClaimsIssuer,
                env);

            EndSessionEndpoint = string.Format(CultureInfo.InvariantCulture,
                FormatStrings.EndSessionEndpoint,
                env);

            MetadataEndpoint = string.Format(CultureInfo.InvariantCulture,
               FormatStrings.MetadataEndpoint,
               env);
#if NET8_0_OR_GREATER
            UserInformationEndpoint = string.Format(CultureInfo.InvariantCulture,
               FormatStrings.UserInfoEndpoint,
               env);
#endif

            if (_environment == OneIdAuthenticationEnvironment.Production)
            {
                // unlike all other environments, prod simply removes the domain
                // ie. you won't see login.prod.oneidfederation.ehealthontario.ca, just login.oneidfederation.ehealthontario.ca
#if NET8_0_OR_GREATER
                AuthorizationEndpoint = AuthorizationEndpoint.Replace(".prod", string.Empty, StringComparison.InvariantCulture);
                TokenEndpoint = TokenEndpoint.Replace(".prod", string.Empty, StringComparison.InvariantCulture);
                ClaimsIssuer = ClaimsIssuer.Replace(".prod", string.Empty, StringComparison.InvariantCulture);
                Audience = Audience.Replace(".prod", string.Empty, StringComparison.InvariantCulture).Replace("idaasprodoidc", "idaasoidc", StringComparison.InvariantCultureIgnoreCase); // Special case
                EndSessionEndpoint = EndSessionEndpoint.Replace(".prod", string.Empty, StringComparison.InvariantCulture);
                MetadataEndpoint = MetadataEndpoint.Replace(".prod", string.Empty, StringComparison.InvariantCulture);
                UserInfo = UserInfo.Replace(".prod", string.Empty, StringComparison.InvariantCulture).Replace("idaasprodoidc", "idaasoidc", StringComparison.InvariantCultureIgnoreCase); // Special case
#else
                AuthorizationEndpoint = AuthorizationEndpoint.Replace(".prod", string.Empty);
                TokenEndpoint = TokenEndpoint.Replace(".prod", string.Empty);
                ClaimsIssuer = ClaimsIssuer.Replace(".prod", string.Empty);
                Audience = Audience.Replace(".prod", string.Empty).Replace("idaasprodoidc", "idaasoidc"); // Special case
                EndSessionEndpoint = EndSessionEndpoint.Replace(".prod", string.Empty);
                MetadataEndpoint = MetadataEndpoint.Replace(".prod", string.Empty);
#endif
            }
        }

#if NET8_0_OR_GREATER

        /// <inheritdoc/>
        public override void Validate()
        {
            var old = ClientSecret;
            // base.Validate is checking to see that ClientSecret isn't empty. Ron Popeil this (set and then forget).
            if (string.IsNullOrEmpty(old)) ClientSecret = Guid.NewGuid().ToString();
            base.Validate();
            ClientSecret = old;

            if (_environment == OneIdAuthenticationEnvironment.Production
            && !AuthorizationEndpoint.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                throw new NotSupportedException("Production environment requires secure endpoints, i.e. begins with 'https://'.");
            }

            if (string.IsNullOrEmpty(AuthorizationEndpoint))
            {
                throw new InvalidOperationException($"The '{nameof(AuthorizationEndpoint)}' option must be provided.");
            }

            if (string.IsNullOrEmpty(TokenEndpoint))
            {
                throw new InvalidOperationException($"The '{nameof(TokenEndpoint)}' option must be provided.");
            }

            if (!ServiceProfileOptions.HasFlag(OneIdAuthenticationServiceProfiles.OLIS) && !ServiceProfileOptions.HasFlag(OneIdAuthenticationServiceProfiles.DHDR))
            {
                throw new InvalidOperationException($"A '{nameof(ServiceProfileOptions)}' option must be provided.");
            }

            if (!TokenSaveOptions.HasFlag(OneIdAuthenticationTokenSave.AccessToken)
                && !TokenSaveOptions.HasFlag(OneIdAuthenticationTokenSave.RefreshToken)
                && !TokenSaveOptions.HasFlag(OneIdAuthenticationTokenSave.IdToken))
            {
                throw new InvalidOperationException($"A '{nameof(TokenSaveOptions)}' option must be provided because they must be accessed in session.");
            }

            if (_environment != OneIdAuthenticationEnvironment.Production &&
                string.IsNullOrEmpty(ClientSecret))
            {
                throw new InvalidOperationException($"The '{nameof(ClientSecret)}' option must be provided within this environment.");
            }

            if (!CallbackPath.HasValue)
            {
                throw new InvalidOperationException($"The '{nameof(CallbackPath)}' option must be provided.");
            }

            if (ConfigurationManager == null)
            {
                throw new InvalidOperationException($"Provide {nameof(Authority)}, {nameof(MetadataEndpoint)}, or {nameof(ConfigurationManager)} to {nameof(OneIdAuthenticationOptions)}.");
            }
        }

#endif
    }
}