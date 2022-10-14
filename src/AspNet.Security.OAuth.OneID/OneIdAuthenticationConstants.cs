#region License, Terms and Conditions

//
// OneIdAuthenticationConstants.cs
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
using System.Resources;

[assembly: NeutralResourcesLanguage("en")]

namespace AspNet.Security.OAuth.OneID
{
    /// <summary>
    /// Contains constants specific to the <see cref="OneIdAuthenticationHandler"/>.
    /// </summary>
    public static class OneIdAuthenticationConstants
    {
        /// <summary>
        /// Constants related to oAuth/OIDC
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "<Pending>")]
        public static class OAuth2Constants
        {
            /// <summary>
            /// The access token
            /// </summary>
            public const string AccessToken = "access_token";

            /// <summary>
            /// The client assertion
            /// </summary>
            public const string Assertion = "client_assertion";

            /// <summary>
            /// The client id
            /// </summary>
            public const string ClientId = "client_id";

            /// <summary>
            /// The PKCE code
            /// </summary>
            public const string Code = "code";

            /// <summary>
            /// The PKCE code verifier
            /// </summary>
            public const string CodeVerifier = "code_verifier";

            /// <summary>
            /// The oauth grant type
            /// </summary>
            public const string GrantType = "grant_type";

            /// <summary>
            /// The authorization code
            /// </summary>
            public const string AuthorizationCode = "authorization_code";

            /// <summary>
            /// The identity token
            /// </summary>
            public const string IdentityToken = "id_token";

            /// <summary>
            /// The nonce
            /// </summary>
            public const string Nonce = "nonce";

            /// <summary>
            /// The code challenge
            /// </summary>
            public const string CodeChallenge = "code_challenge";

            /// <summary>
            /// The code challenge method
            /// </summary>
            public const string CodeChallengeMethod = "code_challenge_method";

            /// <summary>
            /// The audience
            /// </summary>
            public const string Audience = "aud";

            /// <summary>
            /// The profile
            /// </summary>
            public const string Profile = "_profile";

            /// <summary>
            /// The redirect uri
            /// </summary>
            public const string RedirectUri = "redirect_uri";

            /// <summary>
            /// The refresh token
            /// </summary>
            public const string RefreshToken = "refresh_token";

            /// <summary>
            /// The response type
            /// </summary>
            public const string ResponseType = "response_type";

            /// <summary>
            /// The scope
            /// </summary>
            public const string Scope = "scope";

            /// <summary>
            /// The state
            /// </summary>
            public const string State = "state";
        }

        /// <summary>
        /// Profile names
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "<Pending>")]
        public static class ProfileNames
        {
            /// <summary>
            /// The diagnostic search profile name
            /// </summary>
            public const string DiagnosticSearchProfile = "http://ehealthontario.ca/StructureDefinition/ca-on-lab-profile-DiagnosticReport";
            public const string MedicationSearchProfile = "http://ehealthontario.ca/StructureDefinition/ca-on-dhdr-profile-MedicationDispense";
        }

        /// <summary>
        /// oAuth2/OIDC claim names
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "<Pending>")]
        public static class ClaimNames
        {
            /// <summary>
            /// The JWT bearer assertion
            /// </summary>
            public const string JwtBearerAssertion = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

            /// <summary>
            /// The api audience
            /// </summary>
            public const string ApiAudience = "https://provider.ehealthontario.ca";
        }

        /// <summary>
        /// Scope names
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "<Pending>")]
        public static class ScopeNames
        {
            /// <summary>
            /// Name of the DiagnosticReport scope
            /// </summary>
            public const string DiagnosticReport = "user/DiagnosticReport.read";
            public const string MedicationDispense = "user/MedicationDispense.read";
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "<Pending>")]
        public static class FormatStrings
        {
            /// <summary>
            /// A format string used to construct <see cref="OneIdAuthenticationOptions.Authority"/>.
            /// </summary>
            public const string Authority = "https://login.{0}.oneidfederation.ehealthontario.ca";

            /// <summary>
            /// A format string used to populate OAuth authorize endpoint.
            /// </summary>
            public const string AuthorizeEndpoint = "https://login.{0}.oneidfederation.ehealthontario.ca/oidc/authorize";

            /// <summary>
            /// A format string used to populate OAuth end session endpoint.
            /// </summary>
            public const string EndSessionEndpoint = "https://login.{0}.oneidfederation.ehealthontario.ca/oidc/logout";

            /// <summary>
            /// A format string used to construct the claims issuer
            /// </summary>
            public const string ClaimsIssuer = "login.{0}.oneidfederation.ehealthontario.ca";

            /// <summary>
            /// A format string used to populate OAuth token endpoint.
            /// </summary>
            public const string TokenEndpoint = "https://login.{0}.oneidfederation.ehealthontario.ca/oidc/access_token";

            /// <summary>
            /// The audience
            /// </summary>
            public const string Audience = "https://login.{0}.oneidfederation.ehealthontario.ca/sso/oauth2/realms/root/realms/idaas{0}oidc/access_token";
        }
    }
}