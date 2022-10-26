#region License, Terms and Conditions

//
// OneIdAuthenticationDefaults.cs
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

namespace AspNet.Security.OAuth.OneID
{
    /// <summary>
    /// The Supported (by this library) Ontario Health (OH) Clinical Data Repositories
    /// </summary>
    [Flags]
    public enum OneIdAuthenticationServiceProfiles
    {
        None = 0,

        /// <summary>
        /// Ontario Laboratories Information System
        /// </summary>
        /// <seealso href="https://ehealthontario.on.ca/en/standards/ontario-laboratories-information-system-standard"/>
        OLIS = 1,

        /// <summary>
        /// Digital Health Drug Repository
        /// </summary>
        /// <seealso href="https://ehealthontario.on.ca/en/standards/digital-health-drug-repository-specification-fhir-release-3"/>
        DHDR = 2
    }

    /// <summary>
    /// Which tokens you would like saved, regardless of the location (cookies, session)
    /// </summary>
    [Flags]
    public enum OneIdAuthenticationTokenSave
    {
        None = 0,
        IdToken = 1,
        RefreshToken = 2,
        AccessToken = 4
    }

    /// <summary>
    /// Default values used by the OneId authentication middleware
    /// </summary>
    public static class OneIdAuthenticationDefaults
    {
        /// <summary>
        /// Default value for AuthenticationScheme Name
        /// </summary>
        public const string AuthenticationScheme = "OneID";

        /// <summary>
        /// Default value for CallbackPath
        /// </summary>
        public const string CallbackPath = "/signin-oneid";

        /// <summary>
        /// Default value DisplayName
        /// </summary>
        public const string DisplayName = "OneID";

        /// <summary>
        /// The default envionrment
        /// </summary>
        public const OneIdAuthenticationEnvironment Environment = OneIdAuthenticationEnvironment.Development;

        /// <summary>
        /// Default value for ClaimsIssuer
        /// </summary>
        public const string Issuer = "OneID";

        /// <summary>
        /// Since there's no way to tell what service you might be using this with, none is the default
        /// You must pick one before you can get a token.
        /// </summary>
        public const OneIdAuthenticationServiceProfiles ServiceProfiles = OneIdAuthenticationServiceProfiles.None;

        /// <summary>
        /// Don't store the access_token in cookie by default, because it's VERY large
        /// </summary>
        public const OneIdAuthenticationTokenSave TokenSave = OneIdAuthenticationTokenSave.IdToken | OneIdAuthenticationTokenSave.RefreshToken;

        private static string? _userAgent;

        /// <summary>
        /// The user agent
        /// </summary>
        public static string UserAgent => _userAgent ??= $"OneId Authentication Middleware v{System.Reflection.Assembly.GetExecutingAssembly().GetName().Version}";
    }
}