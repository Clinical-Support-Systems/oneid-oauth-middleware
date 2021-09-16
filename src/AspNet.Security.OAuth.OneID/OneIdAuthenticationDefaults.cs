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
    /// Default values used by the OneId authentication middleware.
    /// </summary>
    public static class OneIdAuthenticationDefaults
    {
        /// <summary>
        /// The user agent
        /// </summary>
        public static string UserAgent => _userAgent ??=
                                               string.Format("OneId Authentication Middleware v" +
                                                             System.Reflection.Assembly.GetExecutingAssembly().GetName().Version);

        private static string _userAgent;

        /// <summary>
        /// Default value for AuthenticationScheme Name
        /// </summary>
        public const string AuthenticationScheme = "OneID";

        /// <summary>
        /// Default value DisplayName
        /// </summary>
        public const string DisplayName = "OneID";

        /// <summary>
        /// Default value for ClaimsIssuer
        /// </summary>
        public const string Issuer = "OneID";

        /// <summary>
        /// Default value for CallbackPath
        /// </summary>
        public const string CallbackPath = "/signin-oneid";

        /// <summary>
        /// The default envionrment
        /// </summary>
        public const OneIdAuthenticationEnvironment Environment = OneIdAuthenticationEnvironment.Development;

        /// <summary>
        /// Don't store the access_token because it's large, by default.
        /// </summary>
        public const OneIdAuthenticationTokenSave TokenSave = OneIdAuthenticationTokenSave.IdToken | OneIdAuthenticationTokenSave.RefreshToken;

        /// <summary>
        /// Since there's no way to tell what service you might be using this with, none is the default.
        /// You must pick one before you can get a token.
        /// </summary>
        public const OneIdAuthenticationServiceProfiles ServiceProfiles = OneIdAuthenticationServiceProfiles.None;
    }

    [Flags]
    public enum OneIdAuthenticationTokenSave
    {
        None = 0,
        IdToken = 1,
        RefreshToken = 2,
        AccessToken = 4
    }

    [Flags]
    public enum OneIdAuthenticationServiceProfiles
    {
        None = 0,
        OLIS = 1,
        DHDR = 2
    }
}