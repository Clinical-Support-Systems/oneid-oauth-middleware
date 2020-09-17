#region License, Terms and Conditions

//
// OneIdValidateIdTokenContext.cs
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

#if NETCORE

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OAuth.OneID
{
    /// <summary>
    /// Contains information about the ID token to validate.
    /// </summary>
    public class OneIdValidateIdTokenContext : BaseContext<OneIdAuthenticationOptions>
    {
        /// <summary>
        /// Creates a new instance of the <see cref="OneIdValidateIdTokenContext"/> class.
        /// </summary>
        /// <param name="context">The HTTP context.</param>
        /// <param name="scheme">The authentication scheme.</param>
        /// <param name="options">The authentication options associated with the scheme.</param>
        /// <param name="idToken">The OneID ID token for the user to validate.</param>
        public OneIdValidateIdTokenContext(HttpContext context, AuthenticationScheme scheme, OneIdAuthenticationOptions options, string idToken)
            : base(context, scheme, options)
        {
            IdToken = idToken;
        }

        /// <summary>
        /// Gets the Apple ID token.
        /// </summary>
        public string IdToken { get; }
    }
}

#endif