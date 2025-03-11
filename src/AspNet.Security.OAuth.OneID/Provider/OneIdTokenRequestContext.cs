#region License, Terms and Conditions

//
// OneIdTokenRequestContext.cs
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

#if NETFULL
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace AspNet.Security.OAuth.OneID.Provider
{
    public class OneIdTokenRequestContext : BaseContext
    {
        #region Constructors and Destructors

        /// <summary>Initializes a new instance of the <see cref="OneIdTokenRequestContext"/> class.</summary>
        /// <param name="context">The context.</param>
        /// <param name="options">The options.</param>
        /// <param name="state">The state.</param>
        /// <param name="code">The code.</param>
        /// <param name="properties">The properties</param>
        public OneIdTokenRequestContext(IOwinContext context, OneIdAuthenticationOptions options, string state, string? code, AuthenticationProperties properties)
            : base(context)
        {
            Context = context;
            Options = options;
            State = state;
            Code = code;
            Properties = properties;
        }

        #endregion Constructors and Destructors

        #region Public Properties

        /// <summary>Gets or sets the code.</summary>
        public string? Code { get; set; }

        /// <summary>
        ///     Gets or sets the context.
        /// </summary>
        public IOwinContext Context { get; set; }

        /// <summary>
        ///     Gets or sets the options.
        /// </summary>
        public OneIdAuthenticationOptions Options { get; set; }

        /// <summary>Gets or sets the properties.</summary>
        public AuthenticationProperties Properties { get; set; }

        /// <summary>Gets or sets the state.</summary>
        public string State { get; set; }

        #endregion Public Properties
    }
}
#endif