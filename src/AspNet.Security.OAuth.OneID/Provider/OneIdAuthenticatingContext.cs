#region License, Terms and Conditions

//
// OneIdAutenticatingContext.cs
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
using Microsoft.Owin.Security.Provider;

namespace AspNet.Security.OAuth.OneID.Provider
{
    /// <summary>
    /// The OneId authenticating context.
    /// </summary>
    public sealed class OneIdAuthenticatingContext : BaseContext
    {
        #region Constructors and Destructors

        /// <summary>
        /// Initializes a new instance of the <see cref="OneIdAuthenticatingContext"/> class.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="options">The options.</param>
        public OneIdAuthenticatingContext(IOwinContext context, OneIdAuthenticationOptions options)
            : base(context)
        {
            Context = context;
            Options = options;
        }

        #endregion Constructors and Destructors

        #region Public Properties

        /// <summary>
        ///     Gets or sets the context.
        /// </summary>
        public IOwinContext Context { get; set; }

        /// <summary>
        ///     Gets or sets the options.
        /// </summary>
        public OneIdAuthenticationOptions Options { get; set; }

        #endregion Public Properties
    }
}
#endif