#region License, Terms and Conditions

//
// OneIdAuthenticationProvider.cs
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

#if !NETCORE
using AspNet.Security.OAuth.OneID.Provider;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using System;
using System.Threading.Tasks;

namespace AspNet.Security.OAuth.OneID
{
    public interface IOneIdAuthenticationProvider
    {
        /// <summary>
        /// Invoked whenever OneId successfully authenticates a user
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task Authenticated(OneIdAuthenticatedContext context);

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/>
        /// being saved in a local cookie and the browser being redirected to the
        /// originally requested URL.
        /// </summary>
        /// <param name="context">The context</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task Authenticating(OneIdAuthenticatingContext context);

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/>
        /// being saved in a local cookie and the browser being redirected to the
        /// originally requested URL.
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task ReturnEndpoint(OneIdReturnEndpointContext context);

        void ApplyRedirect(OneIdApplyRedirectContext context);

        /// <summary>
        /// Invoked prior to calling the token request endpoint on OneId.
        /// </summary>
        /// <param name="context">The context</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task TokenRequest(OneIdTokenRequestContext context);
    }

    public class OneIdAuthenticationProvider : IOneIdAuthenticationProvider
    {
        public OneIdAuthenticationProvider()
        {
            this.OnAuthenticating = context => Task.CompletedTask;
            this.OnAuthenticated = context => Task.CompletedTask;
            this.OnReturnEndpoint = context => Task.CompletedTask;
            this.OnApplyRedirect = context => context.Response.Redirect(context.RedirectUri.AbsoluteUri);
            this.OnTokenRequest = context => Task.FromResult<object?>(null);
        }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<OneIdAuthenticatingContext, Task> OnAuthenticating { get; set; }

        /// <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<OneIdAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<OneIdReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        /// <summary>Gets or sets the on token request.</summary>
        public Func<OneIdTokenRequestContext, Task> OnTokenRequest { get; set; }

        /// <summary>
        /// Gets or sets the on token request.
        /// </summary>
        public Action<OneIdApplyRedirectContext> OnApplyRedirect { get; set; }

        public virtual Task Authenticating(OneIdAuthenticatingContext context)
        {
            return this.OnAuthenticating(context);
        }

        public virtual Task Authenticated(OneIdAuthenticatedContext context)
        {
            return this.OnAuthenticated(context);
        }

        public virtual Task ReturnEndpoint(OneIdReturnEndpointContext context)
        {
            return this.OnReturnEndpoint(context);
        }

        public virtual void ApplyRedirect(OneIdApplyRedirectContext context)
        {
            this.OnApplyRedirect(context);
        }

        /// <summary>
        /// Invoked prior to calling the token request endpoint on OneId.
        /// </summary>
        /// <param name="context">The context</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task TokenRequest(OneIdTokenRequestContext context)
        {
            return this.OnTokenRequest(context);
        }
    }
}
#endif