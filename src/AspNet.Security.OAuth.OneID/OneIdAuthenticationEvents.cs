#region License, Terms and Conditions

//
// OneIdAuthenticationEvents.cs
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

#if NET8_0_OR_GREATER
using Microsoft.AspNetCore.Authentication.OAuth;
using System;
using System.Threading.Tasks;

namespace AspNet.Security.OAuth.OneID
{
    /// <summary>
    /// Default <see cref="OneIdAuthenticationEvents"/> implementation.
    /// </summary>
    public class OneIdAuthenticationEvents : OAuthEvents
    {
        /// <summary>
        /// Delegate invoked when the <see cref="ValidateIdToken"/> method is invoked.
        /// Skips validation silently if no <see cref="IOneIdTokenValidator"/> is configured to avoid NREs in unit tests.
        /// </summary>
        private Func<OneIdValidateIdTokenContext, Task> OnValidateIdToken { get; } = context =>
        {
            ArgumentNullException.ThrowIfNull(context);
            // If no validator configured (e.g. lightweight unit test scenario), do nothing.
            var validator = context.Options.TokenValidator;
            return validator is not null ? validator.ValidateAsync(context) : Task.CompletedTask;
        };

        /// <summary>
        /// Invoked whenever the ID token needs to be validated.
        /// </summary>
        /// <param name="context">Contains information about the ID token to validate.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual async Task ValidateIdToken(OneIdValidateIdTokenContext context) =>
            await OnValidateIdToken(context).ConfigureAwait(false);
    }
}
#endif