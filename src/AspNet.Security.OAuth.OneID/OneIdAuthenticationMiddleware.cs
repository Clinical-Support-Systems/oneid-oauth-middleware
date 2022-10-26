#region License, Terms and Conditions

//
// OneIdAuthenticationMiddleware.cs
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

using AspNet.Security.OAuth.OneID.Properties;
using AspNet.Security.OAuth.OneID.Provider;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin;
using System;
using System.Globalization;
using System.Net.Http;

namespace AspNet.Security.OAuth.OneID
{
    public sealed class OneIdAuthenticationMiddleware : AuthenticationMiddleware<OneIdAuthenticationOptions> , IDisposable
    {
        private HttpClient? _httpClient;
        private readonly ILogger _logger;
        private bool _isDisposed;

        public OneIdAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, OneIdAuthenticationOptions options) : base(next, options)
        {
            if (string.IsNullOrWhiteSpace(this.Options.ClientId))
            {
                throw new ArgumentException(
                    string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "ClientId"));
            }

            _logger = app.CreateLogger<OneIdAuthenticationMiddleware>();

            if (options != null && options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(typeof(OneIdAuthenticationMiddleware).FullName,
                    options.AuthenticationType);

                options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (string.IsNullOrEmpty(this.Options.SignInAsAuthenticationType))
            {
                this.Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }

            _httpClient = new HttpClient(ResolveHttpMessageHandler(this.Options))
            {
                Timeout = options?.BackchannelTimeout ?? TimeSpan.FromMinutes(5),
                MaxResponseContentBufferSize = 1024 * 1024 * 10
            };

            if (this.Options.AuthenticationHandlerFactory == null)
            {
                this.Options.AuthenticationHandlerFactory = new OneIdAuthenticationHandlerFactory(_httpClient, _logger);
            }

            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd(OneIdAuthenticationDefaults.UserAgent);
            _httpClient.DefaultRequestHeaders.ExpectContinue = false;
        }

        /// <summary>The resolve http message handler.</summary>
        /// <param name="options">The options.</param>
        /// <returns>The <see cref="HttpMessageHandler"/>.</returns>
        /// <exception cref="InvalidOperationException">If the web request handler is null</exception>
        private static HttpMessageHandler ResolveHttpMessageHandler(OneIdAuthenticationOptions options)
        {
            return options.BackchannelHttpHandler ?? new OneIdAuthenticationBackChannelHandler(options);
        }

        protected override AuthenticationHandler<OneIdAuthenticationOptions> CreateHandler()
        {
            return this.Options.AuthenticationHandlerFactory!.CreateHandler();
        }

        private void Dispose(bool disposing)
        {
            if (!_isDisposed)
            {
                if (disposing)
                {
                    _httpClient?.Dispose();
                }

                _httpClient = null;
                _isDisposed = true;
            }
        }
        ~OneIdAuthenticationMiddleware()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: false);
        }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}

#endif