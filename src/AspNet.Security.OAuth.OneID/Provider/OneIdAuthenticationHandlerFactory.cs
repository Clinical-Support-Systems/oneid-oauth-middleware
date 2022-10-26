#region License, Terms and Conditions

//
// OneIdAutenticateionHandlerFactory.cs
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
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using System.Net.Http;

namespace AspNet.Security.OAuth.OneID.Provider
{
    public interface IOneIdAuthenticationHandlerFactory
    {
        /// <summary>The create handler.</summary>
        /// <returns>The <see cref="AuthenticationHandler"/>.</returns>
        AuthenticationHandler<OneIdAuthenticationOptions> CreateHandler();
    }

    /// <summary>
    /// The OneId authentication handler factory.
    /// </summary>
    public sealed class OneIdAuthenticationHandlerFactory : IOneIdAuthenticationHandlerFactory
    {
        #region Fields

        /// <summary>The http client.</summary>
        private readonly HttpClient _httpClient;

        /// <summary>The logger.</summary>
        private readonly ILogger _logger;

        #endregion Fields

        #region Constructors and Destructors

        /// <summary>
        /// Initializes a new instance of the <see cref="OneIdAuthenticationHandlerFactory"/> class.
        /// </summary>
        /// <param name="httpClient">The http Client.</param>
        /// <param name="logger">The logger.</param>
        public OneIdAuthenticationHandlerFactory(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        #endregion Constructors and Destructors

        #region Public Methods and Operators

        /// <summary>The create handler.</summary>
        /// <returns>The <see cref="AuthenticationHandler" />.</returns>
        public AuthenticationHandler<OneIdAuthenticationOptions> CreateHandler()
        {
            return new OneIdAuthenticationHandler(_logger, _httpClient);
        }

        #endregion Public Methods and Operators
    }
}
#endif