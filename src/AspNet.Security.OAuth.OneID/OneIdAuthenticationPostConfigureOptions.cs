#region License, Terms and Conditions

//
// OneIdAuthenticationPostConfigureOptions.cs
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
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace AspNet.Security.OAuth.OneID
{
    public class OneIdAuthenticationPostConfigureOptions : IPostConfigureOptions<OneIdAuthenticationOptions>
    {
        private readonly ILoggerFactory _loggerFactory;
        private readonly IHttpClientFactory _httpClientFactory;

        public OneIdAuthenticationPostConfigureOptions(ILoggerFactory loggerFactory,
            IHttpClientFactory httpClientFactory)
        {
            _loggerFactory = loggerFactory;
            _httpClientFactory = httpClientFactory;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "<Pending>")]
        public void PostConfigure(string? name, OneIdAuthenticationOptions options)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException($"'{nameof(name)}' cannot be null or empty.", nameof(name));
            }

            ArgumentNullException.ThrowIfNull(options);

            if (string.IsNullOrEmpty(options.TokenValidationParameters.ValidAudience) && !string.IsNullOrEmpty(options.ClientId))
            {
                options.TokenValidationParameters.ValidateAudience = true;
                options.TokenValidationParameters.ValidAudience = options.ClientId;

                options.TokenValidationParameters.ValidateIssuer = true;
                options.TokenValidationParameters.ValidIssuer = options.ClaimsIssuer;

                options.TokenValidationParameters.ValidateIssuerSigningKey = true;
            }

            options.TokenValidator ??= new DefaultOneIdTokenValidator(
                    _loggerFactory.CreateLogger<DefaultOneIdTokenValidator>(), _httpClientFactory);

            if (options.ConfigurationManager == null)
            {
                if (string.IsNullOrEmpty(options.MetadataEndpoint))
                {
                    throw new InvalidOperationException($"The MetadataEndpoint must be set on the {nameof(OneIdAuthenticationOptions)} instance.");
                }

                options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                    options.MetadataEndpoint,
                    new OpenIdConnectConfigurationRetriever(),
                    new HttpDocumentRetriever(_httpClientFactory.CreateClient())) // Specifically the default backchannel handler isn't usable for this, just use a regular httpclient back retriever
                {
                    AutomaticRefreshInterval = TimeSpan.FromDays(1),
                    RefreshInterval = TimeSpan.FromSeconds(30)
                };
            }

            options.SecurityTokenHandler ??= new JsonWebTokenHandler();
        }
    }
}
#endif