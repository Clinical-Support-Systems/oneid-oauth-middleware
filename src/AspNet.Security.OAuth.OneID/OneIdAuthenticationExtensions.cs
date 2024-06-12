#region License, Terms and Conditions

//
// OneIdAuthenticationExtensions.cs
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
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

#if NETCORE
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;

#elif !NETCORE

using Owin;

#endif

namespace AspNet.Security.OAuth.OneID
{
    /// <summary>
    /// Extension methods to add OneID authentication capabilities to an HTTP application pipeline.
    /// </summary>
    public static class OneIdAuthenticationExtensions
    {
#if NETCORE
        /// <summary>
        /// Adds <see cref="OneIdAuthenticationHandler"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables OneId authentication capabilities.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public static AuthenticationBuilder AddOneId(this AuthenticationBuilder builder)
        {
            ArgumentNullException.ThrowIfNull(builder);

            return builder.AddOneId(OneIdAuthenticationDefaults.AuthenticationScheme, _ => { });
        }

        /// <summary>
        /// Adds <see cref="OneIdAuthenticationHandler"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables OneId authentication capabilities.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="configuration">The delegate used to configure the OpenID 2.0 options.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public static AuthenticationBuilder AddOneId(
            this AuthenticationBuilder builder,
            Action<OneIdAuthenticationOptions> configuration)
        {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentNullException.ThrowIfNull(configuration);

            return builder.AddOneId(OneIdAuthenticationDefaults.AuthenticationScheme, configuration);
        }

        /// <summary>
        /// Adds <see cref="OneIdAuthenticationHandler"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables OneId authentication capabilities.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="scheme">The authentication scheme associated with this instance.</param>
        /// <param name="configuration">The delegate used to configure the OneId options.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddOneId(
            this AuthenticationBuilder builder,
            string scheme,
            Action<OneIdAuthenticationOptions> configuration)
        {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentNullException.ThrowIfNull(configuration);

            if (string.IsNullOrEmpty(scheme))
            {
                throw new ArgumentException($"'{nameof(scheme)}' cannot be null or empty.", nameof(scheme));
            }

            return builder.AddOneId(scheme, OneIdAuthenticationDefaults.DisplayName, configuration);
        }

        /// <summary>
        /// Adds <see cref="OneIdAuthenticationHandler"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables OneId authentication capabilities.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="scheme">The authentication scheme associated with this instance.</param>
        /// <param name="caption">The optional display name associated with this instance.</param>
        /// <param name="configuration">The delegate used to configure the OneId options.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddOneId(
            this AuthenticationBuilder builder,
            string scheme,
            string caption,
            Action<OneIdAuthenticationOptions> configuration)
        {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentNullException.ThrowIfNull(scheme);
            ArgumentNullException.ThrowIfNull(configuration);

            builder.Services.AddHttpClient();
            builder.Services.TryAddSingleton<JwtSecurityTokenHandler>();
            builder.Services.TryAddSingleton<IPostConfigureOptions<OneIdAuthenticationOptions>, OneIdAuthenticationPostConfigureOptions>();

            return builder.AddOAuth<OneIdAuthenticationOptions, OneIdAuthenticationHandler>(scheme, caption, configuration);
        }

#elif !NETCORE

        /// <summary>The to query string.</summary>
        /// <param name="parameters">The parameters.</param>
        /// <returns>The <see cref="string"/>.</returns>
        /// <exception cref="ArgumentNullException">If the parameters are null</exception>
        internal static string ToQueryString(this Dictionary<string, string> parameters)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            // Avoiding URL encoding the query string parameters as it is NOT compatible with OneId.
            var query = string.Join("&", parameters.Where(pair => !string.IsNullOrEmpty(pair.Value)).Select(item => string.Format(CultureInfo.InvariantCulture, "{0}={1}", item.Key, item.Value)).ToArray());
            return string.IsNullOrEmpty(query) ? string.Empty : "?" + query;
        }

        /// <summary>
        /// Adds OneId authentication capabilities.
        /// </summary>
        /// <param name="app">The authentication builder.</param>
        /// <param name="options">The specific OneId authentication options, like environment and PKI.</param>
        /// <returns>The <see cref="IAppBuilder"/>.</returns>
        public static IAppBuilder UseOneIdAuthentication(this IAppBuilder app, OneIdAuthenticationOptions options)
        {
            if (app == null) throw new ArgumentNullException(nameof(app));
            if (options == null) throw new ArgumentNullException(nameof(options));

            app.Use(typeof(OneIdAuthenticationMiddleware), app, options);
            return app;
        }

        /// <summary>
        /// Adds OneId authentication capabilities.
        /// </summary>
        /// <param name="app">The authentication builder.</param>
        /// <param name="certificateThumbprint">The thumbprint of the prearranged and installed PKI certificate.</param>
        /// <param name="environment">The specific environment to connect with at eHealth.</param>
        /// <returns>The <see cref="IAppBuilder"/>.</returns>
        public static IAppBuilder UseOneIdAuthentication(this IAppBuilder app, string certificateThumbprint, OneIdAuthenticationEnvironment environment)
        {
            if (app == null) throw new ArgumentNullException(nameof(app));

            app.Use(typeof(OneIdAuthenticationMiddleware), app, new OneIdAuthenticationOptions
            {
                CertificateThumbprint = certificateThumbprint,
                Environment = environment
            });
            return app;
        }

#endif
    }
}