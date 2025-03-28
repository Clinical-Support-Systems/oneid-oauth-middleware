﻿#region License, Terms and Conditions

//
// OneIdAuthenticationBackChannelHandler.cs
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

using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static AspNet.Security.OAuth.OneID.OneIdAuthenticationConstants;

namespace AspNet.Security.OAuth.OneID
{
    /// <summary>
    /// The backchannel handler that deals with the client assertion and SSL
    /// </summary>
    public sealed class OneIdAuthenticationBackChannelHandler : HttpClientHandler
    {
        private readonly OneIdAuthenticationOptions _options;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="options">The options</param>
        public OneIdAuthenticationBackChannelHandler(OneIdAuthenticationOptions options)
        {
            _options = options;
        }

        /// <inheritdoc/>
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
#if NET8_0_OR_GREATER
            ArgumentNullException.ThrowIfNull(request);
#else
            if (request is null)
            {
                throw new ArgumentNullException(nameof(request));
            }
#endif

            // Get the certificate
            X509Certificate2? cert = null;

            try
            {
                if (!string.IsNullOrEmpty(_options.CertificateThumbprint) && !string.IsNullOrEmpty(_options.CertificateFilename))
                {
                    throw new InvalidOperationException("Cannot specify both CertificateThumbprint and CertificateFilename.");
                }

                if (!string.IsNullOrEmpty(_options.CertificateThumbprint))
                {
                    cert = OneIdCertificateUtility.FindCertificateByThumbprint(
                        _options.CertificateStoreName,
                        _options.CertificateStoreLocation,
                        _options.CertificateThumbprint,
                        false);
                }
                else if (!string.IsNullOrEmpty(_options.CertificateFilename))
                {
#if NET8_0_OR_GREATER
                    var certBytes = await File.ReadAllBytesAsync(_options.CertificateFilename, cancellationToken);
#else
                    var certBytes = File.ReadAllBytes(_options.CertificateFilename);
#endif
                    cert = new X509Certificate2(
                        certBytes,
                        _options.CertificatePassword,
                        X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
                }

                if (cert == null)
                {
                    throw new InvalidOperationException("Must specify CertificateThumbprint or CertificateFilename (with CertificatePassword if applicable).");
                }

                X509SecurityKey key = new(cert);
                SigningCredentials credentials = new(key, SecurityAlgorithms.RsaSha256);

                var now = DateTimeOffset.Now.ToUnixTimeSeconds();
                var expire = DateTimeOffset.Now.AddMinutes(20).ToUnixTimeSeconds();

                // we now need to create a JWT that we include in the response as the claim_assertion
                var permClaims = new List<Claim>
            {
                new("iss", _options.ClientId),
                new("sub", _options.ClientId),
                new("aud", _options.Audience),
                new("iat", now.ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),
                new("exp", expire.ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),
#if NET8_0_OR_GREATER
                new("jti", $"{Guid.NewGuid().ToString().Replace("-", string.Empty, StringComparison.InvariantCulture)}")
#else
                new("jti", $"{Guid.NewGuid().ToString().Replace("-", string.Empty)}")
#endif
            };

                // Create Security Token object by giving required parameters. Since we're specifically setting the iss/sub/aud/exp above, don't include them below
                var token = new JwtSecurityToken(
                                claims: permClaims,
                                signingCredentials: credentials);

                token.Header.Remove("kid");

                var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

                // Now we need to redo the form params so we can add/modify. Let's first take the values out and put them into a mutable dictionary
                if (request.Content == null) return new HttpResponseMessage { StatusCode = HttpStatusCode.NoContent };
#if NET8_0_OR_GREATER
                var oldContent = await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
#else
                var oldContent = await request.Content.ReadAsStringAsync().ConfigureAwait(false);
#endif

#if NET8_0_OR_GREATER
                var data = oldContent.Replace("?", string.Empty, StringComparison.InvariantCulture).Split('&').ToDictionary(x => x.Split('=')[0], x => x.Split('=')[1]);
#else
                    var data = oldContent.Replace("?", string.Empty).Split('&').ToDictionary(x => x.Split('=')[0], x => x.Split('=')[1]);
#endif

                // Helen reported we were double encoding this, so let's set it again
                if (data.TryGetValue("redirect_uri", out string? redirectUri))
                    data["redirect_uri"] = WebUtility.UrlDecode(redirectUri);

                // Make sure the client_assertion_type is what is expected.
                data.Remove("client_assertion_type");
                data.Add("client_assertion_type", ClaimNames.JwtBearerAssertion); // must include this non-encoded as the process will re-encode it

                // Make sure the client_assertion is what is expected.
                data.Remove("client_assertion");
                data.Add("client_assertion", jwtToken);

                data.Remove("aud");
                data.Add("aud", ClaimNames.ApiAudience); // Is this value ever-changing?

                // Now put it back ibnto the request
                request.Content = new FormUrlEncodedContent(data.AsEnumerable());

                return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                cert?.Dispose();
            }
        }
    }

    /// <summary>
    /// utility class to find certs and export them into byte arrays
    /// </summary>
    public static class OneIdCertificateUtility
    {
        /// <summary>
        /// Finds the cert having thumbprint supplied from store location supplied
        /// </summary>
        /// <param name="storeName"></param>
        /// <param name="storeLocation"></param>
        /// <param name="thumbprint"></param>
        /// <param name="validationRequired"></param>
        /// <returns>X509Certificate2</returns>
        public static X509Certificate2 FindCertificateByThumbprint(StoreName storeName, StoreLocation storeLocation, string? thumbprint, bool validationRequired)
        {
            if (string.IsNullOrEmpty(thumbprint))
            {
                throw new ArgumentNullException(nameof(thumbprint));
            }

            var store = new X509Store(storeName, storeLocation);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                var col = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validationRequired);
                if (col == null || col.Count == 0)
                {
                    throw new ArgumentException($"Certificate was not found in store {storeName}:{storeLocation}");
                }

                return col[0];
            }
            finally
            {
#if !NETCORE
                // IDisposable not implemented in NET451
                store.Close();
#else
                // Close is private in DNXCORE, but Dispose calls close internally
                store.Dispose();
#endif
            }
        }

        /// <summary>
        ///Finds the cert having thumbprint supplied defaulting to the personal store of currrent user.
        /// </summary>
        /// <param name="thumbprint"></param>
        /// <param name="validateCertificate"></param>
        /// <returns>X509Certificate2</returns>
        public static X509Certificate2 FindCertificateByThumbprint(string thumbprint, bool validateCertificate)
        {
            return FindCertificateByThumbprint(StoreName.My, StoreLocation.CurrentUser, thumbprint, validateCertificate);
        }

        /// <summary>
        /// Exports the cert supplied into a byte arrays and secures it with a randomly generated password.
        ///</summary>
        /// <param name="cert"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static byte[] ExportCertificateWithPrivateKey(X509Certificate2 cert, out string password)
        {
#if NET8_0_OR_GREATER
            ArgumentNullException.ThrowIfNull(cert);
#else
            if (cert is null)
            {
                throw new ArgumentNullException(nameof(cert));
            }
#endif

            password = Convert.ToBase64String(Encoding.Unicode.GetBytes(Guid.NewGuid().ToString("N")));
            return cert.Export(X509ContentType.Pkcs12, password);
        }
    }
}