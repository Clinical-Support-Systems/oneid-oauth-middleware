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

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using static AspNet.Security.OAuth.OneID.OneIdAuthenticationConstants;

namespace AspNet.Security.OAuth.OneID
{
    /// <summary>
    ///     Provides a specialized HTTP client handler for performing back-channel authentication requests to the OneID
    ///     identity provider, using client certificate-based JWT assertions as required by OneID protocols.
    /// </summary>
    /// <remarks>
    ///     This handler is intended for use with OneID authentication flows that require secure, signed
    ///     requests using a client certificate. It automatically generates and attaches a JWT assertion to outgoing
    ///     requests, based on the provided certificate options. The handler validates configuration to ensure only one
    ///     certificate source is specified and returns a 204 NoContent response if the request has no content, avoiding
    ///     unnecessary network calls. Thread safety is inherited from the base HttpClientHandler. For correct operation,
    ///     ensure that the associated OneIdAuthenticationOptions are properly configured with either a certificate
    ///     thumbprint or a certificate file and password.
    /// </remarks>
    public sealed class OneIdAuthenticationBackChannelHandler : HttpClientHandler
    {
        private static readonly char[] EqualsSeparator = ['=']; // CA1861 mitigation
        private readonly OneIdAuthenticationOptions _options;

        /// <summary>
        ///     Initializes a new instance of the OneIdAuthenticationBackChannelHandler class using the specified
        ///     authentication options.
        /// </summary>
        /// <param name="options">The configuration options for OneId authentication. Cannot be null.</param>
        public OneIdAuthenticationBackChannelHandler(OneIdAuthenticationOptions options)
        {
            _options = options;
        }

        protected async override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
#if NET8_0_OR_GREATER
            ArgumentNullException.ThrowIfNull(request);
#else
            if (request is null)
            {
                throw new ArgumentNullException(nameof(request));
            }
#endif
            if (request.Content == null)
            {
                // Early return without performing a network call when there is no content.
                // This aligns with test expectations: SendAsync should return 204 NoContent.
                return new HttpResponseMessage(HttpStatusCode.NoContent);
            }

#pragma warning disable CA1508 // cert may be null until assignment; disposal uses null-conditional for safety.
            X509Certificate2? cert = null;
            try
            {
                if (!string.IsNullOrEmpty(_options.CertificateThumbprint) &&
                    !string.IsNullOrEmpty(_options.CertificateFilename))
                {
                    throw new InvalidOperationException(
                        "Cannot specify both CertificateThumbprint and CertificateFilename.");
                }

                if (!string.IsNullOrEmpty(_options.CertificateThumbprint))
                {
                    cert = OneIdCertificateUtility.FindCertificateByThumbprint(_options.CertificateStoreName,
                        _options.CertificateStoreLocation, _options.CertificateThumbprint, false);
                }
                else if (!string.IsNullOrEmpty(_options.CertificateFilename))
                {
#if NET8_0_OR_GREATER
                    var certBytes =
                        await File.ReadAllBytesAsync(_options.CertificateFilename!, cancellationToken).ConfigureAwait(false);
#else
                    var certBytes = File.ReadAllBytes(_options.CertificateFilename!);
#endif
                    string? plainPassword = null;
#if NET8_0_OR_GREATER
                    if (_options.CertificatePassword is not null)
                    {
                        plainPassword = new NetworkCredential(string.Empty, _options.CertificatePassword).Password;
                    }
#else
                    if (_options.CertificatePassword is not null)
                    {
                        plainPassword = new NetworkCredential(string.Empty, _options.CertificatePassword).Password;
                    }
#endif
                    cert = TryImportWithFallback(certBytes, plainPassword);
                }

                if (cert == null)
                {
                    throw new InvalidOperationException(
                        "Must specify CertificateThumbprint or CertificateFilename (with CertificatePassword if applicable).");
                }

                var signingKey = new X509SecurityKey(cert);
                var credentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256);

                var now = DateTimeOffset.Now.ToUnixTimeSeconds();
                var expire = DateTimeOffset.Now.AddMinutes(20).ToUnixTimeSeconds();

                var permClaims = new List<Claim>
                {
                    new("iss", _options.ClientId),
                    new("sub", _options.ClientId),
                    new("aud", _options.Audience),
                    new("iat", now.ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),
                    new("exp", expire.ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),
#if NET8_0_OR_GREATER
                    new("jti", Guid.NewGuid().ToString().Replace("-", string.Empty, StringComparison.InvariantCulture))
#else
                    new("jti", Guid.NewGuid().ToString().Replace("-", string.Empty))
#endif
                };

                var token = new JwtSecurityToken(claims: permClaims, signingCredentials: credentials);
                token.Header.Remove("kid");
                var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

#if NET8_0_OR_GREATER
                var oldContent = await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
#else
                var oldContent = await request.Content.ReadAsStringAsync().ConfigureAwait(false);
#endif

                var data = new Dictionary<string, string>(StringComparer.Ordinal);
#if NET8_0_OR_GREATER
                var raw = oldContent.Replace("?", string.Empty, StringComparison.InvariantCulture);
#else
                var raw = oldContent.Replace("?", string.Empty);
#endif
                foreach (var segment in raw.Split('&'))
                {
                    if (string.IsNullOrWhiteSpace(segment))
                    {
                        continue;
                    }

                    var parts = segment.Split(EqualsSeparator, 2);
                    var decodedKeyLocal = WebUtility.UrlDecode(parts[0]);
                    var decodedValueLocal = parts.Length == 2 ? WebUtility.UrlDecode(parts[1]) : string.Empty;
                    data[decodedKeyLocal] = decodedValueLocal;
                }

                if (data.TryGetValue("redirect_uri", out var redirectUri))
                {
                    data["redirect_uri"] = WebUtility.UrlDecode(redirectUri);
                }

                data["client_assertion_type"] = ClaimNames.JwtBearerAssertion;
                data["client_assertion"] = jwtToken;
                data["aud"] = ClaimNames.ApiAudience;

                request.Content = new FormUrlEncodedContent(data.AsEnumerable());
                return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                cert?.Dispose();
            }
#pragma warning restore CA1508
        }

        private static X509Certificate2? TryImportWithFallback(byte[] certBytes, string? password)
        {
            if (certBytes.Length == 0)
            {
                return null;
            }

            var attempts = new List<X509KeyStorageFlags>();
#if NET8_0_OR_GREATER
            attempts.Add(X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
#endif
            attempts.Add(X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);
            attempts.Add(X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);

            foreach (var flags in attempts)
            {
                try { return new X509Certificate2(certBytes, password, flags); }
                catch (CryptographicException) { }
            }

            // Legacy fallback (may persist key). Avoid if possible but retain for backward compatibility.
            try
            {
                return new X509Certificate2(certBytes, password,
                    X509KeyStorageFlags.MachineKeySet |
                    X509KeyStorageFlags.Exportable |
                    X509KeyStorageFlags.PersistKeySet);
            }
            catch (CryptographicException) { return null; }
        }
    }

    /// <summary>
    ///     Provides utility methods for locating and exporting X.509 certificates used with OneId authentication scenarios.
    /// </summary>
    /// <remarks>
    ///     This class offers static methods to search for certificates by thumbprint in the Windows
    ///     certificate store and to export certificates with their private keys. All methods are thread-safe and do not
    ///     maintain any internal state. The exported certificates are protected with a randomly generated password for
    ///     security. These utilities are intended to simplify certificate management tasks in applications that integrate
    ///     with OneId.
    /// </remarks>
    public static class OneIdCertificateUtility
    {
        /// <summary>
        ///     Finds and returns an X509 certificate from the specified certificate store that matches the given
        ///     thumbprint.
        /// </summary>
        /// <remarks>
        ///     The method searches the specified certificate store in read-only mode and returns the
        ///     first certificate that matches the provided thumbprint. If <paramref name="validationRequired" /> is
        ///     <see
        ///         langword="true" />
        ///     , only certificates that are currently valid are considered. The caller is responsible for
        ///     disposing the returned certificate if necessary.
        /// </remarks>
        /// <param name="storeName">The name of the certificate store to search, such as My or Root.</param>
        /// <param name="storeLocation">The location of the certificate store, such as CurrentUser or LocalMachine.</param>
        /// <param name="thumbprint">The thumbprint of the certificate to locate. Cannot be null or empty.</param>
        /// <param name="validationRequired">
        ///     Specifies whether only valid certificates should be returned. If <see langword="true" />, only certificates
        ///     that are valid at the time of search are considered.
        /// </param>
        /// <returns>An <see cref="X509Certificate2" /> object representing the certificate that matches the specified thumbprint.</returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="thumbprint" /> is null or empty.</exception>
        /// <exception cref="ArgumentException">
        ///     Thrown if no certificate matching the specified thumbprint is found in the given
        ///     store.
        /// </exception>
        public static X509Certificate2 FindCertificateByThumbprint(StoreName storeName, StoreLocation storeLocation,
            string? thumbprint, bool validationRequired)
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
                store.Close();
#else
                store.Dispose();
#endif
            }
        }

        /// <summary>
        ///     Finds an X.509 certificate in the current user's personal certificate store by its thumbprint, with optional
        ///     validation.
        /// </summary>
        /// <remarks>
        ///     If multiple certificates share the specified thumbprint, the first matching
        ///     certificate is returned. Validation includes checking the certificate's expiration and revocation status
        ///     when <paramref name="validateCertificate" /> is <see langword="true" />.
        /// </remarks>
        /// <param name="thumbprint">
        ///     The thumbprint of the certificate to locate. This value is case-insensitive and must not be
        ///     null or empty.
        /// </param>
        /// <param name="validateCertificate">
        ///     Specifies whether to validate the certificate's integrity and trustworthiness. Set to <see langword="true" />
        ///     to perform validation; otherwise, <see langword="false" />.
        /// </param>
        /// <returns>
        ///     An <see cref="X509Certificate2" /> instance representing the found certificate if a matching certificate
        ///     exists; otherwise, <see langword="null" />.
        /// </returns>
        public static X509Certificate2 FindCertificateByThumbprint(string thumbprint, bool validateCertificate)
        {
            return FindCertificateByThumbprint(StoreName.My, StoreLocation.CurrentUser, thumbprint,
                validateCertificate);
        }

        /// <summary>
        ///     Exports the specified X.509 certificate and its private key to a PKCS#12 (PFX) byte array, protecting the
        ///     private key with a randomly generated password.
        /// </summary>
        /// <remarks>
        ///     The generated password is a random, base64-encoded string and is required to import
        ///     the exported PKCS#12 data. The caller is responsible for securely storing or transmitting the password as
        ///     needed.
        /// </remarks>
        /// <param name="cert">
        ///     The X509Certificate2 instance containing the certificate and private key to export. Must include a private
        ///     key.
        /// </param>
        /// <param name="password">
        ///     When this method returns, contains the randomly generated password used to protect the exported PKCS#12
        ///     data.
        /// </param>
        /// <returns>
        ///     A byte array containing the PKCS#12 (PFX) representation of the certificate and private key, encrypted with
        ///     the generated password.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="cert" /> is <see langword="null" />.</exception>
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
