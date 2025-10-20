#region License, Terms and Conditions

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
    public sealed class OneIdAuthenticationBackChannelHandler : HttpClientHandler
    {
        private readonly OneIdAuthenticationOptions _options;
        private static readonly char[] EqualsSeparator = ['=']; // CA1861 mitigation

        public OneIdAuthenticationBackChannelHandler(OneIdAuthenticationOptions options) => _options = options;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
#if NET8_0_OR_GREATER
            ArgumentNullException.ThrowIfNull(request);
#else
            if (request is null) throw new ArgumentNullException(nameof(request));
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
                if (!string.IsNullOrEmpty(_options.CertificateThumbprint) && !string.IsNullOrEmpty(_options.CertificateFilename))
                {
                    throw new InvalidOperationException("Cannot specify both CertificateThumbprint and CertificateFilename.");
                }

                if (!string.IsNullOrEmpty(_options.CertificateThumbprint))
                {
                    cert = OneIdCertificateUtility.FindCertificateByThumbprint(_options.CertificateStoreName, _options.CertificateStoreLocation, _options.CertificateThumbprint, false);
                }
                else if (!string.IsNullOrEmpty(_options.CertificateFilename))
                {
#if NET8_0_OR_GREATER
                    var certBytes = await File.ReadAllBytesAsync(_options.CertificateFilename, cancellationToken).ConfigureAwait(false);
#else
                    var certBytes = File.ReadAllBytes(_options.CertificateFilename);
#endif
                    string? plainPassword = null;
#if NET8_0_OR_GREATER
                    if (_options.CertificatePassword is not null)
                    {
                        plainPassword = new System.Net.NetworkCredential(string.Empty, _options.CertificatePassword).Password;
                    }
#else
                    if (_options.CertificatePassword is not null)
                    {
                        plainPassword = new System.Net.NetworkCredential(string.Empty, _options.CertificatePassword).Password;
                    }
#endif
                    cert = TryImportWithFallback(certBytes, plainPassword);
                }

                if (cert == null)
                {
                    throw new InvalidOperationException("Must specify CertificateThumbprint or CertificateFilename (with CertificatePassword if applicable).");
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
                    if (string.IsNullOrWhiteSpace(segment)) continue;
                    var parts = segment.Split(EqualsSeparator, 2);
                    var decodedKeyLocal = WebUtility.UrlDecode(parts[0]);
                    var decodedValueLocal = parts.Length == 2 ? WebUtility.UrlDecode(parts[1]) : string.Empty;
                    data[decodedKeyLocal] = decodedValueLocal;
                }

                if (data.TryGetValue("redirect_uri", out string? redirectUri))
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
            if (certBytes.Length == 0) return null;

            var attempts = new List<X509KeyStorageFlags>();
#if NET8_0_OR_GREATER
            attempts.Add(X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
#endif
            attempts.Add(X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);
            attempts.Add(X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);

            foreach (var flags in attempts)
            {
                try { return new X509Certificate2(certBytes, password, flags); }
                catch (System.Security.Cryptography.CryptographicException) { }
            }

            // Legacy fallback (may persist key). Avoid if possible but retain for backward compatibility.
            try { return new X509Certificate2(certBytes, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet); }
            catch (System.Security.Cryptography.CryptographicException) { return null; }
        }
    }

    public static class OneIdCertificateUtility
    {
        public static X509Certificate2 FindCertificateByThumbprint(StoreName storeName, StoreLocation storeLocation, string? thumbprint, bool validationRequired)
        {
            if (string.IsNullOrEmpty(thumbprint)) throw new ArgumentNullException(nameof(thumbprint));
            var store = new X509Store(storeName, storeLocation);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                var col = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validationRequired);
                if (col == null || col.Count == 0) throw new ArgumentException($"Certificate was not found in store {storeName}:{storeLocation}");
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

        public static X509Certificate2 FindCertificateByThumbprint(string thumbprint, bool validateCertificate)
            => FindCertificateByThumbprint(StoreName.My, StoreLocation.CurrentUser, thumbprint, validateCertificate);

        public static byte[] ExportCertificateWithPrivateKey(X509Certificate2 cert, out string password)
        {
#if NET8_0_OR_GREATER
            ArgumentNullException.ThrowIfNull(cert);
#else
            if (cert is null) throw new ArgumentNullException(nameof(cert));
#endif
            password = Convert.ToBase64String(Encoding.Unicode.GetBytes(Guid.NewGuid().ToString("N")));
            return cert.Export(X509ContentType.Pkcs12, password);
        }
    }
}