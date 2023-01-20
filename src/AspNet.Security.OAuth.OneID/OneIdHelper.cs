﻿#region License, Terms and Conditions

//
// OneIdHelper.cs
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

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using static AspNet.Security.OAuth.OneID.OneIdAuthenticationConstants;

namespace AspNet.Security.OAuth.OneID
{
    public static class OneIdHelper
    {
        /// <summary>
        /// This value should be updated by the discovery endpoint content, but won't be because it might not be correct.
        /// </summary>
        internal static string EndSessionUrl = "https://login.pst.oneidfederation.ehealthontario.ca/oidc/connect/endSession";

        /// <summary>
        /// Access token endpoint
        /// </summary>
        internal static string TokenEndpoint = "https://login.pst.oneidfederation.ehealthontario.ca/sso/oauth2/realms/root/realms/idaaspstoidc/access_token";

        /// <summary>
        /// Retrieves the constructed endSession url that the user should be redirected to, to end their OAG session.
        /// </summary>
        /// <param name="idToken">The id token</param>
        /// <param name="clientId">(Optional) The auth client id</param>
        /// <param name="postLogoutUri">(Optional) A post logout redirect</param>
        /// <param name="isProduction">Is this production? Default is false, PST</param>
        /// <returns>The url to redirect to</returns>
        public static string GetEndSessionUrl(string idToken, string? clientId = null, Uri? postLogoutUri = null, bool isProduction = false)
        {
            var queryValues = new Dictionary<string, string?>
            {
                {OAuth2Constants.IdTokenHint, idToken}
            };
            if (!string.IsNullOrEmpty(clientId))
                queryValues.Add(OAuth2Constants.ClientId, HttpUtility.UrlEncode(clientId));

            if (postLogoutUri != null)
                queryValues.Add(OAuth2Constants.PostLogoutRedirectUri, HttpUtility.UrlDecode(postLogoutUri.ToString()));

            if (isProduction)
            {
                EndSessionUrl = "https://login.oneidfederation.ehealthontario.ca/oidc/connect/endSession";
            }

            string uri;

            var array = queryValues.Where(x => !string.IsNullOrEmpty(x.Value)).Select(x => $"{HttpUtility.UrlEncode(x.Key)}={HttpUtility.UrlEncode(x.Value)}").ToArray();
            uri = EndSessionUrl + "?" + string.Join("&", array);

            return uri;
        }

        /// <summary>
        /// Obtain a new access token
        /// </summary>
        /// <param name="client">An http client that uses <see cref="OneIdAuthenticationBackChannelHandler"/> as it's backing http handler</param>
        /// <param name="options">The same set of <see cref="OneIdAuthenticationOptions"/> that was used when setting up authentication</param>
        /// <param name="refreshToken">The refresh token</param>
        /// <param name="ct">(optional) The cancellation token</param>
        /// <returns>The new access token if successful, empty string otherwise.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        public static async Task<string> RefreshToken(HttpClient client, OneIdAuthenticationOptions options, string refreshToken, CancellationToken ct = default)
        {
            if (client is null)
            {
                throw new ArgumentNullException(nameof(client));
            }

            if (options is null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (string.IsNullOrEmpty(refreshToken))
            {
                throw new ArgumentException($"'{nameof(refreshToken)}' cannot be null or empty.", nameof(refreshToken));
            }

            var tokenEndpoint = TokenEndpoint;
            if (options.Environment == OneIdAuthenticationEnvironment.Production)
            {
                tokenEndpoint = tokenEndpoint.Replace(".prod", string.Empty).Replace("idaasprodoidc", "idaasoidc");
            }
            else if(options.Environment != OneIdAuthenticationEnvironment.PartnerSelfTest)
            {
                throw new NotSupportedException($"Environment {Enum.GetName(typeof(OneIdAuthenticationEnvironment), options.Environment)} isn't supported for refresh token.");
            }

            using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/x-www-form-urlencoded"));
            request.Headers.UserAgent.ParseAdd(OneIdAuthenticationDefaults.UserAgent);

            var parameters = new Dictionary<string, string?>
            {
                [OAuth2Constants.GrantType] = OAuth2Constants.RefreshToken,
                [OAuth2Constants.RefreshToken] = refreshToken,
            };

            request.Content = new FormUrlEncodedContent((IEnumerable<KeyValuePair<string?, string?>>)parameters);
            using var response = await client.SendAsync(request, cancellationToken: ct).ConfigureAwait(false);

            Task<string>? readTask = null;

#if NETCORE
            readTask = response.Content.ReadAsStringAsync(ct);
#else
            readTask = response.Content.ReadAsStringAsync();
#endif

            if (response.IsSuccessStatusCode)
            {
                var tokenJson = JsonConvert.DeserializeObject<JObject>(await readTask.ConfigureAwait(false));

                return tokenJson?[OAuth2Constants.AccessToken]?.ToObject<string>() ?? "";
            }
            else
            {
                var responseContent = await readTask.ConfigureAwait(false);

                throw new OneIdAuthException(request.RequestUri, response.StatusCode, responseContent);
            }
        }
    }
}