#region License, Terms and Conditions

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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace AspNet.Security.OAuth.OneID
{
    public static class OneIdHelper
    {
        internal static string EndSessionUrl = "https://login.pst.oneidfederation.ehealthontario.ca/sso/oauth2/realms/root/realms/idaaspstoidc/connect/endSession";

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
                {"id_token_hint", idToken},
                //{ "IsES", "y" } // Don't know what this is, but it's on the spec example (but not documented)
            };
            if (!string.IsNullOrEmpty(clientId))
                queryValues.Add("client_id", HttpUtility.UrlEncode(clientId));

            if (postLogoutUri != null)
                queryValues.Add("post_logout_redirect_uri", HttpUtility.UrlEncode(postLogoutUri.ToString()));

            if (isProduction)
            {
                EndSessionUrl = "https://login.oneidfederation.ehealthontario.ca/sso/oauth2/realms/root/realms/idaasoidc/connect/endSession";
            }

            string uri;

            var array = queryValues.Where(x => !string.IsNullOrEmpty(x.Value)).Select(x => $"{HttpUtility.UrlEncode(x.Key)}={HttpUtility.UrlEncode(x.Value)}").ToArray();
            uri = EndSessionUrl + "?" + string.Join("&", array);

            return uri;
        }
    }
}