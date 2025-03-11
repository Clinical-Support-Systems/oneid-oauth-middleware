#region License, Terms and Conditions

//
// PKCECode.cs
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

#if !NETCORE

namespace AspNet.Security.OAuth.OneID
{
    public class PkceCode
    {
        public string? CodeChallenge { get; set; }

        public string? CodeVerifier { get; set; }

        public static PkceCode GeneratePKCECodes()
        {
            var bytes = new byte[32];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }

            // It's recommended that the code_verifier be a URL-safe string
            // See the Section 4 of the RFC 7636 for more details.
            var code_verifier = Convert.ToBase64String(bytes)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');

            var code_challenge = string.Empty;
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                var challengeBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(code_verifier));
                code_challenge = Convert.ToBase64String(challengeBytes)
                    .TrimEnd('=')
                    .Replace('+', '-')
                    .Replace('/', '_');
            }

            return new PkceCode()
            {
                CodeVerifier = code_verifier,
                CodeChallenge = code_challenge,
            };
        }
    }
}
#endif