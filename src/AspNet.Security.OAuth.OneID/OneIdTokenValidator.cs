#region License, Terms and Conditions

//
// OneIdTokenValidator.cs
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
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Diagnostics.CodeAnalysis;
using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace AspNet.Security.OAuth.OneID
{
    /// <summary>
    /// Represents the base class for validating Apple ID tokens.
    /// </summary>
    public abstract class OneIdTokenValidator
    {
        /// <summary>
        /// Validates the OneID token associated with the specified context as an asynchronous operation.
        /// </summary>
        /// <param name="context">The context to validate the ID token for.</param>
        /// <returns>
        /// A <see cref="Task"/> representing the asynchronous operation to validate the ID token.
        /// </returns>
        public abstract Task ValidateAsync(OneIdValidateIdTokenContext context);
    }

    internal sealed partial class DefaultOneIdTokenValidator : OneIdTokenValidator
    {
        private readonly ILogger _logger;

        public DefaultOneIdTokenValidator(
            [NotNull] ILogger<DefaultOneIdTokenValidator> logger)
        {
            _logger = logger;
        }

        public override async Task ValidateAsync([NotNull] OneIdValidateIdTokenContext context)
        {
            if (context.Options.SecurityTokenHandler is null)
            {
                throw new InvalidOperationException("The options SecurityTokenHandler is null.");
            }

            if (!context.Options.SecurityTokenHandler.CanValidateToken)
            {
                throw new NotSupportedException($"The configured {nameof(JsonWebTokenHandler)} cannot validate tokens.");
            }

            if (context.Options.ConfigurationManager is null)
            {
                throw new InvalidOperationException($"An OpenID Connect configuration manager has not been set on the {nameof(OneIdAuthenticationOptions)} instance.");
            }

            if (context.Options.TokenValidationParameters is null)
            {
                throw new InvalidOperationException($"Token validation parameters have not been set on the {nameof(OneIdAuthenticationOptions)} instance.");
            }

            var configuration = await context.Options.ConfigurationManager.GetConfigurationAsync(context.HttpContext.RequestAborted).ConfigureAwait(false);

            // TODO: Update with value from discovery? Value might be incorrect
            //OneIdHelper.EndSessionUrl = configuration.EndSessionEndpoint;

            var validationParameters = context.Options.TokenValidationParameters.Clone();
            validationParameters.IssuerSigningKeys = configuration.JsonWebKeySet.Keys;

            try
            {
                var old = validationParameters.ValidIssuer;
                validationParameters.ValidIssuer = context.Options.Audience.Replace("/access_token", string.Empty, StringComparison.OrdinalIgnoreCase);
                var result = await context.Options.SecurityTokenHandler.ValidateTokenAsync(context.IdToken, validationParameters).ConfigureAwait(false);

                if (result.Exception is not null || !result.IsValid)
                {
                    throw new SecurityTokenValidationException("OneID token validation failed.", result.Exception);
                }
            }
            catch (Exception ex)
            {
                _logger.TokenValidationFailed(ex, validationParameters.ValidIssuer, validationParameters.ValidAudience);
                _logger.TokenInvalid(ex, context.IdToken);
                throw;
            }
        }
    }

}
#endif