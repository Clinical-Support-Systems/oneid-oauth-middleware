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

#if NET8_0_OR_GREATER
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using System.Threading.Tasks;

namespace AspNet.Security.OAuth.OneID
{
    /// <summary>
    /// Represents the base class for validating Apple ID tokens.
    /// </summary>
    public interface IOneIdTokenValidator
    {
        /// <summary>
        /// Validates the OneID token associated with the specified context as an asynchronous operation.
        /// </summary>
        /// <param name="context">The context to validate the ID token for.</param>
        /// <returns>
        /// A <see cref="Task"/> representing the asynchronous operation to validate the ID token.
        /// </returns>
        Task ValidateAsync(OneIdValidateIdTokenContext context);
    }
    
    internal sealed partial class DefaultOneIdTokenValidator : IOneIdTokenValidator
    {
        private readonly ILogger _logger;
        private readonly IHttpClientFactory _httpClientFactory;

public DefaultOneIdTokenValidator(
            [NotNull] ILogger<DefaultOneIdTokenValidator> logger, IHttpClientFactory httpClientFactory)
        {
            _logger = logger;
            _httpClientFactory = httpClientFactory;
        }

[SuppressMessage("Performance", "CA1848:Use the LoggerMessage delegates", Justification = "<Pending>")]
        [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "<Pending>")]

        public async Task ValidateAsync([NotNull] OneIdValidateIdTokenContext context)
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

            // After retrieving the configuration
            if (configuration.JsonWebKeySet == null)
            {
                _logger.LogWarning("JsonWebKeySet is null in original configuration");

                // Try to fetch JWKS directly if the URI is available
                if (!string.IsNullOrEmpty(configuration.JwksUri))
                {
                    _logger.LogDebug("Attempting to fetch JWKS directly from: {JwksUri}", configuration.JwksUri);
                    try
                    {
                        using var httpClient = _httpClientFactory.CreateClient();
                        var jwksJson = await httpClient.GetStringAsync(new Uri(configuration.JwksUri)).ConfigureAwait(false);
                        _logger.LogTrace("JWKS response: {JwksJson}", jwksJson);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error fetching JWKS directly");
                    }
                }
                else
                {
                    _logger.LogWarning("No JwksUri available in the configuration");

                    // Set it manually
                    configuration.JwksUri = $"{configuration.AuthorizationEndpoint[..configuration.AuthorizationEndpoint.LastIndexOf('/')]}/connect/jwk_uri";

                    // Manually load the JWK set
                    using var httpClient = _httpClientFactory.CreateClient();
                    var jwksResponse = await httpClient.GetStringAsync(new Uri(configuration.JwksUri)).ConfigureAwait(false);

                    // Parse and set the JSON Web Key Set
                    configuration.JsonWebKeySet = JsonWebKeySet.Create(jwksResponse);
                }
            }

            var validationParameters = context.Options.TokenValidationParameters.Clone();

            if (configuration.JsonWebKeySet != null)
            {
                validationParameters.IssuerSigningKeys = configuration.JsonWebKeySet?.Keys;
            }
            else
            {
#pragma warning disable CA5404 // Do not disable token validation checks
                validationParameters.ValidateIssuer = false;
#pragma warning restore CA5404 // Do not disable token validation checks
            }

            try
            {
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