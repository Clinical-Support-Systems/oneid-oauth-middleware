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

            var configuration = await context.Options.ConfigurationManager.GetConfigurationAsync(context.HttpContext.RequestAborted);

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