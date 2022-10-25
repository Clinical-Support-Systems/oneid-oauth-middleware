#if NETCORE
using Microsoft.AspNetCore.Authentication.OAuth;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;

namespace AspNet.Security.OAuth.OneID
{
    /// <summary>
    /// Default <see cref="OneIdAuthenticationEvents"/> implementation.
    /// </summary>
    public class OneIdAuthenticationEvents : OAuthEvents
    {
        /// <summary>
        /// Gets or sets the delegate that is invoked when the <see cref="ValidateIdToken"/> method is invoked.
        /// </summary>
        public Func<OneIdValidateIdTokenContext, Task> OnValidateIdToken { get; set; } = async context =>
        {
            await context.Options.TokenValidator.ValidateAsync(context);
        };

        /// <summary>
        /// Invoked whenever the ID token needs to be validated.
        /// </summary>
        /// <param name="context">Contains information about the ID token to validate.</param>
        /// <returns>
        /// A <see cref="Task"/> representing the completed operation.
        /// </returns>
        public virtual async Task ValidateIdToken([NotNull] OneIdValidateIdTokenContext context) =>
            await OnValidateIdToken(context);
    }
}
#endif