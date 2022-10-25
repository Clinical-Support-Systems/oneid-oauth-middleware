#if NETCORE
using Microsoft.AspNetCore.Authentication.OAuth.Claims;
using System;
using System.Security.Claims;
using System.Text.Json;

namespace AspNet.Security.OAuth.OneID
{
    internal sealed class OneIdAuthenticationClaimAction : ClaimAction
    {
        private readonly OneIdAuthenticationOptions _options;

        internal OneIdAuthenticationClaimAction(OneIdAuthenticationOptions options)
            : base(ClaimTypes.Email, ClaimValueTypes.String)
        {
            _options = options;
        }

        public override void Run(JsonElement userData, ClaimsIdentity identity, string issuer)
        {
            if (!identity.HasClaim((p) => string.Equals(p.Type, ClaimType, StringComparison.OrdinalIgnoreCase)))
            {
                var emailClaim = identity.FindFirst("email");

                if (!string.IsNullOrEmpty(emailClaim?.Value))
                {
                    identity.AddClaim(new Claim(ClaimType, emailClaim.Value, ValueType, _options.ClaimsIssuer));
                }
            }
        }
    }
}
#endif