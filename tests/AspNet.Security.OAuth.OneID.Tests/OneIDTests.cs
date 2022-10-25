using AspNet.Security.OAuth.OneID;
using AspNet.Security.OAuth.Providers.Tests.Infrastructure;
using Microsoft.AspNetCore.Authentication;

namespace AspNet.Security.OAuth.Providers.Tests
{
    public class OneIDTests : OAuthTests<OneIdAuthenticationOptions>
    {
        public OneIDTests(ITestOutputHelper outputHelper)
        {
            OutputHelper = outputHelper;
        }

        public override string DefaultScheme => OneIdAuthenticationDefaults.AuthenticationScheme;

        protected override HttpMethod RedirectMethod => HttpMethod.Post;

        protected internal override void RegisterAuthentication(AuthenticationBuilder builder)
        {
            Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;

            builder.AddOneId(OneIdAuthenticationDefaults.AuthenticationScheme, options =>
            {
                ConfigureDefaults(builder, options);

                options.ServiceProfileOptions = OneIdAuthenticationServiceProfiles.OLIS | OneIdAuthenticationServiceProfiles.DHDR;
                options.ValidateTokens = false;
                options.Environment = OneIdAuthenticationEnvironment.PartnerSelfTest;
            });
        }

        [Theory]
        [InlineData(ClaimTypes.NameIdentifier, "D26903C8554D4BB3BEEFF4C26AB9F0B4@oneid.on.ca")]
        [InlineData(ClaimTypes.Name, "Chester Tester")]
        [InlineData(ClaimTypes.Email, "chester.tester@oneid.on.ca")]
        [InlineData(ClaimTypes.GivenName, "Chester")]
        public async Task Can_Sign_In_Using_OneID(string claimType, string claimValue)
        {
            // Arrange
            using var server = CreateTestServer();

            // Act
            var claims = await AuthenticateUserAsync(server);

            // Assert
            AssertClaim(claims, claimType, claimValue);
        }
    }
}