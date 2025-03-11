using AspNet.Security.OAuth.OneID;

namespace AspNet.Security.OAuth.Providers.Tests
{
    public class TokenTests
    {
        [Fact(Skip = "Only do this when verifying")]
        public async Task RefreshToken_Should_Return_New_AccessToken_Production()
        {
            var existingAccessToken = "";
            var refreshToken = "";
            var pfxPassword = new System.Security.SecureString();
            "".ToCharArray().ToList().ForEach(pfxPassword.AppendChar);

            // Set up production environment options
            var options = new OneIdAuthenticationOptions
            {
                ClientId = "",
                CertificateFilename = "",
                CertificatePassword = pfxPassword,
                Environment = OneIdAuthenticationEnvironment.Production // Hit the production endpoint
            };

            // Arrange
            using var handler = new OneIdAuthenticationBackChannelHandler(options);
            using var client = new HttpClient(handler); // In production, you use a real HttpClient

            // Act
            var newAccessToken = await OneIdHelper.RefreshToken(client, options, refreshToken);

            // Assert that a new access token is returned
            newAccessToken.ShouldSatisfyAllConditions(
                x => x.ShouldNotBeNullOrEmpty(),
                x => x.ShouldNotBe(existingAccessToken)
            );
        }
    }
}
