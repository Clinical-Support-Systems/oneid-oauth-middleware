using AspNet.Security.OAuth.OneID;

namespace AspNet.Security.OAuth.Providers.Tests
{
    public class OneIDAuthenticationOptionsTests
    {
        [Fact]
        public static void Validate_Throws_If_ClientId_Is_Null()
        {
            // Arrange
            var options = new OneIdAuthenticationOptions()
            {
                ClientId = null!
            };

            // Act and Assert
            Assert.Throws<ArgumentException>("ClientId", () => options.Validate());
        }

        [Fact]
        public static void Validate_NonProdEnv_Throws_If_ClientSecret_Is_Null()
        {
            // Arrange
            var options = new OneIdAuthenticationOptions()
            {
                Environment = OneIdAuthenticationEnvironment.PartnerSelfTest,
                ServiceProfileOptions = OneIdAuthenticationServiceProfiles.OLIS,
                ClientId = "my-client-id",
                ClientSecret = null!,
            };

            // Act and Assert
            Assert.Throws<ArgumentException>("ClientSecret", () => options.Validate());
        }

        [Fact]
        public static void Validate_Throws_If_ServiceProfileOptions_Empty()
        {
            // Arrange
            var options = new OneIdAuthenticationOptions()
            {
                ClientId = "my-client-id"
            };

            // Act and Assert
            Assert.Throws<ArgumentException>("ServiceProfileOptions", () => options.Validate());
        }

        [Fact]
        public static void Validate_Throws_If_TokenSaveOptions_Empty()
        {
            // Arrange
            var options = new OneIdAuthenticationOptions()
            {
                ClientId = "my-client-id",
                ServiceProfileOptions = OneIdAuthenticationServiceProfiles.OLIS,
                TokenSaveOptions = OneIdAuthenticationTokenSave.None
            };

            // Act and Assert
            Assert.Throws<ArgumentException>("TokenSaveOptions", () => options.Validate());
        }

        [Fact]
        public static void Validate_Throws_If_AuthorizationEndpoint_Is_Null()
        {
            // Arrange
            var options = new OneIdAuthenticationOptions()
            {
                ClientId = "my-client-id",
                AuthorizationEndpoint = null!,
            };

            // Act and Assert
            Assert.Throws<ArgumentException>("AuthorizationEndpoint", () => options.Validate());
        }

        [Fact]
        public static void Validate_Throws_If_TokenEndpoint_Is_Null()
        {
            // Arrange
            var options = new OneIdAuthenticationOptions()
            {
                ClientId = "my-client-id",
                TokenEndpoint = null!,
            };

            // Act and Assert
            Assert.Throws<ArgumentException>("TokenEndpoint", () => options.Validate());
        }

        [Fact]
        public static void Validate_Throws_If_CallbackPath_Is_Null()
        {
            // Arrange
            var options = new OneIdAuthenticationOptions()
            {
                ClientId = "my-client-id",
                CallbackPath = null,
            };

            // Act and Assert
            Assert.Throws<ArgumentException>("CallbackPath", () => options.Validate());
        }
    }
}