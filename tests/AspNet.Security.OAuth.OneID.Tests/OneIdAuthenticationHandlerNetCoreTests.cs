using System.Text.Encodings.Web;
using AspNet.Security.OAuth.OneID;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNet.Security.OAuth.Providers.Tests
{
    public class OneIdAuthenticationHandlerNetCoreTests
    {
#if NET8_0_OR_GREATER
        [Fact]
        public void Constructor_Succeeds_With_Valid_Arguments()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddAuthentication().AddOneId(o =>
            {
                o.ClientId = "client";
                o.ClientSecret = "secret";
            });
            var sp = services.BuildServiceProvider();
            var optionsMonitor = sp.GetRequiredService<IOptionsMonitor<OneIdAuthenticationOptions>>();
            var loggerFactory = sp.GetRequiredService<ILoggerFactory>();
            var encoder = UrlEncoder.Default;

            // Act
            var handler = new OneIdAuthenticationHandler(optionsMonitor, loggerFactory, encoder);

            // Assert
            Assert.NotNull(handler);
        }

        [Fact]
        public void Constructor_Throws_If_Options_Null()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddAuthentication().AddOneId(o =>
            {
                o.ClientId = "client";
                o.ClientSecret = "secret";
            });
            var sp = services.BuildServiceProvider();
            var loggerFactory = sp.GetRequiredService<ILoggerFactory>();
            var encoder = UrlEncoder.Default;

            // Act & Assert
            var ex = Assert.Throws<ArgumentNullException>(() => new OneIdAuthenticationHandler(null!, loggerFactory, encoder));
            Assert.Equal("options", ex.ParamName);
        }

        [Fact]
        public void Constructor_Throws_If_LoggerFactory_Null()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddAuthentication().AddOneId(o =>
            {
                o.ClientId = "client";
                o.ClientSecret = "secret";
            });
            var sp = services.BuildServiceProvider();
            var optionsMonitor = sp.GetRequiredService<IOptionsMonitor<OneIdAuthenticationOptions>>();
            var encoder = UrlEncoder.Default;

            // Act & Assert
            var ex = Assert.Throws<ArgumentNullException>(() => new OneIdAuthenticationHandler(optionsMonitor, null!, encoder));
            Assert.Equal("logger", ex.ParamName);
        }

        [Fact]
        public void Constructor_Throws_If_Encoder_Null()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddAuthentication().AddOneId(o =>
            {
                o.ClientId = "client";
                o.ClientSecret = "secret";
            });
            var sp = services.BuildServiceProvider();
            var optionsMonitor = sp.GetRequiredService<IOptionsMonitor<OneIdAuthenticationOptions>>();
            var loggerFactory = sp.GetRequiredService<ILoggerFactory>();

            // Act & Assert
            var ex = Assert.Throws<ArgumentNullException>(() => new OneIdAuthenticationHandler(optionsMonitor, loggerFactory, null!));
            Assert.Equal("encoder", ex.ParamName);
        }
#endif
    }
}