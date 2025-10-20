using System;
using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;
using AspNet.Security.OAuth.OneID;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AspNet.Security.OAuth.Providers.Tests
{
    public class OneIdAuthenticationExtensionsTests
    {
#if NET8_0_OR_GREATER
        [Fact]
        public void AddOneId_Default_Registers_Scheme_And_Services()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddLogging();
            var builder = services.AddAuthentication();

            // Act
            builder.AddOneId();
            var provider = services.BuildServiceProvider();

            // Assert
            var schemes = provider.GetRequiredService<IAuthenticationSchemeProvider>();
            var scheme = schemes.GetSchemeAsync(OneIdAuthenticationDefaults.AuthenticationScheme).GetAwaiter().GetResult();
            Assert.NotNull(scheme);
            Assert.Equal(OneIdAuthenticationDefaults.DisplayName, scheme.DisplayName);
            Assert.NotNull(provider.GetService<JwtSecurityTokenHandler>()); // registered singleton
            Assert.NotNull(provider.GetService<IPostConfigureOptions<OneIdAuthenticationOptions>>());
            Assert.NotNull(provider.GetService<IHttpClientFactory>()); // AddHttpClient called
        }

        [Fact]
        public void AddOneId_With_Action_Configures_Options()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddLogging();
            var builder = services.AddAuthentication();
            bool configured = false;

            // Act
            builder.AddOneId(o => { configured = true; o.ClientId = "client"; o.ClientSecret = "secret"; o.ServiceProfileOptions = OneIdAuthenticationServiceProfiles.OLIS; });
            var sp = services.BuildServiceProvider();
            var monitor = sp.GetRequiredService<IOptionsMonitor<OneIdAuthenticationOptions>>();
            var options = monitor.Get(OneIdAuthenticationDefaults.AuthenticationScheme);

            // Assert
            Assert.True(configured);
            Assert.Equal("client", options.ClientId);
            Assert.Equal("secret", options.ClientSecret);
            Assert.Equal(OneIdAuthenticationServiceProfiles.OLIS, options.ServiceProfileOptions);
        }

        [Fact]
        public void AddOneId_Custom_Scheme_Registers_With_Caption()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddLogging();
            var builder = services.AddAuthentication();

            // Act
            builder.AddOneId("CustomScheme", "CustomCaption", o => { o.ClientId = "abc"; o.ClientSecret = "secret"; o.ServiceProfileOptions = OneIdAuthenticationServiceProfiles.DHDR; });
            var sp = services.BuildServiceProvider();
            var schemes = sp.GetRequiredService<IAuthenticationSchemeProvider>();
            var scheme = schemes.GetSchemeAsync("CustomScheme").GetAwaiter().GetResult();
            var monitor = sp.GetRequiredService<IOptionsMonitor<OneIdAuthenticationOptions>>();
            var options = monitor.Get("CustomScheme");

            // Assert
            Assert.NotNull(scheme);
            Assert.Equal("CustomCaption", scheme.DisplayName);
            Assert.Equal("abc", options.ClientId);
            Assert.Equal("secret", options.ClientSecret);
            Assert.Equal(OneIdAuthenticationServiceProfiles.DHDR, options.ServiceProfileOptions);
        }

        [Fact]
        public void AddOneId_Throws_If_Scheme_Null_Or_Empty()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = services.AddAuthentication();

            // Act & Assert - null scheme handled by ThrowIfNull (ArgumentNullException)
            Assert.Throws<ArgumentNullException>(() => builder.AddOneId(null!, _ => { }));
            var ex = Assert.Throws<ArgumentException>(() => builder.AddOneId(string.Empty, _ => { }));
            Assert.Equal("scheme", ex.ParamName);
        }

        [Fact]
        public void AddOneId_Throws_If_Configuration_Null()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = services.AddAuthentication();

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => builder.AddOneId(OneIdAuthenticationDefaults.AuthenticationScheme, null!));
            Assert.Throws<ArgumentNullException>(() => builder.AddOneId("Scheme", "Caption", null!));
        }

        [Fact]
        public void AddOneId_Throws_If_Builder_Null()
        {
            // Arrange
            AuthenticationBuilder builder = null!;

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => builder.AddOneId());
            Assert.Throws<ArgumentNullException>(() => builder.AddOneId(_ => { }));
            Assert.Throws<ArgumentNullException>(() => builder.AddOneId("a", _ => { }));
            Assert.Throws<ArgumentNullException>(() => builder.AddOneId("a", "b", _ => { }));
        }
#endif
    }
}
