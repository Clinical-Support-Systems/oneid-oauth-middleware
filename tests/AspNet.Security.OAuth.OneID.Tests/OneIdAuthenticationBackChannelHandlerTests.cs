using AspNet.Security.OAuth.OneID;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static AspNet.Security.OAuth.OneID.OneIdAuthenticationConstants;

namespace AspNet.Security.OAuth.Providers.Tests
{
    public class OneIdAuthenticationBackChannelHandlerTests
    {
        [Fact]
        public void SendAsync_Throws_When_Both_Thumbprint_And_Filename_Specified()
        {
            var options = new OneIdAuthenticationOptions
            {
                ClientId = "client",
                CertificateThumbprint = "ABCDEF",
                CertificateFilename = "file.pfx" // both set
            };

            using var handler = new OneIdAuthenticationBackChannelHandler(options);

            var request = new HttpRequestMessage(HttpMethod.Post, "https://example.com/token")
            {
                Content = new StringContent("a=b")
            };

            // The invalid configuration exception is thrown asynchronously from the task, so it surfaces directly.
            var ex = Assert.Throws<InvalidOperationException>(() => InvokeSendAsync(handler, request).GetAwaiter().GetResult());
            ex.Message.ShouldContain("Cannot specify both CertificateThumbprint and CertificateFilename");
        }

        [Fact]
        public void SendAsync_Throws_When_No_Certificate_Configured()
        {
            var options = new OneIdAuthenticationOptions
            {
                ClientId = "client"
            }; // neither thumbprint nor filename

            using var handler = new OneIdAuthenticationBackChannelHandler(options);

            var request = new HttpRequestMessage(HttpMethod.Post, "https://example.com/token")
            {
                Content = new StringContent("a=b")
            };

            var ex = Assert.Throws<InvalidOperationException>(() => InvokeSendAsync(handler, request).GetAwaiter().GetResult());
            ex.Message.ShouldContain("Must specify CertificateThumbprint or CertificateFilename");
        }

        [Fact]
        public async Task SendAsync_Returns_NoContent_When_Request_Has_No_Content()
        {
            var (options, tempFile) = CreateOptionsWithTempCertificate();
            using var handler = new OneIdAuthenticationBackChannelHandler(options);
            using var request = new HttpRequestMessage(HttpMethod.Post, "https://localhost/token"); // no Content

            HttpResponseMessage? response = null;
            try
            {
                response = await InvokeSendAsync(handler, request);
            }
            catch (TargetInvocationException tie) when (tie.InnerException is HttpRequestException)
            {
                // Network failure not expected because early return occurs before base.SendAsync.
                throw; // rethrow to fail test
            }
            catch (HttpRequestException)
            {
                // Same as above - should not happen when no content.
                throw;
            }

            response.ShouldNotBeNull();
            response!.StatusCode.ShouldBe(System.Net.HttpStatusCode.NoContent);

            CleanupTempCertificate(tempFile);
        }

        [Fact]
        public async Task SendAsync_Rewrites_Form_Parameters_With_Jwt_ClientAssertion()
        {
            var (options, tempFile) = CreateOptionsWithTempCertificate();
            using var handler = new OneIdAuthenticationBackChannelHandler(options);

            const string original = "client_id=client&redirect_uri=https%3A%2F%2Fapp%2Fcb&grant_type=authorization_code&client_assertion_type=old_type&client_assertion=old_assertion&aud=old_audience&extra=1";
            using var request = new HttpRequestMessage(HttpMethod.Post, "https://localhost/token")
            {
                Content = new StringContent(original, Encoding.UTF8, "application/x-www-form-urlencoded")
            };

            // Invoke - expect network failure after mutation; capture exception
            try
            {
                await InvokeSendAsync(handler, request);
            }
            catch (HttpRequestException)
            {
                // Expected: base handler tried to send to localhost; mutations already applied.
            }
            catch (TargetInvocationException tie) when (tie.InnerException is HttpRequestException)
            {
                // Expected: base handler tried to send to localhost; mutations already applied.
                // Expected wrapped case.
            }

            string mutated = await request.Content!.ReadAsStringAsync();
            var dict = ParseForm(mutated);

            dict.ShouldContainKey("client_assertion_type");
            dict["client_assertion_type"].ShouldBe(ClaimNames.JwtBearerAssertion);

            dict.ShouldContainKey("client_assertion");
            var assertion = dict["client_assertion"];
            assertion.ShouldNotBe("old_assertion");
            assertion.Split('.').Length.ShouldBe(3); // JWT format

            dict.ShouldContainKey("aud");
            dict["aud"].ShouldBe(ClaimNames.ApiAudience);

            dict.ShouldContainKey("redirect_uri");
            dict["redirect_uri"].ShouldBe("https://app/cb"); // decoded

            // Ensure jti claim present inside JWT payload
            var payloadJson = DecodeJwtPayload(assertion);
            payloadJson.ShouldContain("\"jti\"");
            payloadJson.ShouldContain("\"iss\":\"client\"");
            payloadJson.ShouldContain("\"sub\":\"client\"");
            payloadJson.ShouldContain("\"aud\":\"" + options.Audience + "\"");

            CleanupTempCertificate(tempFile);
        }

        [Fact]
        public async Task SendAsync_Throws_ArgumentNull_When_Request_Is_Null()
        {
            var (options, tempFile) = CreateOptionsWithTempCertificate();
            using var handler = new OneIdAuthenticationBackChannelHandler(options);

            var method = typeof(OneIdAuthenticationBackChannelHandler).GetMethod("SendAsync", BindingFlags.Instance | BindingFlags.NonPublic);
            method.ShouldNotBeNull();

            var ex = await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            {
                var task = (Task<HttpResponseMessage>)method!.Invoke(handler, new object?[] { null!, CancellationToken.None })!;
                await task; // will fault
            });
            ex.ParamName.ShouldBe("request");

            CleanupTempCertificate(tempFile);
        }

        private static async Task<HttpResponseMessage> InvokeSendAsync(OneIdAuthenticationBackChannelHandler handler, HttpRequestMessage request)
        {
            var method = typeof(OneIdAuthenticationBackChannelHandler).GetMethod("SendAsync", BindingFlags.Instance | BindingFlags.NonPublic)!;
            var task = (Task<HttpResponseMessage>)method.Invoke(handler, new object[] { request, CancellationToken.None })!;
            return await task.ConfigureAwait(false);
        }

        private static (OneIdAuthenticationOptions options, string tempFile) CreateOptionsWithTempCertificate()
        {
            var passwordString = "TestPwd123!";
            var secure = new SecureString();
            foreach (var c in passwordString) secure.AppendChar(c);
            secure.MakeReadOnly();

            using var rsa = RSA.Create(2048);
            var req = new CertificateRequest("CN=OneIdTestCert", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
            var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            var bytes = cert.Export(X509ContentType.Pkcs12, passwordString);

            var tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".pfx");
            File.WriteAllBytes(tempPath, bytes);
            cert.Dispose();

            var options = new OneIdAuthenticationOptions
            {
                ClientId = "client",
                CertificateFilename = tempPath,
                CertificatePassword = secure,
                Environment = OneIdAuthenticationEnvironment.PartnerSelfTest
            };

            return (options, tempPath);
        }

        private static void CleanupTempCertificate(string path)
        {
            try
            {
                if (File.Exists(path)) File.Delete(path);
            }
            catch
            {
                // ignore
            }
        }

        private static Dictionary<string, string> ParseForm(string form)
        {
            return form.Split('&')
                       .Select(p => p.Split('='))
                       .Where(a => a.Length == 2)
                       .ToDictionary(a => a[0], a => Uri.UnescapeDataString(a[1]));
        }

        private static string DecodeJwtPayload(string jwt)
        {
            var parts = jwt.Split('.');
            if (parts.Length != 3) return string.Empty;
            string payload = parts[1];
            // Pad base64
            switch (payload.Length % 4)
            {
                case 2: payload += "=="; break;
                case 3: payload += "="; break;
            }
            var json = Encoding.UTF8.GetString(Convert.FromBase64String(payload.Replace('-', '+').Replace('_', '/')));
            return json;
        }
    }
}
