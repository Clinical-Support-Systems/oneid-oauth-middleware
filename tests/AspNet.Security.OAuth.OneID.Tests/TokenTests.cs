using AspNet.Security.OAuth.OneID;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AspNet.Security.OAuth.Providers.Tests
{
    public class TokenTests
    {
        [Fact]
        public async Task RefreshToken_Should_Return_New_AccessToken_Production()
        {
            var existingAccessToken = "eyJ0eXAiOiJKV1QiLCJraWQiOiI1OHo1UnFHMG44bFQvZGVCcTR2b2VrejEzVXc9IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJDQzZEODAzMzZGQzYwRDJERTA1NDAwMTQ0RkY5QTQ1MEBvbmVpZGZlZC5vbi5jYSIsImN0cyI6Ik9BVVRIMl9TVEFURUxFU1NfR1JBTlQiLCJhdXRoX2xldmVsIjowLCJhdWRpdFRyYWNraW5nSWQiOiIwOGRlMDEyZC05MTU5LTQ1Y2ItOWMzNi05ZWQ5YjRkZjEyYjAtMTU0NzA5NjgwIiwiaXNzIjoiaHR0cHM6Ly9sb2dpbi5vbmVpZGZlZGVyYXRpb24uZWhlYWx0aG9udGFyaW8uY2Evc3NvL29hdXRoMi9yZWFsbXMvcm9vdC9yZWFsbXMvaWRhYXNvaWRjIiwidG9rZW5OYW1lIjoiYWNjZXNzX3Rva2VuIiwidG9rZW5fdHlwZSI6IkJlYXJlciIsImF1dGhHcmFudElkIjoiNnBDMmpnZjVQemppbEcydFlTbTA3U3pMV0ZjIiwiYXVkIjpbIkNhYk1EX0NsaW5pY2FsU3VwcG9ydFN5c3RlbXNfWFhYWFgiLCJodHRwczovL3Byb3ZpZGVyLmVoZWFsdGhvbnRhcmlvLmNhIl0sIm5iZiI6MTcyNjc2NDE4OSwiZ3JhbnRfdHlwZSI6ImF1dGhvcml6YXRpb25fY29kZSIsInNjb3BlIjpbIm9wZW5pZCIsInVzZXIvTWVkaWNhdGlvbkRpc3BlbnNlLnJlYWQiLCJ1c2VyL0RpYWdub3N0aWNSZXBvcnQucmVhZCJdLCJhdXRoX3RpbWUiOjE3MjY3NjE1NTAsInJlYWxtIjoiL2lkYWFzb2lkYyIsImV4cCI6MTcyNjc2Nzc4OSwiaWF0IjoxNzI2NzY0MTg5LCJleHBpcmVzX2luIjozNjAwLCJqdGkiOiJ3TDR0eXJlN3BVSmdaejlrR1pMTEdrYkRXUUEiLCJnaXZlbl9uYW1lIjoiU3RlcGhlbiBBbmRyZXciLCJmYW1pbHlfbmFtZSI6IkxhSGF5ZSIsImVtYWlsIjoic3RlcGhlbmxhaGF5ZUBob3RtYWlsLmNvbSIsInJpZCI6WyJDUFNPOjY4MTE5Il0sInVzZXJuYW1lIjoiU1RFUEhFTkFORFJFVy5MQUhBWUVAT05FSUQuT04uQ0EiLCJhenAiOiJDYWJNRF9DbGluaWNhbFN1cHBvcnRTeXN0ZW1zX1hYWFhYIiwiaWRwIjoiMi4xNi44NDAuMS4xMTM4ODMuMy4yMzkuMzUuMy4xIiwidWFvIjoiMi4xNi44NDAuMS4xMTM4ODMuMy4yMzkuOToxMDQyODY2Mjg3NzEiLCJ1YW9OYW1lIjoiQ2xpbmljYWwgU3VwcG9ydCBTeXN0ZW1zIiwidWFvVHlwZSI6Ik9yZ2FuaXphdGlvbiIsIl9wcm9maWxlIjpbImh0dHA6Ly9laGVhbHRob250YXJpby5jYS9TdHJ1Y3R1cmVEZWZpbml0aW9uL2NhLW9uLWxhYi1wcm9maWxlLURpYWdub3N0aWNSZXBvcnQiLCJodHRwOi8vZWhlYWx0aG9udGFyaW8uY2EvU3RydWN0dXJlRGVmaW5pdGlvbi9jYS1vbi1kaGRyLXByb2ZpbGUtTWVkaWNhdGlvbkRpc3BlbnNlIl0sImFwaV9rZXlzIjpbIlN0M0VZWG01QzFpalVPMTJueEUrSFM0elBEMC9XZEtuMGJnNVIxazFJSm89Il0sIkROIjoiQ049Q0FCTUQuQ1NTLlBST0QsT1U9QXBwbGljYXRpb25zLE9VPWVIZWFsdGhVc2VycyxPVT1TdWJzY3JpYmVycyxEQz1zdWJzY3JpYmVycyxEQz1zc2giLCJ2ZXJzaW9uIjoiMS4wIiwic3RhdGUiOiJDZkRKOEpEX3ltUlNRY2xNbDhpLUtOeS1YY2V2enR5N21BQVRFNkxnbDdDOHJCX1pTZWNWR0NKZmdzNVBuM2F6MVEwNVJLSVVtSGp5NW9sc1pYN21TXzlxdnVESi1fQ2JGNVU4YWxjcktBNGkzRGVXTnkxMHVwVUg5M0FRdGNRSnN4U2NEd0Ixa3U4bWttTFpvVEhSN3BXOFNqaHJVdUJINXdvZDgzNlhFVDFKVHR3QXM4VW9hd0dPRFZaQVhNbjlpVkZHVUt4Zi1rRHZLNDJrRkNmZXdCdl83RkNfNzJYVkR2MFRJeHF3cDhfd1pmNk82SzZWZ1diWmJlbDZTRXBkZ05leXJTa1hTWXhMZ2I1c3QzaTF3ZElScEl6UmlCSC1UcEExeWpIRnVqSXNxM3lUZTV4eUpIU2tDZ2k2eG0yVllfTmxrTFhtX0V5U3JDYWJMQml6X0l3RTZWaTQ2MWRZS1RHODVVcXJsZ0o1SXFzWDhqTEFIRGhnMEpIODFCTVRnOEU0aVBfR1ZyMEJ3YzlTQUNDa0s3bFloRDgifQ.dHFS3ljGdZIGIxOWI4qJQFO2y-jkpY8BnNBNGp2y4Ch7JN7IwaCcah_a12mIOXkc3AU_2wcNTeFlnRk9oZO3h_SNICwMCFwEAywShEdwD-VrUcvnIO-p8qPLloKf1_ZkVMBsbkawW5FD4i7oTb8deZiuuoHPjhEVqAlJnPS8Qw8rP3DnLdfx_QY57pyuCjyP6HkjrTUZYicY8YG0-ejmDU3C2hkj6gIlGWEbtKAKGqUIStGNmG-1W9IKuvCKPTTldTgukuDH6Pem6DjC2zwWweI-08C8bBLST1CVp2z3JB6PdBKldTjMy5YiZwsYSFw-IytZhOiw4_1PX-GygML8Og";
            var refreshToken = "eyJ0eXAiOiJKV1QiLCJraWQiOiI1OHo1UnFHMG44bFQvZGVCcTR2b2VrejEzVXc9IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiI2Mjk0ZGE1Zi1jMTAxLTRmZDgtOWNmMS1lMmU3MzE2YWZmZjUiLCJjdHMiOiJPQVVUSDJfU1RBVEVMRVNTX0dSQU5UIiwiYXV0aF9sZXZlbCI6MCwiYXVkaXRUcmFja2luZ0lkIjoiMDhkZTAxMmQtOTE1OS00NWNiLTljMzYtOWVkOWI0ZGYxMmIwLTE1NDcwOTY3OSIsImlzcyI6Imh0dHBzOi8vbG9naW4ub25laWRmZWRlcmF0aW9uLmVoZWFsdGhvbnRhcmlvLmNhL3Nzby9vYXV0aDIvcmVhbG1zL3Jvb3QvcmVhbG1zL2lkYWFzb2lkYyIsInRva2VuTmFtZSI6InJlZnJlc2hfdG9rZW4iLCJhdXRoTW9kdWxlcyI6Ik9uZUlEU0FNTHxVQU9TZWxlY3RvckF1dGhNb2QiLCJ0b2tlbl90eXBlIjoiQmVhcmVyIiwiYXV0aEdyYW50SWQiOiI2cEMyamdmNVB6amlsRzJ0WVNtMDdTekxXRmMiLCJhdWQiOiJDYWJNRF9DbGluaWNhbFN1cHBvcnRTeXN0ZW1zX1hYWFhYIiwiYWNyIjoiMCIsIm5iZiI6MTcyNjc2NDE4OSwib3BzIjoiWWFVTk9zNzltdm9kSG1HT04zY203T1FQQkRnIiwiZ3JhbnRfdHlwZSI6ImF1dGhvcml6YXRpb25fY29kZSIsInNjb3BlIjpbIm9wZW5pZCIsInVzZXIvTWVkaWNhdGlvbkRpc3BlbnNlLnJlYWQiLCJ1c2VyL0RpYWdub3N0aWNSZXBvcnQucmVhZCJdLCJhdXRoX3RpbWUiOjE3MjY3NjE1NTAsInJlYWxtIjoiL2lkYWFzb2lkYyIsImV4cCI6MTcyNzM2ODk4OSwiaWF0IjoxNzI2NzY0MTg5LCJleHBpcmVzX2luIjo2MDQ4MDAsImp0aSI6ImNMYXRFV283OHVKZGphTlZmSnU4RFlqenNaNCJ9.MFDbAz2NrX_UatGA3_i1mnUGWX1REIWdb2R3OySMHvh5-HJBrP1ytpdRxirDc-OzanJtE_kaFvLUsFhMGLZueiZPpWAdF5NKx2VL53kB4jfR0ugMbxOigmvPOCQQEiMEVu7fMD4ZcLSoBs-cWBcLv-T4Usbu7F1GeAzGBxn_oPDSbp9jX15CP_jZbT4DR2u9Vi0xfOIAzFNyAIUkbgEVfizVG12Cf0oe0QBTXkq-0lwC-iA_STMNU42jFqwl6Fq-sK-ks3XxdhuMsqVVk-ojwfDot297AfLKd6T1hrh3WrQUJQgj431-hCltb5Xa3O_qvzfUxm4tUWRJusH-5SthsQ";
            var pfxPassword = new System.Security.SecureString();
            "!@cl1n1c4l".ToCharArray().ToList().ForEach(pfxPassword.AppendChar);

            // Set up production environment options
            var options = new OneIdAuthenticationOptions
            {
                ClientId = "CabMD_ClinicalSupportSystems_XXXXX",
                CertificateFilename = "CABMD.CSS.PROD-combined.pfx",
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
