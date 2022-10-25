#if NETCORE
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace AspNet.Security.OAuth.OneID
{
    internal static class LoggerExtensions
    {
        private static readonly Action<ILogger, string?, Exception?> _logAccessToken = LoggerMessage.Define<string?>(
                logLevel: LogLevel.Trace,
                eventId: 1,
                formatString: "Access Token: {AccessToken}");

        private static readonly Action<ILogger, string?, Exception?> _logRefreshToken = LoggerMessage.Define<string?>(
                logLevel: LogLevel.Trace,
                eventId: 2,
                formatString: "Refresh Token: {RefreshToken}");

        private static readonly Action<ILogger, string?, Exception?> _logTokenType = LoggerMessage.Define<string?>(
               logLevel: LogLevel.Trace,
               eventId: 3,
               formatString: "Token Type: {TokenType}");

        private static readonly Action<ILogger, string?, Exception?> _logExpiresIn = LoggerMessage.Define<string?>(
               logLevel: LogLevel.Trace,
               eventId: 4,
               formatString: "Expires In: {ExpiresIn}");

        private static readonly Action<ILogger, string?, Exception?> _logIdToken = LoggerMessage.Define<string?>(
               logLevel: LogLevel.Trace,
               eventId: 5,
               formatString: "ID Token: {IdToken}");

        private static readonly Action<ILogger, JsonElement?, Exception?> _logTokenResponse = LoggerMessage.Define<JsonElement?>(
               logLevel: LogLevel.Trace,
               eventId: 6,
               formatString: "Token Response: {TokenResponse}");

        private static readonly Action<ILogger, HttpStatusCode, string?, string, Exception?> _logBackchannelException = LoggerMessage.Define<HttpStatusCode, string?, string>(
               logLevel: LogLevel.Error,
               eventId: 7,
               formatString: "An error occurred while retrieving an access token: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.");

        private static readonly Action<ILogger, HttpStatusCode, string?, string, Exception?> _logUserInfoException = LoggerMessage.Define<HttpStatusCode, string?, string>(
               logLevel: LogLevel.Error,
               eventId: 7,
               formatString: "An error occurred while retrieving the user profile: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.");

        private static readonly Action<ILogger, string, string, Exception?> _tokenValidationFailed = LoggerMessage.Define<string, string>(
            logLevel: LogLevel.Error, 
            eventId: 8, 
            formatString: "OneID token validation failed for issuer {TokenIssuer} and audience {TokenAudience}.");

        private static readonly Action<ILogger, string, Exception?> _tokenInvalid = LoggerMessage.Define<string>(
            logLevel: LogLevel.Trace,
            eventId: 9,
            formatString: "OneID token {IdToken} could not be validated.");

        public static void TokenValidationFailed(this ILogger logger, Exception exception, string tokenIssuer, string tokenAudience)
        {
            _tokenValidationFailed(logger, tokenIssuer, tokenAudience, exception);
        }

        public static void TokenInvalid(this ILogger logger, Exception exception, string idToken)
        {
            _tokenInvalid(logger, idToken, exception);
        }

        public static void LogAccessToken(
            this ILogger logger, string? accessToken)
        {
            if (!string.IsNullOrEmpty(accessToken))
                _logAccessToken(logger, accessToken, null);
        }

        public static void LogRefreshToken(
            this ILogger logger, string? refreshToken)
        {
            if (!string.IsNullOrEmpty(refreshToken))
                _logRefreshToken(logger, refreshToken, null);
        }

        public static void LogTokenType(
            this ILogger logger, string? tokenType)
        {
            if (!string.IsNullOrEmpty(tokenType))
                _logTokenType(logger, tokenType, null);
        }

        public static void LogTokenExpiry(
            this ILogger logger, string? expiresIn)
        {
            if (!string.IsNullOrEmpty(expiresIn))
                _logExpiresIn(logger, expiresIn, null);
        }

        public static void LogIdToken(
            this ILogger logger, string? idToken)
        {
            if (!string.IsNullOrEmpty(idToken))
                _logIdToken(logger, idToken, null);
        }

        public static void LogTokenResponse(
            this ILogger logger, JsonElement? tokenResponse)
        {
            if (tokenResponse != null)
                _logTokenResponse(logger, tokenResponse, null);
        }

        public static void LogBackchannelFailure(
            this ILogger logger, HttpStatusCode statusCode, string? headers, string body, Exception? exception = null)
        {
            _logBackchannelException(logger, statusCode, headers, body, exception);
        }

        public static void LogUserInfoFailure(
            this ILogger logger, HttpStatusCode statusCode, string? headers, string body, Exception? exception = null)
        {
            _logUserInfoException(logger, statusCode, headers, body, exception);
        }
    }
}
#endif