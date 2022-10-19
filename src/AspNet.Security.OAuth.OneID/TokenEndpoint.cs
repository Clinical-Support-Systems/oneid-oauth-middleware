#region License, Terms and Conditions

//
// TokenEndpoint.cs
//
// Authors: Kori Francis <twitter.com/korifrancis>
// Copyright (C) 2020 Clinical Support Systems, Inc. All rights reserved.
//
//  THIS FILE IS LICENSED UNDER THE MIT LICENSE AS OUTLINED IMMEDIATELY BELOW:
//
//  Permission is hereby granted, free of charge, to any person obtaining a
//  copy of this software and associated documentation files (the "Software"),
//  to deal in the Software without restriction, including without limitation
//  the rights to use, copy, modify, merge, publish, distribute, sublicense,
//  and/or sell copies of the Software, and to permit persons to whom the
//  Software is furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//  DEALINGS IN THE SOFTWARE.
//

#endregion License, Terms and Conditions

namespace AspNet.Security.OAuth.OneID
{
#if NETFULL
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;
#else

    using System.Text.Json;
    using System.Text.Json.Serialization;
    using System.Buffers;

#endif

    using System;
    using System.Globalization;

    /// <summary>
    /// The access_token endpoint return data
    /// </summary>
    public partial class TokenEndpoint
    {
        /// <summary>
        /// The access token
        /// </summary>
#if NETFULL
        [JsonProperty("access_token")]
#else

        [JsonPropertyName("access_token")]
#endif
        public string AccessToken { get; set; } = string.Empty;

        /// <summary>
        /// The refresh token
        /// </summary>
#if NETFULL
        [JsonProperty("refresh_token")]
#else

        [JsonPropertyName("refresh_token")]
#endif
        public string RefreshToken { get; set; } = string.Empty;

        /// <summary>
        /// The oauth scope
        /// </summary>
#if NETFULL
        [JsonProperty("scope")]
#else

        [JsonPropertyName("scope")]
#endif
        public string Scope { get; set; } = string.Empty;

        /// <summary>
        /// The returned context session id
        /// </summary>
#if NETFULL
        [JsonProperty("contextSessionId")]
#else

        [JsonPropertyName("contextSessionId")]
#endif
        public string ContextSessionId { get; set; } = string.Empty;

        /// <summary>
        /// The id token
        /// </summary>
#if NETFULL
        [JsonProperty("id_token")]
#else

        [JsonPropertyName("id_token")]
#endif
        public string IdToken { get; set; } = string.Empty;

        /// <summary>
        /// The token type
        /// </summary>
#if NETFULL
        [JsonProperty("token_type")]
#else

        [JsonPropertyName("token_type")]
#endif
        public string TokenType { get; set; } = string.Empty;

        /// <summary>
        /// How many seconds until the access_token expires
        /// </summary>
#if NETFULL
        [JsonProperty("expires_in")]
#else

        [JsonPropertyName("expires_in")]
#endif
        public long ExpiresIn { get; set; }

        /// <summary>
        /// Nonce
        /// </summary>
#if NETFULL
        [JsonProperty("nonce")]
#else

        [JsonPropertyName("nonce")]
#endif
        public string Nonce { get; set; } = string.Empty;
    }

    public partial class TokenEndpoint
    {
#if NETFULL
        public static TokenEndpoint? FromJson(string json) => JsonConvert.DeserializeObject<TokenEndpoint>(json, Converter.Settings);
#else

        /// <summary>
        /// Deserialize
        /// </summary>
        /// <param name="json">The json to deserialize</param>
        /// <returns>The <see cref="TokenEndpoint"/> object</returns>
        public static TokenEndpoint? FromJson(JsonElement json) => json.ToObject<TokenEndpoint>();

#endif
    }

#if NETCORE

    /// <summary>
    /// Extensions related to deserializing json
    /// </summary>
    public static partial class JsonExtensions
    {
        /// <summary>
        /// Deserialize
        /// </summary>
        /// <typeparam name="T">The type</typeparam>
        /// <param name="element">The json containing element</param>
        /// <param name="options">Serializer options</param>
        /// <returns>The object</returns>
        public static T? ToObject<T>(this JsonElement element, JsonSerializerOptions? options = null)
        {
            var bufferWriter = new ArrayBufferWriter<byte>();
            using (var writer = new Utf8JsonWriter(bufferWriter))
                element.WriteTo(writer);
            return System.Text.Json.JsonSerializer.Deserialize<T>(bufferWriter.WrittenSpan, options);
        }

        /// <summary>
        /// Deserialize
        /// </summary>
        /// <typeparam name="T">The type</typeparam>
        /// <param name="document">The json document</param>
        /// <param name="options">Serializer options</param>
        /// <returns>The object</returns>
        public static T? ToObject<T>(this JsonDocument document, JsonSerializerOptions? options = null)
        {
            if (document == null)
                throw new ArgumentNullException(nameof(document));
            return document.RootElement.ToObject<T>(options);
        }
    }

#endif

    /// <summary>
    /// Serialization extensions
    /// </summary>
    public static class Serialize
    {
#if NETFULL
        public static string ToJson(this TokenEndpoint self) => JsonConvert.SerializeObject(self, Converter.Settings);
#else

        /// <summary>
        /// Serialize <see cref="TokenEndpoint"/> to json string
        /// </summary>
        /// <param name="self">The object to serialize</param>
        /// <returns>The json string</returns>
        public static string ToJson(this TokenEndpoint self) => self.ToJson();

#endif
    }

#if NETFULL
    internal static class Converter
    {
        public static readonly JsonSerializerSettings Settings = new()
        {
            MetadataPropertyHandling = MetadataPropertyHandling.Ignore,
            DateParseHandling = DateParseHandling.None,
            Converters =
            {
                new IsoDateTimeConverter { DateTimeStyles = DateTimeStyles.AssumeUniversal }
            },
        };
    }
#endif
}