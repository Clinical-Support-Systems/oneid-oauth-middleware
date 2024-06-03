using System;
using System.Net;
using System.Runtime.Serialization;

namespace AspNet.Security.OAuth.OneID
{
    [Serializable]
    public class OneIdAuthException : Exception
    {
        private const string DefaultMessage = "There was an issue authenticating with OneID.";

        public OneIdAuthException(string message) : base(message)
        {
        }

        public OneIdAuthException(string message, Exception innerException) : base(message, innerException)
        {
        }

        public OneIdAuthException() : base(DefaultMessage)
        {
        }

        public OneIdAuthException(Uri? url, HttpStatusCode statusCode, string responseContent) : base($"There was a {statusCode} issue authenticating with OneID at '{url}'.")
        {
            Url = url;
            StatusCode = statusCode;
            ResponseContent = responseContent;
        }

        protected OneIdAuthException(SerializationInfo serializationInfo, StreamingContext streamingContext)
#if !NET8_0_OR_GREATER
            : base(serializationInfo, streamingContext)
#endif
        {
#if NETCORE
            ArgumentNullException.ThrowIfNull(serializationInfo);
#else
            if (serializationInfo is null)
            {
                throw new ArgumentNullException(nameof(serializationInfo));
            }
#endif

            Url = (Uri)serializationInfo.GetValue(nameof(Url), typeof(Uri))!;
            StatusCode = (HttpStatusCode)serializationInfo.GetValue(nameof(StatusCode), typeof(HttpStatusCode))!;
            ResponseContent = (string)serializationInfo.GetValue(nameof(ResponseContent), typeof(string))!;
        }

        public string? ResponseContent { get; }
        public HttpStatusCode StatusCode { get; }
        public Uri? Url { get; }

#if !NET8_0_OR_GREATER
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            base.GetObjectData(info, context);

            info.AddValue(nameof(Url), Url, typeof(Uri));
            info.AddValue(nameof(StatusCode), StatusCode, typeof(HttpStatusCode));
            info.AddValue(nameof(ResponseContent), ResponseContent, typeof(string));
        }
#endif
    }
}