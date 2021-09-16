using System;
using System.Runtime.Serialization;

namespace AspNet.Security.OAuth.OneID
{
    [Serializable]
    public class OneIdAuthenticationException : Exception
    {
        public OneIdAuthenticationException()
        {
        }

        public OneIdAuthenticationException(string message) : base(message)
        {
        }

        public OneIdAuthenticationException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected OneIdAuthenticationException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}