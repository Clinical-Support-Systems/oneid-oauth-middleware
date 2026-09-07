using System;
using Microsoft.Owin.Security.DataProtection;

namespace AspNet.Security.OAuth.OneID.NetFull.Tests.Infrastructure
{
    /// <summary>
    /// A test-only <see cref="IDataProtector"/> that performs a genuine byte-array round trip.
    /// It provides no confidentiality whatsoever: <see cref="Protect"/> and <see cref="Unprotect"/>
    /// each return a defensive copy of the bytes they were given.
    /// </summary>
    /// <remarks>
    /// This exists purely so that <c>Microsoft.Owin.Security.DataHandler.PropertiesDataFormat</c>
    /// (which does the real work of serializing an <c>AuthenticationProperties</c> instance to and
    /// from a byte array) can be exercised end to end without a real key ring. Because this type
    /// only ever sees serialized <c>byte[]</c> data - never the live <c>AuthenticationProperties</c>
    /// object - a test built on it cannot accidentally pass by handing back a reference to the
    /// original in-memory properties instance.
    /// </remarks>
    internal sealed class PassthroughDataProtector : IDataProtector
    {
        public byte[] Protect(byte[] userData)
        {
            if (userData is null)
            {
                throw new ArgumentNullException(nameof(userData));
            }

            var copy = new byte[userData.Length];
            Array.Copy(userData, copy, userData.Length);
            return copy;
        }

        public byte[] Unprotect(byte[] protectedData)
        {
            if (protectedData is null)
            {
                throw new ArgumentNullException(nameof(protectedData));
            }

            var copy = new byte[protectedData.Length];
            Array.Copy(protectedData, copy, protectedData.Length);
            return copy;
        }
    }
}
