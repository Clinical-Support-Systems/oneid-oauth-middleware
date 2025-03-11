using JustEat.HttpClientInterception;
using Microsoft.Extensions.Http;

namespace AspNet.Security.OAuth.Providers.Tests.Infrastructure
{
    /// <summary>
    /// Registers an delegating handler to intercept HTTP requests made by the test application.
    /// </summary>
    internal sealed class HttpRequestInterceptionFilter : IHttpMessageHandlerBuilderFilter
    {
        private readonly HttpClientInterceptorOptions _options;

        internal HttpRequestInterceptionFilter(HttpClientInterceptorOptions options)
        {
            _options = options;
        }

        public Action<HttpMessageHandlerBuilder> Configure(Action<HttpMessageHandlerBuilder> next)
        {
            return builder =>
            {
                next(builder);
                builder.AdditionalHandlers.Add(_options.CreateHttpMessageHandler());
            };
        }
    }
}