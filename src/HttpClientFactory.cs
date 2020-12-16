using System.Net.Http;

namespace Benner.Tecnologia.OpenIDConnect
{
    /// <summary>
    /// Factory para fornecer uma instância de HttpClient saudável
    /// </summary>
    public static class HttpClientFactory
    {
        private static HttpClientEx _client = new HttpClientEx();
        /// <summary>
        /// Recupera uma instância de HttpClient saudável
        /// </summary>
        public static HttpClientEx Instance
        {
            get
            {
                if (_client.Disposed)
                    _client = new HttpClientEx();
                return _client;
            }
        }
        /// <summary>
        /// HttpClient que permite descobrir se está saudável ou não sem a necessidade de emitir uma ObjectDisposedException
        /// </summary>
        public class HttpClientEx : HttpClient
        {
            /// <summary>
            /// Despeja o objeto
            /// </summary>
            /// <param name="disposing"></param>
            protected override void Dispose(bool disposing)
            {
                if (disposing && !Disposed)
                    Disposed = true;
                base.Dispose(disposing);
            }
            /// <summary>
            /// Indica se esse objeto está ou não despejado
            /// </summary>
            public bool Disposed { get; private set; }
        }
    }
}
