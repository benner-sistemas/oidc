using Benner.Tecnologia.Common.Services;
using System.Configuration;

namespace Benner.Tecnologia.OpenIDConnect
{
    public class OpenIDConnectConfiguration : IOpenIDConnectConfiguration
    {
        public string TokenEndpoint => ConfigurationManager.AppSettings["oidc-token-endpoint"];

        public string UserinfoEndpoint => ConfigurationManager.AppSettings["oidc-userinfo-endpoint"];

        public string ClientID => ConfigurationManager.AppSettings["oidc-client-id"];

        public string ClientSecret => ConfigurationManager.AppSettings["oidc-client-secret"];
    }
}
