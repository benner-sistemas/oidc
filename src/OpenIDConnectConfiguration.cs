using Benner.Tecnologia.Common.Services;
using System.Configuration;

namespace Benner.Tecnologia.OpenIDConnect
{
    public class OpenIDConnectConfiguration : IOpenIDConnectConfiguration
    {
        public string TokenEndpoint => ConfigurationManager.AppSettings["oidc:TokenEndpoint"];

        public string UserInfoEndpoint => ConfigurationManager.AppSettings["oidc:UserInfoEndpoint"];

        public string ClientID => ConfigurationManager.AppSettings["oidc:ClientID"];

        public string ClientSecret => ConfigurationManager.AppSettings["oidc:ClientSecret"];
    }
}
