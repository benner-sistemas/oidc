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

        public string Issuer => ConfigurationManager.AppSettings["oidc:Issuer"];

        public string Certificate => ConfigurationManager.AppSettings["oidc:Certificate"];

        public void Validate()
        {
            var msg = "{0} not found or empty in configuration.";

            if (string.IsNullOrWhiteSpace(TokenEndpoint))
                throw new SettingsPropertyNotFoundException(string.Format(msg, nameof(TokenEndpoint)));

            if (string.IsNullOrWhiteSpace(UserInfoEndpoint))
                throw new SettingsPropertyNotFoundException(string.Format(msg, nameof(UserInfoEndpoint)));

            if (string.IsNullOrWhiteSpace(ClientID))
                throw new SettingsPropertyNotFoundException(string.Format(msg, nameof(ClientID)));

            if (string.IsNullOrWhiteSpace(ClientSecret))
                throw new SettingsPropertyNotFoundException(string.Format(msg, nameof(ClientSecret)));

            if (string.IsNullOrWhiteSpace(Issuer))
                throw new SettingsPropertyNotFoundException(string.Format(msg, nameof(Issuer)));

            if (string.IsNullOrWhiteSpace(Certificate))
                throw new SettingsPropertyNotFoundException(string.Format(msg, nameof(Certificate)));
        }
    }
}
