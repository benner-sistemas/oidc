using Benner.Tecnologia.Common.Services;
using IdentityModel.Client;
using System;
using System.Net.Http;

namespace Benner.Tecnologia.OpenIDConnect
{
    public class OpenIDConnectService : IOpenIDConnectService
    {
        public IOpenIDConnectConfiguration Configuration { get; set; }

        private static readonly HttpClient _httpClient = new HttpClient();

        public string GrantPasswordAccessToken(string userName, string password)
        {
            if (Configuration == null)
                throw new InvalidOperationException("OpenIDConnectServiceConfiguration not found");

            var request = new PasswordTokenRequest
            {
                Address = Configuration.TokenEndpoint,
            
                ClientId = Configuration.ClientID,
                ClientSecret = Configuration.ClientSecret,
            
                UserName = userName,
                Password = password,
            
                Scope = "openid profile email updated_at groups",
            };

            var passwordResponse = _httpClient.RequestPasswordTokenAsync(request).Result;
            if (passwordResponse.IsError)
            {
                throw new InvalidOperationException(passwordResponse.Error);
            }

            return passwordResponse.AccessToken;
        }
    }
}