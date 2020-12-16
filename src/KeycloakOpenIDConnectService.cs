using Benner.Tecnologia.Common.Services;
using IdentityModel.Client;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.IdentityModel.Tokens.Jwt;

namespace Benner.Tecnologia.OpenIDConnect
{
    public class KeycloakOpenIDConnectService : OpenIDConnectServiceBase
    {
        protected override string[] PossibleUsernameKeys => new string[] { "username", "preferred_username" };

        /// <summary>
        /// Requests access_token based on user name and password
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="password"></param>
        public override string GrantPasswordAccessToken(string userName, string password)
        {
            return base.GetTokenResponse(userName, password, "openid profile email updated_at groups").AccessToken;
        }

        /// <summary>
        /// Requests id_token based on user name and password
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="password"></param>
        public override string GrantPasswordIdentityToken(string userName, string password)
        {
            return base.GetTokenResponse(userName, password, "openid profile email updated_at groups").IdentityToken;
        }

        public override void ValidateJwtSecutiryToken(JwtSecurityToken jwtSecurityToken)
        {
            if (string.IsNullOrEmpty(Configuration.JsonWebKeySetEndpoint))
                throw new InvalidOperationException("A configuração 'JsonWebKeySetEndpoint' não pode ser vazia.");

            var keysResponse = HttpClientFactory.Instance.GetAsync(Configuration.JsonWebKeySetEndpoint).Result;
            if (!keysResponse.IsSuccessStatusCode)
                throw new InvalidOperationException($"Falha ao recuperar JsonWebKeySet");

            var rawKeys = keysResponse.Content.ReadAsStringAsync().Result;
            if (string.IsNullOrEmpty(rawKeys))
                throw new InvalidOperationException($"JsonWebKeySet recebido está vazio");

            Microsoft.IdentityModel.Tokens.JsonWebKeySet jsonWebKeySet = JsonConvert.DeserializeObject<Microsoft.IdentityModel.Tokens.JsonWebKeySet>(rawKeys);
            if (jsonWebKeySet == null)
                throw new InvalidOperationException($"JsonWebKeySet recebido está nulo");

            if (string.IsNullOrEmpty(Configuration.Issuer))
                throw new InvalidOperationException("A configuração 'Issuer' não pode ser vazia.");

            if (string.IsNullOrEmpty(Configuration.ClientID))
                throw new InvalidOperationException("A configuração 'ClientID' não pode ser vazia.");

            if (!_jwtSecurityTokenHandler.CanValidateToken)
                throw new InvalidOperationException("SecurityTokenHandler não pode validar o token");


            var validationParameters = new TokenValidationParameters
            {
                ValidIssuer = Configuration.Issuer,
                ValidAudiences = new[] { Configuration.ClientID },
                IssuerSigningKeys = jsonWebKeySet.GetSigningKeys(),
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,
            };

            var claimsPrincipal = _jwtSecurityTokenHandler.ValidateToken(jwtSecurityToken.RawData, validationParameters, out SecurityToken validatedToken);

            if (claimsPrincipal == null)
                throw new InvalidOperationException("ClaimsPrincipal está nulo");

            if (!(validatedToken is JwtSecurityToken))
                throw new InvalidOperationException("ValidatedToken está nulo ou inválido");
        }
    }
}