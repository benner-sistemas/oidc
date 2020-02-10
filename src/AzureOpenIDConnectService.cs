using Benner.Tecnologia.Common.Services;
using IdentityModel.Client;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.IdentityModel.Tokens.Jwt;

namespace Benner.Tecnologia.OpenIDConnect
{
    public class AzureOpenIDConnectService : OpenIDConnectServiceBase
    {
        public override string GrantPasswordAccessToken(string userName, string password)
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

        public override UserInfo RecoverUserInfoFromJwtPayload(JwtPayload jwtPayload)
        {
            var result = new UserInfo();
            result.Name = jwtPayload["name"] as string ?? throw new InvalidOperationException($"Property 'name' not found at user info (id_token) from Identity Server");

            if (jwtPayload.ContainsKey("username"))
                result.UserName = jwtPayload["username"] as string;
            else if (jwtPayload.ContainsKey("preferred_username"))
                result.UserName = jwtPayload["preferred_username"] as string;
            else
                throw new InvalidOperationException("id_token incompleto, 'username' ou 'preferred_username' não foi encontrado");

            if (jwtPayload.ContainsKey("email"))
                result.Email = jwtPayload["email"] as string;
            else if (result.UserName.Contains("@"))
                result.Email = result.UserName;
            else
                throw new InvalidOperationException("id_token incompleto, 'email' não foi encontrado");

            if (jwtPayload.ContainsKey("groups"))
            {
                var rawGroups = jwtPayload["groups"] as JArray ?? throw new InvalidOperationException($"Property 'groups' not found at user info (id_token) from Identity Server");
                foreach (var group in rawGroups)
                    result.Groups.Add(group.ToString());
            }

            return result;
        }

        public override void ValidateJwtSecutiryToken(JwtSecurityToken jwtSecurityToken)
        {
            if (string.IsNullOrEmpty(Configuration.JsonWebKeySetEndpoint))
                throw new InvalidOperationException("A configuração 'JsonWebKeySetEndpoint' não pode ser vazia.");

            var keysResponse = _httpClient.GetAsync(Configuration.JsonWebKeySetEndpoint).Result;
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