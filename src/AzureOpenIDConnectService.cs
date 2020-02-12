using Benner.Tecnologia.Common.Services;
using IdentityModel.Client;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;

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

        /// <summary>
        /// Translate group.Id list received on id_token into group.DisplayName list
        /// </summary>
        /// <param name="groupIdList"></param>
        /// <returns></returns>
        public override List<string> TranslateGroupNames(List<string> groupIdList)
        {
            //
            // validations
            if (groupIdList == null || groupIdList.Count == 0)
                return groupIdList;

            if (string.IsNullOrEmpty(Configuration.ClientID))
                throw new InvalidOperationException("A configuração 'ClientID' não pode ser vazia.");

            if (string.IsNullOrEmpty(Configuration.ClientSecret))
                throw new InvalidOperationException("A configuração 'ClientSecret' não pode ser vazia.");

            if (string.IsNullOrEmpty(Configuration.TokenEndpoint))
                throw new InvalidOperationException("A configuração 'TokenEndpoint' não pode ser vazia.");

            if (string.IsNullOrEmpty(Configuration.TenantID))
                throw new InvalidOperationException("A configuração 'TenantID' não pode ser vazia.");

            // acquire a brand new access_token via client_credentials, especificly to ms graph api
            var clientCredentialsRequest = new ClientCredentialsTokenRequest();
            clientCredentialsRequest.Address = Configuration.TokenEndpoint;
            clientCredentialsRequest.ClientId = Configuration.ClientID;
            clientCredentialsRequest.Scope = "https://graph.microsoft.com/.default";
            clientCredentialsRequest.ClientSecret = Configuration.ClientSecret;

            var accessTokenResponse = _httpClient.RequestClientCredentialsTokenAsync(clientCredentialsRequest).Result;
            if (accessTokenResponse.IsError)
                throw new InvalidOperationException($"Falha ao recuperar AcessToken. {accessTokenResponse.Error}: {accessTokenResponse.ErrorDescription}");

            // set access_token on httpclient
            _httpClient.SetBearerToken(accessTokenResponse.AccessToken);

            var result = new List<string>(groupIdList.Count);
            
            // query ms graph api to recover group info
            foreach (var groupId in groupIdList)
            {
                var url = $"https://graph.microsoft.com/v1.0/{Configuration.TenantID}/groups/{groupId}";
                var groupResponse = _httpClient.GetAsync(url).Result;
                if (!groupResponse.IsSuccessStatusCode)
                    throw new InvalidOperationException($"Falha ao recuperar grupo. {groupResponse.ReasonPhrase}");

                var jsonString = groupResponse.Content.ReadAsStringAsync().Result;
                var group = JsonConvert.DeserializeObject<dynamic>(jsonString);
                if (group?.displayName?.Value == null)
                    throw new InvalidOperationException($"Grupo inválido");

                // get group display name
                result.Add(group.displayName.Value);
            }

            return result;
        }
    }
}