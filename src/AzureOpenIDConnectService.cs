using IdentityModel.Client;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;

namespace Benner.Tecnologia.OpenIDConnect
{
    public class AzureOpenIDConnectService : OpenIDConnectServiceBase
    {
        protected override string[] PossibleUsernameKeys => new string[] { "username", "preferred_username", "upn" };

        /// <summary>
        /// Requests access_token based on user name and password
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="password"></param>
        public override string GrantPasswordAccessToken(string userName, string password)
        {
            return base.GetTokenResponse(userName, password, "openid profile email").AccessToken;
        }

        /// <summary>
        /// Requests id_token based on user name and password
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="password"></param>
        public override string GrantPasswordIdentityToken(string userName, string password)
        {
            return base.GetTokenResponse(userName, password, "openid profile email").IdentityToken;
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