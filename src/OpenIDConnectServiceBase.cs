using Benner.Tecnologia.Common.Services;
using IdentityModel.Client;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;

namespace Benner.Tecnologia.OpenIDConnect
{
    public abstract class OpenIDConnectServiceBase : IOpenIDConnectService
    {
        private IOpenIDConnectConfiguration _configuration;
        public IOpenIDConnectConfiguration Configuration
        {
            get { return _configuration; }
            set
            {
                _configuration = value;
                _configuration?.Validate();
            }
        }

        protected readonly static JwtSecurityTokenHandler _jwtSecurityTokenHandler = new JwtSecurityTokenHandler();

        protected abstract string[] PossibleUsernameKeys { get; }

        ~OpenIDConnectServiceBase()
        {
            HttpClientFactory.Instance.Dispose();
        }

        public abstract string GrantPasswordAccessToken(string userName, string password);

        public abstract string GrantPasswordIdentityToken(string userName, string password);

        protected TokenResponse GetTokenResponse(string userName, string password, string scopes)
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
                Scope = scopes,
            };

            var passwordResponse = HttpClientFactory.Instance.RequestPasswordTokenAsync(request).Result;
            if (passwordResponse.IsError)
                throw new InvalidOperationException(passwordResponse.Error);

            return passwordResponse;
        }

        public abstract void ValidateJwtSecutiryToken(JwtSecurityToken jwtSecurityToken);

        public virtual UserInfo RecoverUserInfoFromJwtPayload(JwtPayload jwtPayload)
        {
            var result = new UserInfo();
            result.Name = jwtPayload["name"] as string
                ?? throw new InvalidOperationException($"id_token incompleto: a propriedade 'name' não foi encontrada no token");

            string foundKey = jwtPayload.Keys.FirstOrDefault(x => PossibleUsernameKeys.Contains(x))
                ?? throw new InvalidOperationException($"id_token incompleto: uma das propriedades {string.Join(", ", PossibleUsernameKeys.Select(x => $"'{x}'"))} não foram encontradas  no token");
            result.UserName = jwtPayload[foundKey] as string;

            if (jwtPayload.ContainsKey("email"))
                result.Email = jwtPayload["email"] as string;
            else if (result.UserName.Contains("@"))
                result.Email = result.UserName;
            else
                throw new InvalidOperationException("id_token incompleto: a propriedade 'email' não foi encontrada no token");

            if (jwtPayload.ContainsKey("groups"))
            {
                JArray rawGroups = jwtPayload["groups"] as JArray
                    ?? throw new InvalidOperationException($"id_token incompleto: a propriedade 'groups' não foi encontrada no token");
                result.Groups = TranslateGroupNames(rawGroups.Values<string>().ToList());
            }

            return result;
        }

        public virtual UserInfo RecoverUserInfoFromIdentityServer(string accessToken)
        {
            //
            // request for id_token
            var userInfoResponse = HttpClientFactory.Instance.GetUserInfoAsync(new UserInfoRequest
            {
                Address = Configuration.UserInfoEndpoint,
                Token = accessToken,
            }).Result;

            if (userInfoResponse.IsError)
                throw new InvalidOperationException($"Identity Server returned invalid user info (id_token) from '{Configuration.UserInfoEndpoint}' response '{userInfoResponse.Raw}'");

            //
            // recover user info
            var payload = JwtPayload.Deserialize(userInfoResponse.Raw);
            return RecoverUserInfoFromJwtPayload(payload);
        }

        public virtual List<string> TranslateGroupNames(List<string> groupIdList)
        {
            return groupIdList;
        }
    }
}