using Benner.Tecnologia.Common.Services;
using IdentityModel.Client;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
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

        public UserInfo GetUserInfo(string accessToken)
        {
            var json = GetRawJson(accessToken);
            return ConvertToUserInfo(json);
        }

        public dynamic GetRawJson(string accessToken)
        {
            var userInfoResponse = _httpClient.GetUserInfoAsync(new UserInfoRequest
            {
                Address = Configuration.UserInfoEndpoint,
                Token = accessToken,
            }).Result;

            if (userInfoResponse.IsError)
                throw new InvalidOperationException(userInfoResponse.Error);

            if (userInfoResponse.Json == null)
                throw new InvalidOperationException($"Identity Server returned invalid user info (id_token) from '{Configuration.UserInfoEndpoint}' response '{userInfoResponse.Raw}'");

            return userInfoResponse.Json;
        }

        private UserInfo ConvertToUserInfo(dynamic rawObject)
        {
            var result = new UserInfo();

            result.Name = rawObject.name ?? throw new InvalidOperationException($"Property 'name' not found at user info (id_token) from Identity Server: {rawObject}");
            result.Email = rawObject.email ?? throw new InvalidOperationException($"Property 'email' not found at user info (id_token) from Identity Server: {rawObject}");
            result.UserName = rawObject.username ?? throw new InvalidOperationException($"Property 'username' not found at user info (id_token) from Identity Server: {rawObject}");
            if (rawObject.groups == null)
                throw new InvalidOperationException($"Property 'groups' not found at user info (id_token) from Identity Server: {rawObject}");
            if (!(rawObject.groups is JArray))
                throw new InvalidOperationException($"Property 'groups' from user info (id_token) must be array : {rawObject}");

            result.Groups = new List<string>();
            foreach (var group in rawObject.groups)
                result.Groups.Add(group.ToString());

            return result;
        }
    }
}