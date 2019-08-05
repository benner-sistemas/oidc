using Benner.Tecnologia.Common.Services;
using IdentityModel.Client;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace Benner.Tecnologia.OpenIDConnect
{
    public class OpenIDConnectService : IOpenIDConnectService
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

            if (!userInfoResponse.IsError)
                return userInfoResponse.Json ??
                    throw new InvalidOperationException($"Identity Server returned invalid user info (id_token) from '{Configuration.UserInfoEndpoint}' response '{userInfoResponse.Raw}'");

            try
            {
                var jwt = ValidateResponse(userInfoResponse);
                var payload = Base64UrlEncoder.Decode(jwt.EncodedPayload);
                return JsonConvert.DeserializeObject(payload);
            }
            catch (Exception e)
            {
                throw new InvalidOperationException("Failed to validate user token.", e);
            }
        }

        private JwtSecurityToken ValidateResponse(UserInfoResponse response)
        {
            var handler = new JwtSecurityTokenHandler();
            var token = response.Raw;
            if (!handler.CanReadToken(token))
                throw new InvalidOperationException(response.Error);

            var cert = new X509Certificate2(Convert.FromBase64String(Configuration.Certificate));
            var parameters = new TokenValidationParameters
            {
                ValidAudience = Configuration.ClientID,
                ValidIssuer = Configuration.Issuer,
                IssuerSigningKey = new X509SecurityKey(cert),
                RequireExpirationTime = false,
            };

            handler.ValidateToken(token, parameters, out SecurityToken st);
            return (JwtSecurityToken)st;
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