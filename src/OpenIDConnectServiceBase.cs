﻿using Benner.Tecnologia.Common.Services;
using IdentityModel.Client;
using System;
using System.IdentityModel.Tokens.Jwt;
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

        protected static JwtSecurityTokenHandler _jwtSecurityTokenHandler = new JwtSecurityTokenHandler();

        protected static readonly HttpClient _httpClient = new HttpClient();

        ~OpenIDConnectServiceBase()
        {
            _httpClient.Dispose();
        }

        public abstract string GrantPasswordAccessToken(string userName, string password);

        public abstract void ValidateJwtSecutiryToken(JwtSecurityToken jwtSecurityToken);

        public abstract UserInfo RecoverUserInfoFromJwtPayload(JwtPayload jwtPayload);

        public virtual UserInfo RecoverUserInfoFromIdentityServer(string accessToken)
        {
            //
            // request for id_token
            var userInfoResponse = _httpClient.GetUserInfoAsync(new UserInfoRequest
            {
                Address = Configuration.UserInfoEndpoint,
                Token = accessToken,
            }).Result;

            if (userInfoResponse.IsError)
                throw new InvalidOperationException($"Identity Server returned invalid user info (id_token) from '{Configuration.UserInfoEndpoint}' response '{userInfoResponse.Raw}'");

            var rawToken = userInfoResponse.Raw;
            if (!_jwtSecurityTokenHandler.CanReadToken(rawToken))
                throw new InvalidOperationException("id_token não pode ser lido pois não está no formato JWT");

            //
            // validate 
            var jwtSecurityToken = _jwtSecurityTokenHandler.ReadJwtToken(rawToken);
            ValidateJwtSecutiryToken(jwtSecurityToken);

            //
            // recover user info
            var userInfo = RecoverUserInfoFromJwtPayload(jwtSecurityToken.Payload);

            return userInfo;
        }
    }
}