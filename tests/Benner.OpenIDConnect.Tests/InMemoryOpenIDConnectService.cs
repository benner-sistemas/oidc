using Benner.Tecnologia.Common.Services;
using System;
using System.Collections.Generic;

namespace Benner.OpenIDConnect.Tests
{
    public class InMemoryOpenIDConnectService : IOpenIDConnectService
    {
        public IOpenIDConnectConfiguration Configuration { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        private static readonly Dictionary<string, string> _data = new Dictionary<string, string>
        {
            { "bob", "bob-pass" },
            { "alice", "alice-pass"},
        };

        public string GrantPasswordAccessToken(string userName, string password)
        {
            string storedPassword;

            if (_data.TryGetValue(userName, out storedPassword) && password.Equals(storedPassword))
                return $"{userName}-accesstoken";


            throw new InvalidOperationException("Invalid authentication");
        }

        public string GetUserInfo(string accessToken)
        {
            return "{\"sub\":\"f2a8d5e6\",\"email_verified\":true,\"name\":\"João Melo\",\"groups\":[\"/Grupo-Teste\",\"/Grupo-Teste/Outro-grupo\",\"/sysdba\"],\"preferred_username\":\"joao.melo\",\"given_name\":\"João\",\"family_name\":\"Melo\",\"email\":\"joao.melo@benner.com.br\"}";
        }
    }
}