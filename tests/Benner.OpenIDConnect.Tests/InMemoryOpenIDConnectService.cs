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
                return "accesstoken content";


            throw new InvalidOperationException("Invalid authentication");
        }
    }
}
