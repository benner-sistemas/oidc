using Benner.Tecnologia.Common.Services;
using Benner.Tecnologia.OpenIDConnect;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Ninject;

namespace Benner.OpenIDConnect.Integration.Tests
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestMethod1()
        {
            var iocKernel = new StandardKernel();
            iocKernel.Bind<IOpenIDConnectServiceFactory>().To<OpenIDConnectServiceFactory>();
            iocKernel.Bind<IOpenIDConnectConfiguration>().To<DemoIdentityServerConfiguration>();
            iocKernel.Bind<IOpenIDConnectService>().To<OpenIDConnectServiceBase>();

            var serviceFactory = iocKernel.Get<IOpenIDConnectServiceFactory>();
            var service = serviceFactory.CreateOpenIDConnectService(iocKernel);

            var accessToken = service.GrantPasswordAccessToken("joao.melo", "keycloak");
            Assert.IsNotNull(accessToken);

            var idToken = service.RecoverUserInfoFromIdentityServer(accessToken);
            Assert.IsNotNull(idToken);
        }
    }
    public class DemoIdentityServerConfiguration : IOpenIDConnectConfiguration
    {
        public string TokenEndpoint => "http://server/auth/realms/master/protocol/openid-connect/token";

        public string UserInfoEndpoint => "http://server/auth/realms/master/protocol/openid-connect/userinfo";

        public string ClientID => "wes-leof";

        public string ClientSecret => "123";

        public string Issuer => "http://server/auth/realms/master";

        public string Certificate => "123";

        public string JsonWebKeySetEndpoint => throw new System.NotImplementedException();

        public string AuthorizationEndpoint => throw new System.NotImplementedException();

        public void Validate()
        {
        }
    }
}
