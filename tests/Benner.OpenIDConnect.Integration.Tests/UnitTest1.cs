using Benner.Tecnologia.Common.Services;
using Benner.Tecnologia.OpenIDConnect;
using IdentityModel;
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
            iocKernel.Bind<IOpenIDConnectService>().To<OpenIDConnectService>();

            var serviceFactory = iocKernel.Get<IOpenIDConnectServiceFactory>();
            var service = serviceFactory.CreateOpenIDConnectService(iocKernel);

            var accessToken = service.GrantPasswordAccessToken("joao.melo", "keycloak");
            Assert.IsNotNull(accessToken);

            var idToken = service.GetUserInfo(accessToken);
            Assert.IsNotNull(idToken);
        }
    }
    public class DemoIdentityServerConfiguration : IOpenIDConnectConfiguration
    {
        public string TokenEndpoint => "http://192.168.5.82:8080/auth/realms/master/protocol/openid-connect/token";

        public string UserInfoEndpoint => "http://192.168.5.82:8080/auth/realms/master/protocol/openid-connect/userinfo";

        public string ClientID => "benner-wes-client";

        public string ClientSecret => "311e0584-d15d-4a3b-9dbe-09479ac63410";
    }
}
