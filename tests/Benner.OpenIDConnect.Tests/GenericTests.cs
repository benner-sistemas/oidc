using Benner.Tecnologia.Common.Services;
using Benner.Tecnologia.OpenIDConnect;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Ninject;

namespace Benner.OpenIDConnect.Tests
{
    [TestClass]
    public class GenericTests
    {
        [TestMethod]
        public void InMemoryOpenIdConnectServiceTests()
        {
            var service = new InMemoryOpenIDConnectService();
            var userName = "bob";
            var password = "bob-pass";

            var accessToken = service.GrantPasswordAccessToken(userName, password);
            Assert.AreEqual($"{userName}-accesstoken", accessToken);


            var idToken = service.GetUserInfo(accessToken);
            Assert.IsNotNull(idToken);
        }

        [TestMethod]
        public void DependencyInjectionAndInversionOfControl()
        {
            var iocKernel = new StandardKernel();


            iocKernel.Bind<IOpenIDConnectServiceFactory>().To<OpenIDConnectServiceFactory>();
            iocKernel.Bind<IOpenIDConnectConfiguration>().To<OpenIDConnectConfiguration>();
            iocKernel.Bind<IOpenIDConnectService>().To<OpenIDConnectService>();

            var serviceFactory = iocKernel.Get<IOpenIDConnectServiceFactory>();
            Assert.IsNotNull(serviceFactory);
            Assert.IsInstanceOfType(serviceFactory, typeof(OpenIDConnectServiceFactory));

            var service = serviceFactory.CreateOpenIDConnectService(iocKernel);
            Assert.IsNotNull(service);
            Assert.IsInstanceOfType(service, typeof(OpenIDConnectService));

            var configuration = service.Configuration;
            Assert.IsNotNull(configuration);
            Assert.IsInstanceOfType(configuration, typeof(OpenIDConnectConfiguration));
        }
    }
}