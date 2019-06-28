using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Benner.OpenIDConnect.Tests
{
    [TestClass]
    public class GenericTests
    {
        [TestMethod]
        public void InMemoryOpenIdConnectServiceTests()
        {
            var service = new InMemoryOpenIDConnectService();
            var accessToken = service.GrantPasswordAccessToken("bob", "bob-pass");
            Assert.AreEqual("accesstoken content", accessToken);
        }
    }
}
