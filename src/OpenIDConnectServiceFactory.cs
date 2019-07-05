using Benner.Tecnologia.Common.Services;
using Ninject;

namespace Benner.Tecnologia.OpenIDConnect
{
    public class OpenIDConnectServiceFactory : IOpenIDConnectServiceFactory
    {
        private static IOpenIDConnectService Instance { get; set; }

        public IOpenIDConnectService CreateOpenIDConnectService(IKernel iocKernel = null)
        {
            if (Instance == null)
            {
                Instance = iocKernel?.Get<IOpenIDConnectService>() ?? new OpenIDConnectService();
                Instance.Configuration = iocKernel?.Get<IOpenIDConnectConfiguration>() ?? new OpenIDConnectConfiguration();
            }
            return Instance;
        }
    }
}
