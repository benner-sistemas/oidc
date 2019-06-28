using Ninject;

namespace Benner.Tecnologia.Common.Services
{
    public interface IOpenIDConnectServiceFactory
    {
        IOpenIDConnectService CreateOpenIDConnectService(IKernel iocKernel = null);
    }
}
