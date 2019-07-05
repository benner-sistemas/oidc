namespace Benner.Tecnologia.Common.Services
{
    public interface IOpenIDConnectConfiguration
    {
        string TokenEndpoint { get; }
        string UserInfoEndpoint { get; }
        string ClientID { get; }
        string ClientSecret { get; }
    }
}
