namespace Benner.Tecnologia.Common.Services
{
    public interface IOpenIDConnectService
    {
        IOpenIDConnectConfiguration Configuration { set; get; }

        string GrantPasswordAccessToken(string userName, string password);

        UserInfo GetUserInfo(string accessToken);
    }
}
