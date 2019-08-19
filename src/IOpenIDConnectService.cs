using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Benner.Tecnologia.Common.Services
{
    public interface IOpenIDConnectService
    {
        IOpenIDConnectConfiguration Configuration { set; get; }

        string GrantPasswordAccessToken(string userName, string password);

        dynamic GetRawJson(string accessToken);

        UserInfo GetUserInfo(string accessToken);

        /// <summary>
        /// Validates the token with certificate and throws exception if invalid
        /// </summary>
        /// <param name="accessToken"></param>
        ClaimsPrincipal ValidateToken(string accessToken, out JwtSecurityToken jwt);

        dynamic GetJsonPayloadFromToken(string accessToken);
    }
}
