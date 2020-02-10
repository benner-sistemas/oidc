using System.IdentityModel.Tokens.Jwt;

namespace Benner.Tecnologia.Common.Services
{
    public interface IOpenIDConnectService
    {
        /// <summary>
        /// Get configuration
        /// </summary>
        IOpenIDConnectConfiguration Configuration { set; get; }

        /// <summary>
        /// Requests access_token based on user name and password
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        string GrantPasswordAccessToken(string userName, string password);

        /// <summary>
        /// Validate jwt security token
        /// </summary>
        /// <param name="jwtSecurityToken"></param>
        void ValidateJwtSecutiryToken(JwtSecurityToken jwtSecurityToken);

        /// <summary>
        /// Recover user info from jwt payload
        /// </summary>
        /// <param name="jwtPayload"></param>
        /// <returns></returns>
        UserInfo RecoverUserInfoFromJwtPayload(JwtPayload jwtPayload);

        /// <summary>
        /// Requests id_token from identity server, based on access_token 
        /// </summary>
        /// <param name="accessToken"></param>
        /// <returns></returns>
        UserInfo RecoverUserInfoFromIdentityServer(string accessToken);
    }
}