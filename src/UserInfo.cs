using System.Collections.Generic;

namespace Benner.Tecnologia.Common.Services
{
    public class UserInfo
    {
        public string Name { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
        public List<string> Groups { get; set; } = new List<string>();
    }
}