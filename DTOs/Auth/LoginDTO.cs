using Microsoft.AspNetCore.Identity;

namespace JupiterSecurity
{
    public class LoginDTO
    {
        public string username { get; set; } = string.Empty;
        public string password {get; set;} = string.Empty;
    }
}
