using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace JupiterSecurity.Data.Models
{
    public class Employee : IdentityUser
    {
        public string Role { get; set; } = string.Empty;
        public string Department { get; set; } = string.Empty;
    }
}
