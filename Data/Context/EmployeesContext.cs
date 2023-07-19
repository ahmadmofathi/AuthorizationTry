using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JupiterSecurity.Data.Context
{
    public class EmployeesContext : IdentityDbContext
    {
        public EmployeesContext(DbContextOptions<EmployeesContext>options):base(options)
        {
            
        }
    }
}
