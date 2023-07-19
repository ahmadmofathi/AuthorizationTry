using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JupiterSecurity.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ConfidentialDataController : ControllerBase
    {
        [Authorize]
        [HttpGet]
        [Route("Employees")]
        public ActionResult<List<string>> GetEmployeesName()
        {
            return new List<string>
            {
                "Ahmad","Muhammed","Marina","Snezhana"
            };
        }

        [Authorize(Policy ="Manager")]
        [HttpGet]
        [Route("Revenue")]
        public ActionResult<decimal> GetCompanyProfit()
        {
            return 400_000_000;
        }
    }
}
