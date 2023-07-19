using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using JupiterSecurity.Data.Models;
using JupiterSecurity.DTOs.Auth;
using Microsoft.Identity.Client.Platforms.Features.DesktopOs.Kerberos;
using System.Net;
using JupiterSecurity.DTOs;

namespace JupiterSecurity.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly UserManager<Employee> _userManager;

        public UserController(IConfiguration config, UserManager<Employee>userManager)
        {
            _configuration = config;
            _userManager = userManager;
        }

        [HttpPost]
        [Route("Register")]
        public async Task<ActionResult<string>> Register(RegisterDTO registerDTO)
        {
            var newEmp = new Employee
            {
                UserName = registerDTO.username
            };
            var creationResult = await _userManager.CreateAsync(newEmp,registerDTO.password);
            if (!creationResult.Succeeded)
            {
                return BadRequest(creationResult.Errors);
            }

            var userClaims = new List<Claim>{
                    new Claim(ClaimTypes.NameIdentifier, newEmp.UserName),
                    new Claim(ClaimTypes.Email, newEmp.Email),
                    new Claim(ClaimTypes.Role, newEmp.Role),
                    new Claim("Department", newEmp.Department),
                    new Claim("Nationality", "EGY"),
                };  
            await _userManager.AddClaimsAsync(newEmp, userClaims);

            return Ok(newEmp);
        }
        [HttpPost]
        [Route("login")]
        public async Task<ActionResult<TokenDTO>> Login(LoginDTO credintials)
        {
            var employee = await _userManager.FindByNameAsync(credintials.username);
            if (employee == null)
            {
                return BadRequest("User Not Found");
            }
            if (await _userManager.IsLockedOutAsync(employee))
            {
                return BadRequest("Try Again");
            }
            var userClaims = await _userManager.GetClaimsAsync(employee);
            bool isAuthenticated =  await _userManager.CheckPasswordAsync(employee, credintials.password);
            if (!isAuthenticated)
            {
                _userManager.AccessFailedAsync(employee);
                return Unauthorized("Wrong Credintials");
            }
            var exp = DateTime.Now.AddMinutes(15);
            var secretKey = _configuration.GetValue<string>("SecretKey");
            var secretKeyBytes = Encoding.ASCII.GetBytes(secretKey);
            var key = new SymmetricSecurityKey(secretKeyBytes);
            var methodGeneratingToken = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);
            var jwt = new JwtSecurityToken(
              claims: userClaims,
              notBefore: DateTime.Now,
              expires: DateTime.Now.AddMinutes(15),
              signingCredentials: methodGeneratingToken);

            var tokenHandler = new JwtSecurityTokenHandler();
            string tokenString = tokenHandler.WriteToken(jwt);
            return new TokenDTO
            {
                Token = tokenString,
                ExpiryDate = exp,
            };
        }

        [HttpPost]
        [Route("staticLogin")]
        public ActionResult<string> StaticLogin(LoginDTO credintials)
        {
            if (credintials.username == "admin" && credintials.password == "password")
            {
                var userClaims = new List<Claim>{
                    new Claim(ClaimTypes.NameIdentifier, credintials.username),
                    new Claim(ClaimTypes.Email, $"{credintials.username}@gmail.com"),
                    new Claim("Nationality", "EGY"),
                };

                var secretKey = _configuration.GetValue<string>("SecretKey");
                var secretKeyBytes = Encoding.ASCII.GetBytes(secretKey);
                var key = new SymmetricSecurityKey(secretKeyBytes);
                var methodGeneratingToken = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);
                var jwt = new JwtSecurityToken(
                  claims: userClaims,
                  notBefore: DateTime.Now,
                  expires: DateTime.Now.AddMinutes(15),
                  signingCredentials: methodGeneratingToken);

                var tokenHandler = new JwtSecurityTokenHandler();
                string tokenString = tokenHandler.WriteToken(jwt);
                return Ok(tokenString);
            }
            return Unauthorized("Wrong");
        }
    }
}
