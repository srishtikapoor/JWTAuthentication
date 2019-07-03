using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using TokenBasedAuthentication.Models;

namespace TokenBasedAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]

    //To bypass the authentication
    [AllowAnonymous]
    public class LoginController : ControllerBase
    {

        private IConfiguration _config;

        public LoginController(IConfiguration config)
        {
            _config = config;
        }

        [HttpPost]
        public IActionResult Login([FromBody]UserModel login)
        {
            IActionResult response = Unauthorized();
            var user = AuthenticateUser(login);

            if (user != null)
            {
                var tokenString = GenerateJSONWebToken(user);
                response = Ok(new { token = tokenString });
            }

            return response;
        }

        private string GenerateJSONWebToken(UserModel userInfo)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[] {
             new Claim(JwtRegisteredClaimNames.Sub, userInfo.Username),
             //new Claim(JwtRegisteredClaimNames.Sub, userInfo.Password),
             new Claim(JwtRegisteredClaimNames.Email, userInfo.EmailAddress),
             new Claim("DateOfJoing", userInfo.DateOfJoing.ToString("yyyy-MM-dd")),
             new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                                };

            var token = new JwtSecurityToken(_config["Jwt:Issuer"],
            _config["Jwt:Issuer"],
            claims,
            expires: DateTime.Now.AddMinutes(120),
            signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private UserModel AuthenticateUser(UserModel login)
        {
            UserModel user = null;

            //Validate the User Credentials 
            if (login.Username == "Jignesh")
            {
                user = new UserModel
                {
                Username = "Jignesh Trivedi", EmailAddress = "test.btest@gmail.com" };
                }
            return user;
        }
    }
}