using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        // Login page
        [HttpGet("login")]
        public IActionResult Login()
        {
            return View(); // Return the login page view
        }

        // Handle login form submission
        [HttpPost("login")]
        public IActionResult Login([FromForm] LoginModel model)
        {
            if (ModelState.IsValid)
            {
                // Replace this with your actual user authentication logic
                if (model.Username == "test" && model.Password == "password")
                {
                    var token = GenerateJwtToken(model.Username);
                    // Store the token in a cookie (optional)
                    Response.Cookies.Append("JwtToken", token, new CookieOptions { HttpOnly = true });

                    // Redirect to another microservice after successful login
                    return Redirect("http://another-microservice-host/home");
                }

                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            }

            return View(model); // Return the login page view with error message
        }

        private string GenerateJwtToken(string username)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, username)
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }

    public class LoginModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}
