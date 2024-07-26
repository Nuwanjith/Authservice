using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;
using System.IO;
using AuthService.Models;

namespace AuthService.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        private readonly IConfiguration _configuration;
        private readonly string _xmlFilePath;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
            _xmlFilePath = Path.Combine(Directory.GetCurrentDirectory(), "Data", "users.xml");
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
                var user = AuthenticateUser(model.Username, model.Password);
                if (user != null)
                {
                    var token = GenerateJwtToken(user.Username, user.UserId);
                    // Store the token in a cookie (optional)
                    Response.Cookies.Append("JwtToken", token, new CookieOptions { HttpOnly = true });

                    // Redirect to another microservice after successful login with userId parameter
                    return Redirect($"http://localhost:5270/Home/Dashboard");
                }

                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            }

            return View(model); // Return the login page view with error message
        }

        private User AuthenticateUser(string username, string password)
        {
            var users = GetUsersFromXml();
            return users.FirstOrDefault(u => u.Username == username && u.Password == password);
        }

        private List<User> GetUsersFromXml()
        {
            var serializer = new XmlSerializer(typeof(List<User>), new XmlRootAttribute("ArrayOfUser"));
            using (var reader = new StreamReader(_xmlFilePath))
            {
                return (List<User>)serializer.Deserialize(reader);
            }
        }

        private string GenerateJwtToken(string username, int userId)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, username),
                    new Claim(ClaimTypes.NameIdentifier, userId.ToString())
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }

    [XmlRoot("User")]
    public class User
    {
        public int UserId { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
    }
}
