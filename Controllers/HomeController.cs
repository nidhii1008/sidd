using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using ITGateway.Models;
using ITGateway.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
namespace ITGateway.Controllers;

public class HomeController : Controller
{
        public DataContext _context ;
    
    public HomeController(DataContext context )
    {
            _context = context;
    }
    // public ActionResult BeforeLayoutContent()
    // {
    //     // Your logic here
    //     return PartialView("_BeforeLayoutContent");
    // }
    public IActionResult Index()
    {
        return View();
    }

    public IActionResult Privacy()
    {
        return View();
    }
    public IActionResult Admin(){
        return View();
    }
     [HttpGet("/Home/Index")]
public ActionResult<string> UserLogin(string userName, string Password)
{
    if (string.IsNullOrEmpty(userName) || string.IsNullOrEmpty(Password))
    {
        // Render the login form
        return View("Index");
    }

    var user = _context.UserInfo.SingleOrDefault(u => u.username == userName);
    if (user != null && Password==user.password)
    {
        var token = GenerateJwtToken(user.username);
       
        // HttpContext.Session.SetString("JwtToken", token);
        Response.Cookies.Append("JwtToken",token);
        // localStorage.setItem("token", token);
        return View("Admin");
    }
    return "Enter correct credentials";
}

// public static string GenerateSecurityKey()
// {
//     const string allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
//     const int keyLength = 32; // Choose a suitable key length (in characters)
    
//     byte[] randomBytes = new byte[keyLength];

//     using (var rng = new RNGCryptoServiceProvider())
//     {
//         rng.GetBytes(randomBytes);
//     }

//     StringBuilder result = new StringBuilder(keyLength);
//     foreach (byte b in randomBytes)
//     {
//         result.Append(allowedChars[b % allowedChars.Length]);
//     }

//     return result.ToString();
// }

  private string GenerateJwtToken(string username)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("abjhbasjhbsjsjbjhabhshNidhi"));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, username),
            // You can add more claims as needed, e.g., roles or additional user information
        };

        var token = new JwtSecurityToken(
            issuer: "http://localhost:5099",
            audience: "http://localhost:5099",
            claims: claims,
            expires: DateTime.Now.AddMinutes(30), // Set the token expiration time as needed
            signingCredentials: credentials
        );

        var tokenHandler = new JwtSecurityTokenHandler();
        return tokenHandler.WriteToken(token);
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
