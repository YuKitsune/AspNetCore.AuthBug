using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using AspNetCore.AuthBug.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace AspNetCore.AuthBug.Controllers
{
    public class HomeController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;

        public HomeController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [HttpPost]
        public async Task<IActionResult> Authenticate([FromBody] AuthenticateModel model)
        {
            await EnsureUserExists();
            
            IdentityUser user = await _userManager.FindByNameAsync(model.UserName);
            if (user == null) return NotFound();

            Microsoft.AspNetCore.Identity.SignInResult signInResult = await _signInManager.PasswordSignInAsync(user, model.Password, true, false);
            if (!signInResult.Succeeded) return Unauthorized();
            
            string token = GetToken(user);
            return Content(token);
        }

        [HttpGet, Authorize]
        public IActionResult AuthRequired() => Content("Authenticated, no scheme specified in attribute.");

        [HttpGet, Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public IActionResult AuthRequiredSchemeSpecified() => Content($"Authenticated, {nameof(JwtBearerDefaults)}.{nameof(JwtBearerDefaults.AuthenticationScheme)} specified (Value: {JwtBearerDefaults.AuthenticationScheme})");

        private string GetToken(IdentityUser user)
        {
            byte[] key = Encoding.ASCII.GetBytes(JwtDemoConstants.Key);
            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                    new Claim(ClaimTypes.Name, user.UserName)
                }),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private async Task EnsureUserExists()
        {
            string defaultUserName = "Administrator";
            string defaultEmail = "admin@.local.host";
            string defaultPassword = "Password123!@#";

            IdentityUser user = await _userManager.FindByNameAsync(defaultUserName);
            if (user != null) return;

            user = new IdentityUser
            {
                UserName = defaultUserName,
                Email = defaultEmail
            };

            await _userManager.CreateAsync(user, defaultPassword);
        }
    }
}