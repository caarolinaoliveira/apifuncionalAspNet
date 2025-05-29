using System.IdentityModel.Tokens.Jwt;
using ApiFuncional.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace apiFuncional.Models;

[ApiController]
[Route("api/conta")]
public class AuthController : ControllerBase
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly JwtSettings _jwtSettings;

    public AuthController(SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager, IOptions<JwtSettings> jwtSettings)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _jwtSettings = jwtSettings.Value;
    }

    [HttpPost("registrar")]
    public async Task<IActionResult> Registrar(RegisterUserViewModel registerUser)
    {
        if (!ModelState.IsValid) return ValidationProblem(ModelState);

        var user = new IdentityUser
        {
            UserName = registerUser.Email,
            Email = registerUser.Email,
            EmailConfirmed = true // Assuming email confirmation is not required for simplicity
        };
        var result = await _userManager.CreateAsync(user, registerUser.Password);
        if (result.Succeeded)
        {
            // Optionally, you can sign in the user after registration
            await _signInManager.SignInAsync(user, isPersistent: false);
            return Ok(GerarJwt());
        }

        return Problem("Erro ao registrar usuário: " + string.Join(", ", result.Errors.Select(e => e.Description)));
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginUserViewModel loginUser)
    {
        if (!ModelState.IsValid) return ValidationProblem(ModelState);

        var result = await _signInManager.PasswordSignInAsync(loginUser.Email, loginUser.Password, false, true);

        if (result.Succeeded)
        {
            return Ok(GerarJwt());
        }
        return Problem("Usário ou senha inválidos.");
    }

    private string GerarJwt()
    {
        var tokenHandler = new JwtSecurityTokenHandler();

        var key = System.Text.Encoding.ASCII.GetBytes(_jwtSettings.Segredo ?? string.Empty);
        var token = tokenHandler.CreateToken(new SecurityTokenDescriptor
        {

            Issuer = _jwtSettings.Emissor,
            Audience = _jwtSettings.Audiencia,
            Expires = DateTime.UtcNow.AddHours(double.Parse(_jwtSettings.ExpiracaoHoras ?? "1")),
            SigningCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(
                new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(key),
                Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256Signature)
        });

        var encodedToken = tokenHandler.WriteToken(token);
        return encodedToken;
    }
}