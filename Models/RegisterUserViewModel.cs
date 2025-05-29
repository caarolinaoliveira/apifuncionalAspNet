using System.ComponentModel.DataAnnotations;

namespace ApiFuncional.Models
{
    public class RegisterUserViewModel
    {
        [Required(ErrorMessage = "O campo {0} é obrigatório")]
        [EmailAddress(ErrorMessage = "O campo {0} deve ser um endereço de e-mail válido")]
        public string? Email { get; set; }

        [Required(ErrorMessage = "O campo {0} é obrigatório")]
        [StringLength(100, ErrorMessage = "O campo {0} deve ter entre {2} e {1} caracteres", MinimumLength = 6)]
        public string? Password { get; set; }

        [Compare("Password", ErrorMessage = "As senhas não coincidem")]
        public string? ConfirmPassword { get; set; }

    }
}