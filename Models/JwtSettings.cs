namespace ApiFuncional.Models;

public class JwtSettings
{
    public string? Segredo { get; set; }
    public string? ExpiracaoHoras { get; set; }
    public string? Emissor { get; set; }
    public string? Audiencia { get; set; }

}