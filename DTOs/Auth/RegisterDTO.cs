namespace JupiterSecurity.DTOs.Auth
{
    public record RegisterDTO
    {
        public string username { get; set; } = string.Empty;
        public string password { get; set; } = string.Empty;
        public string Department { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty; 
    }
}
