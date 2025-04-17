namespace MessagingAppServer.Services
{
    public class JwtSettings
    {
        public string SecretKey { get; set; } = "aB4cDeFgHiJkLmNo";
        public int ExpirationDays { get; set; } = 7;
        public bool Audience { get; set; }
    }
}
