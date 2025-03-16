namespace MessagingAppServer.DTOs
{
    public class LoginPayload
    {
        public required string Username { get; set; }
        public required string PasswordHash { get; set; }
    }
}
