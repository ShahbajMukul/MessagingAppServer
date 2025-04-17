namespace MessagingAppServer.DTOs
{
    public class LoginPayload
    {
        public required string Username { get; set; }
        public required string Password { get; set; }
        public required string PublicKey { get; set; }
    }
}
