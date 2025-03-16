namespace MessagingAppServer.DBResutls;
public class RegistrationPayload
    {
    public string? Username { get; set; }
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? Email { get; set; }
    // hashed password
    public string? Password { get; set; }
    }
