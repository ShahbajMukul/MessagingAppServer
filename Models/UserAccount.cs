namespace MessagingAppServer.Models;

public class UserAccount
{
    public int UserID { get; set; }
    public string? Username { get; set; }   
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? Email { get; set; }
    // hashed password
    public Byte[]? Password { get; set; }
    public DateTime LastActiveTime { get; set; }
    public bool ActiveNow { get; set; }
    public string? PublicKey { get; set; }
}