using MessagingAppServer.Models;

namespace MessagingAppServer.DBResutls
{
    public class RegistrationResult : UserAccount
    {
        public string Token { get; set; }
    }
}
