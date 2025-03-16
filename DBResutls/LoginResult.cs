using MessagingAppServer.Models;

namespace MessagingAppServer.DBResutls
{
    public class LoginResult : UserAccount
    {
        public string Token { get; set; }
    }
}
