using MessagingAppServer.Models;

namespace MessagingAppServer.DBResutls
{
    public class OpenConversationResult
    {
        public int ConversationID { get; set; }
        public int UserID { get; set; }
        public string? Username { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Email { get; set; }
        public DateTime LastActiveTime { get; set; }
        public bool ActiveNow { get; set; }
        public string? PublicKey { get; set; }
    }
}
