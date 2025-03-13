using MessagingAppServer.Models;

namespace MessagingAppServer.DTOs
{
    public class GetConversationDTO : UserAccount
    {
        public int ConversationID { get; set; }
    }
}