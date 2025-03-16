using System;

namespace MessagingAppServer.Models;

public class MessageRequest
{
    public int ConversationID { get; set; }
    public string Content { get; set; }
    public string EncryptedKey { get; set; }
    public DateTime SentTime { get; set; }
    public string IV { get; set; }
}
