namespace MessagingAppServer.DBResutls
{
    public class Message
    {
            public int MessageID { get; set; }
            public int ConversationID { get; set; }
            public string Content { get; set; }
            public string EncryptedKey { get; set; }
            public int SenderUserID { get; set; }
            public DateTime SentTime { get; set; }
            public bool IsRead { get; set; }
            public string IV { get; set; }
    }

    public class MessageResult : Message
    { }
}
