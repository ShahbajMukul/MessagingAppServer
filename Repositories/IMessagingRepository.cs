using MessagingAppServer.Models;
using MessagingAppServer.DTOs;

namespace MessagingAppServer.Repositories;

public interface IMessagingRepository
{
    Task<UserAccount> RegisterUser(UserAccount userAccount);
    Task<UserAccount> LoginUser(string username, string password);
    Task<UserAccount> SearchUser(string searchTerm);
    Task<GetConversationDTO> GetConversation(int userID1, int userID2);
    Task SendMessage(Message message);
    Task<List<Message>> GetMessages(int userID, int conversationID);
}

