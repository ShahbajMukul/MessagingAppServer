using MessagingAppServer.Models;
using MessagingAppServer.DTOs;
using MessagingAppServer.DBResutls;

namespace MessagingAppServer.Repositories;

public interface IMessagingRepository
{
    Task<RegistrationResult> RegisterUserAsync(RegistrationPayload registrationData);
    Task<LoginResult> LoginUserAsync(LoginPayload loginData);
    Task<List<SearchResult>> SearchUserAsync(string searchTerm);
    Task<List<ContactsResult>> GetContactsAsync(int userID);
    Task SendMessageAsync(Message message);
    Task<List<OpenConversationResult>> OpenConversationAsync(int userID1, int userID2);
    Task<List<MessageResult>> GetMessageHistoryAsync(int userID, int conversationID);
}

