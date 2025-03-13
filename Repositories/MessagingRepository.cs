using MessagingAppServer.DTOs;
using MessagingAppServer.Models;
using Microsoft.EntityFrameworkCore;

namespace MessagingAppServer.Repositories
{
    public class MessagingRepository : IMessagingRepository
    {
        private readonly ApplicationDbContext _context;

        public MessagingRepository(ApplicationDbContext context) // Add constructor to initialize _context
        {
            _context = context;
        }

        public Task<GetConversationDTO> GetConversation(int userID1, int userID2)
        {
            throw new NotImplementedException();
        }

        public Task<List<Message>> GetMessages(int userID, int conversationID)
        {
            throw new NotImplementedException();
        }

        public Task<UserAccount> LoginUser(string username, string password)
        {
            throw new NotImplementedException();
        }

        public Task<UserAccount> RegisterUser(UserAccount userAccount)
        {
            throw new NotImplementedException();
        }

        public Task<UserAccount> SearchUser(string searchTerm)
        {
            throw new NotImplementedException();
        }

        public Task SendMessage(Message message)
        {
            throw new NotImplementedException();
        }
    }
}
