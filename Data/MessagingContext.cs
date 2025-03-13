using MessagingAppServer.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Data.SqlClient;
using System.Data;
using Dapper;
using MessagingAppServer.DBResutls;
namespace MessagingAppServer.Data
{
    public class MessagingRepository : DbContext
    {
        private readonly string _connectionString;

        public MessagingRepository(string connectionString)
        {
            _connectionString = connectionString;
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Configure RegisterUserResult as keyless since it's only for SP results
            modelBuilder.Entity<RegistrationResult>().HasNoKey();
        }
        public async Task<RegistrationResult> RegisterUserAsync(UserAccount user)
        {
            using (var connection = new SqlConnection(_connectionString))
            {

                var parameters = new DynamicParameters();
                parameters.Add("@Username", user.Username);
                parameters.Add("@FirstName", user.FirstName);
                parameters.Add("@LastName", user.LastName);
                parameters.Add("@Email", user.Email);
                parameters.Add("@PasswordHash", user.Password);
                parameters.Add("@PublicKey", user.PublicKey);


                var registrationResult = await connection.QueryFirstOrDefaultAsync<RegistrationResult>(
                                "sp_RegisterUser",
                                parameters,
                                commandType: CommandType.StoredProcedure);

                return registrationResult ?? new RegistrationResult();
            }
        }

        public async Task<LoginResult> LoginUserAsync(string username)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                var parameter = username;

                var loginResult = await connection.QueryFirstOrDefaultAsync<LoginResult>(
                                                "sp_LoginUser",
                                                parameter,
                                                commandType: CommandType.StoredProcedure);
                return loginResult ?? new LoginResult();
            }
        }

        public async Task<SearchResult> SearchUserAsync(string searchTerm)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                var parameter = searchTerm;

                var searchResult = await connection.QueryFirstOrDefaultAsync<SearchResult>(
                    "sp_SearchUserAccount",
                    parameter,
                    commandType: CommandType.StoredProcedure);

                return searchResult ?? new SearchResult();
            }
        }

        public async Task SendMessageAsync(Message message)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                var parameters = new DynamicParameters();
                parameters.Add("@ConversationID", message.ConversationID);
                parameters.Add("@SenderUserID", message.SenderUserID);
                parameters.Add("@Content", message.Content);
                parameters.Add("@IV", message.IV);

                await connection.ExecuteAsync("sp_SendMessage",
                                               parameters,
                                               commandType: CommandType.StoredProcedure);

                // add message sent feature later
            }
        }

        public async Task<List<OpenConversationResult>> OpenConversationAsync(int userID1, int userID2)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                var parameters = new DynamicParameters();
                parameters.Add("@UserID1", userID1);
                parameters.Add("@UserID2", userID2);

                var convResult = await connection.QueryAsync<OpenConversationResult>(
                                                  "sp_StartOrGetConversation",
                                                  parameters,
                                                  commandType: CommandType.StoredProcedure);
                return convResult.AsList() ?? new List<OpenConversationResult>();
            }
        }

        public async Task<List<Message>> GetMessageHistoryAsync(int userID, int conversationID)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                var parameters = new DynamicParameters();
                parameters.Add("@UserID", userID);
                parameters.Add("@ConversationID", conversationID);

                var messageHistoryResult = await connection.QueryAsync<Message>(
                                                            "sp_GetMessageHistory",
                                                            parameters,
                                                            commandType: CommandType.StoredProcedure);
                return messageHistoryResult.AsList() ?? new List<Message>();
            }
        }
    }


}
