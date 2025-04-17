using MessagingAppServer.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Data.SqlClient;
using System.Data;
using Dapper;
using MessagingAppServer.DBResutls;
using MessagingAppServer.DTOs;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;
using MessagingAppServer.Services;
namespace MessagingAppServer.Repositories
{
    public class MessagingRepository : DbContext, IMessagingRepository
    {
        private readonly string _connectionString;
        private readonly JwtSettings _jwtSettings;

        public MessagingRepository(string connectionString, JwtSettings jwtSettings)
        {
            _connectionString = connectionString;
            _jwtSettings = jwtSettings;
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Configure RegisterUserResult as keyless since it's only for SP results
            modelBuilder.Entity<RegistrationResult>().HasNoKey();
        }
        public async Task<RegistrationResult?> RegisterUserAsync(RegistrationPayload registrationData)
        {
            if (registrationData == null || string.IsNullOrEmpty(registrationData.Password))
            {
                throw new ArgumentException("Registration data and password are required");
            }
            using (var connection = new SqlConnection(_connectionString))
            {


                var parameters = new DynamicParameters();
                parameters.Add("@Username", registrationData.Username);
                parameters.Add("@FirstName", registrationData.FirstName);
                parameters.Add("@LastName", registrationData.LastName);
                parameters.Add("@Email", registrationData.Email);
                var passwordHashBytes = HashPassword(registrationData!.Password);
                parameters.Add("@PasswordHash", passwordHashBytes, dbType: DbType.Binary);
                parameters.Add("@PublicKey", registrationData!.PublicKey);

                var registrationResult = await connection.QueryFirstOrDefaultAsync<RegistrationResult>(
                                "sp_RegisterUser",
                                parameters,
                                commandType: CommandType.StoredProcedure);

                if (registrationResult == null)
                {
                    return null;
                }

                JwtSecurityTokenHandler tokenHandler;
                SecurityToken token;
                CreateToken(registrationResult, out tokenHandler, out token);
                registrationResult.Token = tokenHandler.WriteToken(token);

                return registrationResult;
            }
        }

        private byte[] HashPassword(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                Console.WriteLine("Password cannot be null or empty");
                throw new ArgumentException("Password cannot be null or empty");
            }

            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
            }
        }

        public async Task<LoginResult?> LoginUserAsync(LoginPayload loginData)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                var parameters = new DynamicParameters();
                parameters.Add("@Username", loginData.Username);

                var loginResult = await connection.QueryFirstOrDefaultAsync<LoginResult>(
                                                    "sp_LoginUser",
                                                    parameters,
                                                    commandType: CommandType.StoredProcedure);

                if (loginResult == null)
                {
                    return null;
                }

                // Verify if the password is correct
                bool isPasswordValid = VerifyPassword(loginData.Password, loginResult.Password);

                if (!isPasswordValid || loginResult.Username == null)
                {
                    return null;
                }

                JwtSecurityTokenHandler tokenHandler;
                SecurityToken token;
                CreateToken(loginResult, out tokenHandler, out token);
                loginResult.Token = tokenHandler.WriteToken(token);

                // user doesnt need the password anymore after logging in
                loginResult.Password = null;

                await UpdatePublicKeyAsync(loginData.Username, loginData.PublicKey);

                return loginResult ?? null;
            }
        }
        public async Task UpdatePublicKeyAsync(string username, string newPublicKey)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                var parameters = new DynamicParameters();
                parameters.Add("@Username", username);
                parameters.Add("@NewPublicKey", newPublicKey);

                var result = await connection.ExecuteAsync(
                    "sp_UpdatePublicKey",
                    parameters,
                    commandType: CommandType.StoredProcedure);
            }
        }
        private void CreateToken(UserAccount? accountData, out JwtSecurityTokenHandler tokenHandler, out SecurityToken token)
        {
            // create the token
            tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtSettings.SecretKey);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                        new Claim(ClaimTypes.Name, accountData.Username),
                        new Claim(ClaimTypes.NameIdentifier, accountData.UserID.ToString())
                    }),
                Expires = DateTime.UtcNow.AddDays(_jwtSettings.ExpirationDays),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            token = tokenHandler.CreateToken(tokenDescriptor);
        }

        private bool VerifyPassword(string givenPassword, byte[] storedPass)
        {
            if (givenPassword == null || storedPass == null)
            {
                return false;
            }

            // Remove the "0x" prefix if present
            if (givenPassword.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                givenPassword = givenPassword.Substring(2);
            }

            // Convert stored password bytes to hex string
            string storedPassHex = BitConverter.ToString(storedPass).Replace("-", "");

            // Hash the given password
            byte[] givenPasswordHash = HashPassword(givenPassword);

            // Compare the byte arrays
            return storedPass.SequenceEqual(givenPasswordHash);
        }




        public async Task<List<SearchResult>> SearchUserAsync(string searchTerm)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                var parameter = new DynamicParameters();
                parameter.Add("@SearchTerm", searchTerm);

                var searchResult = await connection.QueryAsync<SearchResult>(
                    "sp_SearchUserAccount",
                    parameter,
                    commandType: CommandType.StoredProcedure);

                return searchResult.ToList();
            }
        }
        public async Task<List<ContactsResult>> GetContactsAsync(int userID)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                var parameter = new DynamicParameters();
                parameter.Add("@UserID", userID);

                var contacts = await connection.QueryAsync<ContactsResult>(
                    "sp_GetContacts",
                    parameter,
                    commandType: CommandType.StoredProcedure);

                return contacts.ToList();
            }
        }


        public async Task<OpenConversationResult> OpenConversationAsync(int userID1, int userID2)
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
                return convResult.FirstOrDefault() ?? new OpenConversationResult();
            }
        }

        public async Task<List<MessageResult>> GetMessageHistoryAsync(int userID, int conversationID)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                var parameters = new DynamicParameters();
                parameters.Add("@UserID", userID);
                parameters.Add("@ConversationID", conversationID);

                var messageHistoryResult = await connection.QueryAsync<MessageResult>(
                                                            "sp_GetMessageHistory",
                                                            parameters,
                                                            commandType: CommandType.StoredProcedure);
                return messageHistoryResult.AsList() ?? new List<MessageResult>();
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
                parameters.Add("@EncryptedKey", message.EncryptedKey);
                parameters.Add("@IV", message.IV);
                parameters.Add("@SentTime", message.SentTime);

                await connection.ExecuteAsync("sp_SendMessage",
                                               parameters,
                                               commandType: CommandType.StoredProcedure);

                // add message sent feature later
            }
        }


        public byte[] HexToBytes(string hex)
        {
            if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                hex = hex.Substring(2);
            return Convert.FromHexString(hex);
        }
    }
}
