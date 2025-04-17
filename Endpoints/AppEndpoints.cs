using Azure.Core;
using MessagingAppServer.DBResutls;
using MessagingAppServer.DTOs;
using MessagingAppServer.Models;
using MessagingAppServer.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Primitives;
using System.Security.Claims;

namespace MessagingAppServer.Endpoints;

public static class AppEndpoints
{
    public static RouteGroupBuilder MapAppEndpoints(this WebApplication app)
    {
        app.MapGet("/", () => "Backend is running");
        var group = app.MapGroup("/api");

        group.MapPost("/register", RegisterUser).AllowAnonymous().WithName("Register");
        group.MapPost("/login", LoginUser).AllowAnonymous().WithName("Login");

        // The RequireAuthorization() attribute ensures the token is valid
        group.MapGet("/search", (string searchTerm, IMessagingRepository messagingRepository) => SearchUser(searchTerm, messagingRepository)).RequireAuthorization().WithName("Search");
        group.MapGet("/contacts", (IMessagingRepository messagingRepository, ClaimsPrincipal user) => GetContacts(messagingRepository, user)).RequireAuthorization().WithName("GetContacts");

        group.MapGet("/open-conversation", (int otherUserID, IMessagingRepository messagingRepository, ClaimsPrincipal user) => OpenConversation(otherUserID, messagingRepository, user))
            .RequireAuthorization()
            .WithName("OpenConversation");

        group.MapPost("/message", (MessageRequest messageRequest, IMessagingRepository messagingRepository, ClaimsPrincipal user, IHubContext<ChatHub> hubContext) => SendMessage(messageRequest, messagingRepository, user, hubContext)).RequireAuthorization().WithName("SendMessage");
        group.MapGet("/messages", (int conversationID, IMessagingRepository messagingRepository, ClaimsPrincipal user) => GetMessages(conversationID, messagingRepository, user)).RequireAuthorization().WithName("GetMessages");

        group.MapHub<ChatHub>("/chathub");

        group.MapGet("/test", Test);


        return group;
    }

    private static async Task<IResult> LoginUser(IMessagingRepository messagingRepository, LoginPayload loginData)
    {
        Console.WriteLine($"[{DateTime.Now}] Login attempt received for username: {loginData?.Username}");

        if (loginData == null)
        {
            Console.WriteLine($"[{DateTime.Now}] Login failed: Invalid login data received");
            return Results.BadRequest("Invalid login data. Possibly missing data.");
        }
        try
        {
            Console.WriteLine($"[{DateTime.Now}] Processing login for user: {loginData.Username}");
            var result = await messagingRepository.LoginUserAsync(loginData);
            if (result == null)
            {
                Console.WriteLine($"[{DateTime.Now}] Login failed for user: {loginData.Username} - Database validation failed");
                return Results.BadRequest("Error logging in. Checking failed against the database.");
            }
            Console.WriteLine($"[{DateTime.Now}] Login successful for user: {loginData.Username}");
            return Results.Ok(result);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now}] Login error for user {loginData.Username}: {ex}");
            return Results.InternalServerError();
        }
    }

    private static async Task<IResult> RegisterUser(IMessagingRepository messagingRepository, RegistrationPayload registrationData)
    {
        Console.WriteLine($"[{DateTime.Now}] Registration attempt received for username: {registrationData?.Username}");

        if (registrationData == null)
        {
            Console.WriteLine($"[{DateTime.Now}] Registration failed: Invalid registration data received");
            return Results.BadRequest("Invalid registartion data. Possibly missing data.");
        }
        try
        {
            Console.WriteLine($"[{DateTime.Now}] Processing registration for user: {registrationData.Username}");
            var result = await messagingRepository.RegisterUserAsync(registrationData);
            if (result == null)
            {
                Console.WriteLine($"[{DateTime.Now}] Registration failed for user: {registrationData.Username} - Database validation failed");
                return Results.BadRequest("Error registering. Checking failed against the database.");
            }
            Console.WriteLine($"[{DateTime.Now}] Registration successful for user: {registrationData.Username}");
            return Results.Ok(result);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now}] Registration error for user {registrationData.Username}: {ex}");
            return Results.InternalServerError();
        }
    }

    private static async Task Test(HttpContext context)
    {
        Console.WriteLine($"[{DateTime.Now}] Test endpoint called");
        await context.Response.WriteAsync("Test Successful!");
    }

    private static async Task<IResult> SearchUser(string searchTerm, IMessagingRepository messagingRepository)
    {
        Console.WriteLine($"[{DateTime.Now}] Search request received with term: {searchTerm}");

        if (string.IsNullOrEmpty(searchTerm))
        {
            Console.WriteLine($"[{DateTime.Now}] Search failed: Empty search term");
            return Results.BadRequest($"No data sent: '{searchTerm}'.");
        }

        try
        {
            Console.WriteLine($"[{DateTime.Now}] Processing search for term: {searchTerm}");
            var result = await messagingRepository.SearchUserAsync(searchTerm);
            if (result == null)
            {
                Console.WriteLine($"[{DateTime.Now}] Search failed for term: {searchTerm} - Database error");
                return Results.BadRequest("Error searching for user. Checking failed against the database.");
            }
            Console.WriteLine($"[{DateTime.Now}] Search completed for term: {searchTerm}");
            return Results.Ok(result);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now}] Search error for term {searchTerm}: {ex}");
            return Results.InternalServerError();
        }
    }

    private static async Task<IResult> GetContacts(IMessagingRepository messagingRepo, ClaimsPrincipal user)
    {
        Console.WriteLine($"[{DateTime.Now}] GetContacts request received");

        var userIDstr = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        Console.WriteLine($"[{DateTime.Now}] GetContacts processing for user ID: {userIDstr}");

        if (int.TryParse(userIDstr, out int userID))
        {
            Console.WriteLine($"[{DateTime.Now}] Successfully parsed user ID: {userID}");
        }
        else
        {
            Console.WriteLine($"[{DateTime.Now}] Failed to parse user ID: {userIDstr}");
            return Results.InternalServerError();
        }

        try
        {
            Console.WriteLine($"[{DateTime.Now}] Fetching contacts for user ID: {userID}");
            var result = await messagingRepo.GetContactsAsync(userID);
            Console.WriteLine($"[{DateTime.Now}] Successfully retrieved contacts for user ID: {userID}");
            return Results.Ok(result);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now}] Error retrieving contacts for user ID {userID}: {ex}");
            return Results.InternalServerError();
        }
    }

    private static async Task<IResult> OpenConversation(int otherUserID, IMessagingRepository messagingRepository, ClaimsPrincipal user)
    {
        Console.WriteLine($"[{DateTime.Now}] OpenConversation request received with other user ID: {otherUserID}");

        var mainUserIDStr = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (int.TryParse(mainUserIDStr, out int mainUserID))
        {
            Console.WriteLine($"[{DateTime.Now}] Opening conversation between users: {mainUserID} and {otherUserID}");
        }
        else
        {
            Console.WriteLine($"[{DateTime.Now}] Failed to parse user ID: {mainUserIDStr}");
            return Results.InternalServerError();
        }

        try
        {
            Console.WriteLine($"[{DateTime.Now}] Attempting to open conversation between users {mainUserID} and {otherUserID}");
            var result = await messagingRepository.OpenConversationAsync(mainUserID, otherUserID);
            if (result == null)
            {
                Console.WriteLine($"[{DateTime.Now}] Failed to open conversation between users {mainUserID} and {otherUserID}");
                return Results.BadRequest("Faced issue processing with the database");
            }
            Console.WriteLine($"[{DateTime.Now}] Successfully opened conversation ( between users {mainUserID} and {otherUserID}");
            return Results.Ok(result);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now}] Error opening conversation between users {mainUserID} and {otherUserID}: {ex}");
            return Results.InternalServerError();
        }
    }

    public static async Task<IResult> GetMessages(int conversationID, IMessagingRepository messagingRepository, ClaimsPrincipal user)
    {
        Console.WriteLine($"[{DateTime.Now}] GetMessages request received for conversation ID: {conversationID}");

        if (conversationID == 0)
        {
            Console.WriteLine($"[{DateTime.Now}] GetMessages failed: Invalid conversation ID: {conversationID}");
            return Results.BadRequest();
        }

        var mainUserIDstr = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (int.TryParse(mainUserIDstr, out int mainUserID))
        {
            Console.WriteLine($"[{DateTime.Now}] Getting messages for user ID: {mainUserID}, conversation ID: {conversationID}");
        }
        else
        {
            Console.WriteLine($"[{DateTime.Now}] Error converting user ID: {mainUserIDstr}");
            return Results.InternalServerError();
        }

        try
        {
            Console.WriteLine($"[{DateTime.Now}] Fetching message history for user ID: {mainUserID}, conversation ID: {conversationID}");
            var result = await messagingRepository.GetMessageHistoryAsync(mainUserID, conversationID);
            if (result == null)
            {
                Console.WriteLine($"[{DateTime.Now}] No messages found for conversation ID: {conversationID}");
                return Results.NoContent();
            }
            Console.WriteLine($"[{DateTime.Now}] Successfully retrieved messages for conversation ID: {conversationID}");
            return Results.Ok(result);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now}] Error retrieving messages for conversation ID {conversationID}: {ex}");
            return Results.InternalServerError();
        }
    }


    private static async Task<IResult> SendMessage(MessageRequest messageRequest, IMessagingRepository messagingRepository, ClaimsPrincipal user, IHubContext<ChatHub> hubContext)
    {


        Console.WriteLine($"[{DateTime.Now}] SendMessage request received for conversation ID: {messageRequest?.ConversationID}");

        if (string.IsNullOrEmpty(messageRequest?.Content) ||
        string.IsNullOrEmpty(messageRequest?.EncryptedKey) ||
        string.IsNullOrEmpty(messageRequest?.IV))
        {
            Console.WriteLine($"[{DateTime.Now}] SendMessage failed: Missing required message components");
            return Results.BadRequest("Missing required message components");
        }

        var senderUserIDstr = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (int.TryParse(senderUserIDstr, out int senderUserID))
        {
            Console.WriteLine($"[{DateTime.Now}] Message being sent by user ID: {senderUserID} to conversation ID: {messageRequest.ConversationID}");
        }
        else
        {
            Console.WriteLine($"[{DateTime.Now}] Error converting user ID: {senderUserIDstr}, expired token?");
            return Results.Unauthorized();
        }

        var message = new Message
        {
            ConversationID = messageRequest.ConversationID,
            Content = messageRequest.Content,
            EncryptedKey = messageRequest.EncryptedKey,
            SenderUserID = senderUserID,
            SentTime = messageRequest.SentTime,
            IsRead = false,
            IV = messageRequest.IV
        };

        try
        {
            Console.WriteLine($"[{DateTime.Now}] Sending message to conversation ID: {messageRequest.ConversationID}");
            await messagingRepository.SendMessageAsync(message);
            Console.WriteLine($"[{DateTime.Now}] Message successfully sent to conversation ID: {messageRequest.ConversationID}");

            // notify the recipient
            await hubContext.Clients.Group($"conversation-{messageRequest.ConversationID}")
            .SendAsync("ReceiveMessage", message);

            Console.WriteLine($"[{DateTime.Now}] Message successfully sent and broadcasted to conversation ID: {message.ConversationID}");

            return Results.Ok();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now}] Error sending message to conversation ID {messageRequest.ConversationID}: {ex}");
            return Results.InternalServerError();
        }
    }
}
