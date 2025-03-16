using Azure.Core;
using MessagingAppServer.DBResutls;
using MessagingAppServer.DTOs;
using MessagingAppServer.Models;
using MessagingAppServer.Repositories;
using Microsoft.AspNetCore.Authorization;
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

        group.MapPost("/message", (MessageRequest messsageRequest, IMessagingRepository messagingRepository, ClaimsPrincipal user) => SendMessage(messsageRequest, messagingRepository, user)).RequireAuthorization().WithName("SendMessage");
       group.MapGet("/messages", (int conversationID, IMessagingRepository messagingRepository, ClaimsPrincipal user) => GetMessages(conversationID, messagingRepository, user)).RequireAuthorization().WithName("GetMessages");
        app.MapGet("/test", Test);


        return group;
    }

    private static async Task<IResult> LoginUser(IMessagingRepository messagingRepository, LoginPayload loginData)
    {
        if (loginData == null)
        {
            return Results.BadRequest("Invalid login data. Possibly missing data.");
        }
        try
        {
            var result = await messagingRepository.LoginUserAsync(loginData);
            if (result == null)
            {
                return Results.BadRequest("Error logging in. Checking failed against the database.");
            }
            return Results.Ok(result);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
            return Results.InternalServerError();

        }

    }

    private static async Task<IResult> RegisterUser(IMessagingRepository messagingRepository, RegistrationPayload registrationData)
    {
        if (registrationData == null)
        {
            return Results.BadRequest("Invalid registartion data. Possibly missing data.");
        }
        try
        {
            var result = await messagingRepository.RegisterUserAsync(registrationData);
            if (result == null)
            {
                return Results.BadRequest("Error registering. Checking failed against the database.");
            }
            return Results.Ok(result);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
            return Results.InternalServerError();

        }
    }

    private static async Task Test(HttpContext context)
    {
        await context.Response.WriteAsync("Test Successful!");
    }

    private static async Task<IResult> SearchUser(string searchTerm, IMessagingRepository messagingRepository)
    {
        // 
        if (string.IsNullOrEmpty(searchTerm))
        {
            return Results.BadRequest($"No data sent: '{searchTerm}'.");
        }

        try
        {
            var result = await messagingRepository.SearchUserAsync(searchTerm);
            if (result == null)
            {
                return Results.BadRequest("Error searching for user. Checking failed against the database.");
            }
            return Results.Ok(result);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
            return Results.InternalServerError();

        }
    }

    private static async Task<IResult> GetContacts(IMessagingRepository messagingRepo, ClaimsPrincipal user)
    {
        var userIDstr = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if(int.TryParse(userIDstr, out int userID)) 
        {

        }
        else
        {
            Console.WriteLine($"Failed to parse {userIDstr}");
            return Results.InternalServerError();
        }

        try
        {
            var result = await messagingRepo.GetContactsAsync(userID);
            return Results.Ok(result);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
            return Results.InternalServerError();
        }
    }

    private static async Task<IResult> OpenConversation(int otherUserID, IMessagingRepository messagingRepository, ClaimsPrincipal user)
    {
        var mainUserIDStr = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (int.TryParse(mainUserIDStr, out int mainUserID))
        {
            // Console.WriteLine($"Parsed int: {mainUserID}");
        }
        else
        {
            Console.WriteLine($"Failed to parse {mainUserIDStr}");
            return Results.InternalServerError();
        }

        try
        {
            var result = await messagingRepository.OpenConversationAsync(mainUserID, otherUserID);
            if (result == null)
            {
                return Results.BadRequest("Faced issue processing with the database");
            }
            return Results.Ok(result);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
            return Results.InternalServerError();

        }
    }

    public static async Task<IResult> GetMessages(int conversationID, IMessagingRepository messagingRepository, ClaimsPrincipal user)
    {
        if (conversationID == 0)
        {
            return Results.BadRequest();
        }

        var mainUserIDstr = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (int.TryParse(mainUserIDstr, out int mainUserID))
        {
        }
        else
        {
            Console.WriteLine("Error converting mainuserid");
            return Results.InternalServerError();
        }

        try
        {
            var result = await messagingRepository.GetMessageHistoryAsync(mainUserID, conversationID);
            if (result == null)
            {
                return Results.NoContent();
            }
            return Results.Ok(result);  
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
            return Results.InternalServerError();
        }
    }


    private static async Task<IResult> SendMessage(MessageRequest messsageRequest, IMessagingRepository messagingRepository, ClaimsPrincipal user)
    {
        if (string.IsNullOrEmpty(messsageRequest.Content) ||
        string.IsNullOrEmpty(messsageRequest.EncryptedKey) ||
        string.IsNullOrEmpty(messsageRequest.IV))
        {
            return Results.BadRequest("Missing required message components");
        }

        var senderUserIDstr = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (int.TryParse(senderUserIDstr, out int senderUserID))
        {

        }
        else
        {
            Console.WriteLine("Error converting userid, expired token?");
            return Results.Unauthorized();
        }

        var message = new Message
        {
            ConversationID = messsageRequest.ConversationID,
            Content = messsageRequest.Content,          
            EncryptedKey = messsageRequest.EncryptedKey,
            SenderUserID = senderUserID,
            SentTime = messsageRequest.SentTime,
            IsRead = false,
            IV = messsageRequest.IV
        };

        try
        {
            await messagingRepository.SendMessageAsync(message);
            return Results.Ok();
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
            return Results.InternalServerError();
        }
    }
}
