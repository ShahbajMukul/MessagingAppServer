using MessagingAppServer.Models;
using MessagingAppServer.Repositories;

namespace MessagingAppServer.Endpoints;

public static class AppEndpoints
{
    public static RouteGroupBuilder MapAppEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api");
        group.MapPost("/register", RegisterUser).WithName("Register");
        group.MapPost("/login", LoginUser).WithName("Login");
        group.MapGet("/search/{searchTerm}", SearchUser).WithName("Search");
        group.MapGet("/conversation", GetConversation).WithName("GetConversation");
        group.MapPost("/message", SendMessage).WithName("SendMessage");
        group.MapGet("/messages/{userID}/{conversationID}", GetMessages).WithName("GetMessages");
        app.MapGet("/test", Test);


        return group;
    }

    private static async Task RegisterUser(HttpContext context, IMessagingRepository messageRepo)
    {
        // Read the user account from the request body
        var userAccount = await context.Request.ReadFromJsonAsync<UserAccount>();

        if (userAccount == null)
        {
            context.Response.StatusCode = 400;
            return;
        }
        
        // Register the user
        var registeredUser = await messageRepo.RegisterUser(userAccount);
    }

    private static async Task Login(HttpContext context, IMessagingRepository messageRepo)
    {
        var userAccount = await context.request.ReadFromJsonAsync<UserAccount>();

        if (userAccount == null)
        {
            context.Response.StatusCode = 400;
            return;
        }
    }

    private static async Task Test(HttpContext context)
    {
        await context.Response.WriteAsync("Test Successful!");
    }
}