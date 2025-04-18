using Microsoft.AspNetCore.SignalR;
using System.Threading.Tasks;
using MessagingAppServer.Endpoints;
using MessagingAppServer.Models;
using Microsoft.AspNetCore.Authorization;

[Authorize]
public class ChatHub : Hub
{
    // inherets all methods we need for this scenario

    /* public override async Task OnConnectedAsync()
    {
        // map UserID to ConnectionID for easier handling
        var userID = Context.UserIdentifier;
        await Groups.AddToGroupAsync(Context.ConnectionId, $"conversation-{conversationId}");
        await base.OnConnectedAsync();
    } */

    /* public async Task JoinConversation(string conversationId)
    {
        await Groups.AddToGroupAsync(Context.ConnectionId, $"conversation-{conversationId}");
        Console.WriteLine($"[{DateTime.Now}] User {Context.UserIdentifier} joined conversation {conversationId}");
    } */
    public async Task JoinConversationGroup(string groupName)
    {
        if (!string.IsNullOrEmpty(groupName))
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, groupName);
            Console.WriteLine($"Client {Context.ConnectionId} joined group {groupName}");
        }
    }
    /* public async Task LeaveConversation(string conversationId)
    {
        await Groups.RemoveFromGroupAsync(Context.ConnectionId, $"conversation-{conversationId}");
        Console.WriteLine($"[{DateTime.Now}] User {Context.UserIdentifier} left conversation {conversationId}");
    } */
    public async Task LeaveConversationGroup(string groupName)
    {
        if (!string.IsNullOrEmpty(groupName))
        {
            await Groups.RemoveFromGroupAsync(Context.ConnectionId, groupName);
            Console.WriteLine($"Client {Context.ConnectionId} left group {groupName}");
        }
    }
    public override async Task OnConnectedAsync()
    {
        Console.WriteLine($"[{DateTime.Now}] User {Context.UserIdentifier} connected");
        await base.OnConnectedAsync();
    }

    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        Console.WriteLine($"[{DateTime.Now}] User {Context.UserIdentifier} disconnected");
        await base.OnDisconnectedAsync(exception);
    }
}