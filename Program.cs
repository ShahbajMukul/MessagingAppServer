using Scalar.AspNetCore;
using MessagingAppServer.Endpoints;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Text;
using MessagingAppServer.Repositories;
using MessagingAppServer.Services;
using Microsoft.IdentityModel.Logging;


var builder = WebApplication.CreateBuilder(args);

// Add OpenApi for documentation
builder.Services.AddOpenApi();

builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.ListenAnyIP(5500, listenOptions =>
    {
        listenOptions.UseHttps();
    });
});
// Get the connection string – throw an error if not found
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
if (string.IsNullOrEmpty(connectionString))
{
    throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
}


// Configure HTTPS redirection on port 5500. Make sure your launch settings match.
/* builder.Services.AddHttpsRedirection(options =>
{
options.HttpsPort = 5500;
}); */

// Configure JWT settings.
// Ensure your configuration contains JwtSettings with a valid SecretKey.
var jwtSettings = builder.Configuration.GetSection("JwtSettings").Get<JwtSettings>();
if (string.IsNullOrEmpty(jwtSettings!.SecretKey))
{
    throw new InvalidOperationException("jwtSettings not found.");
}
builder.Services.AddSingleton(jwtSettings);

// Set up JWT Authentication.
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtSettings.SecretKey)),
        ValidateIssuer = false,
        ValidateAudience = jwtSettings.Audience,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromMinutes(5)
    };

    // Log authentication failures for debugging.
    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = context =>
        {
            Console.WriteLine($"Authentication failed: {context.Exception.Message}");
            return Task.CompletedTask;
        }
    };
});

// Add authorization.
builder.Services.AddAuthorization();

// Register your repository.
builder.Services.AddScoped<IMessagingRepository>(sp =>
new MessagingRepository(connectionString, jwtSettings));



// IMPORTANT: Order matters—first redirect to HTTPS, then handle CORS & authentication.
/* app.UseHttpsRedirection(); */
builder.Services.AddHttpsRedirection(options =>
{
    options.HttpsPort = 5500;
});
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowMyFrontendCalls", policy =>
        policy.WithOrigins(
            "http://localhost:8000",
            "https://localhost:8500",
            "https://localhost:8500",
            "https://10.0.0.23:5500",    // Your dev machine
            "http://10.0.0.23:5500",     // Your dev machine HTTP
            "https://10.0.2.16:8500"
        )
        .SetIsOriginAllowed(_ => true) // For development only
        .AllowAnyMethod()
        .AllowAnyHeader()
        .AllowCredentials());
});


builder.Services.AddSignalR(options =>
{
    options.EnableDetailedErrors = true;
    options.HandshakeTimeout = TimeSpan.FromSeconds(30);
    IdentityModelEventSource.ShowPII = true;
});



var app = builder.Build();

// In development, set up the OpenApi endpoints.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference(options =>
    {
        options.Title = "Messaging App API";
        options.HideClientButton = true;
    });
}
app.UseCors("AllowMyFrontendCalls");
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseEndpoints(endpoints =>
{
    endpoints.MapHub<ChatHub>("/chathub");
});
app.MapAppEndpoints();
app.Run();