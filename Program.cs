using Scalar.AspNetCore;
using MessagingAppServer.Endpoints;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Text;
using MessagingAppServer.Repositories;
using MessagingAppServer.Services;
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
if (string.IsNullOrEmpty(connectionString))
{
    throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
}

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAllOrigins",
        builder =>
        {
            builder.AllowAnyOrigin()
                   .AllowAnyHeader()
                   .AllowAnyMethod();
        });
});

// Reference: Claude: Adding jwt for dotnet core backend auth

var jwtSettings = builder.Configuration.GetSection("JwtSettings").Get<JwtSettings>();

if (string.IsNullOrEmpty(jwtSettings!.SecretKey))
{
    throw new InvalidOperationException("jwtSettings not found.");
}
builder.Services.AddSingleton(jwtSettings);

// Add JWT Auth

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.ASCII.GetBytes(jwtSettings.SecretKey)),
            ValidateIssuer = false,
            ValidateAudience = jwtSettings.Audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(5)
        };

        // tests
        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                Console.WriteLine($"Authentication failed: {context.Exception.Message}");
                return Task.CompletedTask;
            }
        };

    });



builder.Services.AddAuthorization();
builder.Services.AddScoped<IMessagingRepository>(sp =>
    new MessagingRepository(connectionString, jwtSettings));



var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference(options =>
    {
        options.Title = "Messaging App API";
        options.HideClientButton = true;
    });
}

app.UseAuthentication();
app.UseAuthorization();

app.UseHttpsRedirection();
app.MapAppEndpoints();

app.Run();
