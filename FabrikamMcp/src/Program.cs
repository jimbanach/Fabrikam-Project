using FabrikamMcp.Tools;
using FabrikamMcp.Models;
using FabrikamMcp.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using ModelContextProtocol;
using ModelContextProtocol.Server;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add HttpClient for API calls
builder.Services.AddHttpClient();

// Add HTTP context accessor for authentication
builder.Services.AddHttpContextAccessor();

// Add memory cache for GUID validation caching
builder.Services.AddMemoryCache();

// Configure authentication settings
var authSettings = builder.Configuration.GetSection(AuthenticationSettings.SectionName).Get<AuthenticationSettings>() ?? new AuthenticationSettings();
builder.Services.Configure<AuthenticationSettings>(builder.Configuration.GetSection(AuthenticationSettings.SectionName));

// Add Entity Framework with in-memory database (for development)
builder.Services.AddDbContext<FabrikamDbContext>(options =>
    options.UseInMemoryDatabase("FabrikamMcpDb"));

// Register our services
builder.Services.AddScoped<IUserRegistrationService, UserRegistrationService>();
builder.Services.AddScoped<IServiceJwtService, ServiceJwtService>();

// Add controllers for user registration endpoints
builder.Services.AddControllers();

var jwtSettings = authSettings.Jwt;

if (authSettings.Mode == AuthenticationMode.BearerToken && !string.IsNullOrEmpty(jwtSettings.SecretKey))
{
    builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.SaveToken = true;
        options.RequireHttpsMetadata = jwtSettings.RequireHttpsMetadata;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = jwtSettings.ValidateIssuer,
            ValidateAudience = jwtSettings.ValidateAudience,
            ValidateLifetime = jwtSettings.ValidateLifetime,
            ValidateIssuerSigningKey = jwtSettings.ValidateIssuerSigningKey,
            ValidIssuer = jwtSettings.Issuer,
            ValidAudience = jwtSettings.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.SecretKey)),
            ClockSkew = TimeSpan.FromMinutes(jwtSettings.ClockSkewInMinutes)
        };

        // Configure JWT events for better error handling
        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                logger.LogWarning("MCP JWT Authentication failed: {Exception}", context.Exception.Message);
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                logger.LogDebug("MCP JWT token validated for user: {User}", context.Principal?.Identity?.Name);
                return Task.CompletedTask;
            }
        };
    });

    // Add authorization services
    builder.Services.AddAuthorization();
    
    // Add authentication service based on mode
    switch (authSettings.Mode)
    {
        case AuthenticationMode.BearerToken:
            builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();
            break;
        case AuthenticationMode.Disabled:
            builder.Services.AddScoped<IAuthenticationService, DisabledAuthenticationService>();
            break;
        case AuthenticationMode.EntraExternalId:
            // TODO: Add Entra External ID authentication service when implemented
            builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();
            break;
        default:
            throw new InvalidOperationException($"Unsupported authentication mode: {authSettings.Mode}");
    }
}
else
{
    // Add a dummy authentication service when authentication is disabled or not configured
    builder.Services.AddScoped<IAuthenticationService, DisabledAuthenticationService>();
}

// Configure authentication settings
builder.Services.Configure<AuthenticationSettings>(builder.Configuration.GetSection(AuthenticationSettings.SectionName));
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection(JwtSettings.SectionName));

// Add MCP server services with HTTP transport and Fabrikam business tools
builder.Services.AddMcpServer()
    .WithHttpTransport()
    .WithTools<FabrikamSalesTools>()
    .WithTools<FabrikamInventoryTools>()
    .WithTools<FabrikamCustomerServiceTools>()
    .WithTools<FabrikamProductTools>()
    .WithTools<FabrikamBusinessIntelligenceTools>();

// Add CORS for HTTP transport support in browsers
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}

// Enable CORS
app.UseCors();

// Add authentication and authorization middleware
if (authSettings.RequireUserAuthentication && !string.IsNullOrEmpty(jwtSettings.SecretKey))
{
    app.UseAuthentication();
    app.UseAuthorization();
}

// Map controllers for user registration endpoints
app.MapControllers();

// Map MCP endpoints to the standard /mcp path
app.MapMcp("/mcp");

// Add status and info endpoints
app.MapGet("/status", (IConfiguration configuration) =>
{
    var authConfig = configuration.GetSection(AuthenticationSettings.SectionName).Get<AuthenticationSettings>() ?? new AuthenticationSettings();
    
    return new
    {
        Status = "Ready",
        Service = "Fabrikam MCP Server",
        Version = "1.0.0",
        Description = "Model Context Protocol server for Fabrikam Modular Homes business operations",
        Transport = "HTTP",
        Authentication = new
        {
            Required = authConfig.RequireUserAuthentication,
            Method = authConfig.RequireUserAuthentication ? "JWT Bearer Token" : "None",
            Issuer = authConfig.Jwt.Issuer,
            Audience = authConfig.Jwt.Audience
        },
        BusinessModules = new[]
        {
            "Sales - Order management and customer analytics",
            "Inventory - Product catalog and stock monitoring", 
            "Customer Service - Support ticket management and resolution",
            "Products - Product catalog, inventory analytics and management",
            "Business Intelligence - Executive dashboards and performance alerts"
        },
        Timestamp = DateTime.UtcNow,
        Environment = app.Environment.EnvironmentName
    };
});

// Redirect root path to status for convenience
app.MapGet("/", () => Results.Redirect("/status"));

app.Run();
