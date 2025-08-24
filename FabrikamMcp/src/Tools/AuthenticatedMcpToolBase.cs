using System.ComponentModel;
using System.Reflection;
using System.Text;
using System.Text.Json;
using FabrikamMcp.Attributes;
using FabrikamMcp.Services;

namespace FabrikamMcp.Tools;

/// <summary>
/// Base class for authenticated MCP tools
/// Provides authentication context and authorization validation
/// </summary>
public abstract class AuthenticatedMcpToolBase
{
    protected readonly HttpClient _httpClient;
    protected readonly IConfiguration _configuration;
    protected readonly IAuthenticationService _authService;
    protected readonly ILogger _logger;
    protected readonly IHttpContextAccessor? _httpContextAccessor;

    protected AuthenticatedMcpToolBase(
        HttpClient httpClient, 
        IConfiguration configuration, 
        IAuthenticationService authService,
        ILogger logger,
        IHttpContextAccessor? httpContextAccessor = null)
    {
        _httpClient = httpClient;
        _configuration = configuration;
        _authService = authService;
        _logger = logger;
        _httpContextAccessor = httpContextAccessor;
    }

    /// <summary>
    /// Validate authorization for the current method call
    /// </summary>
    protected virtual bool ValidateAuthorization(string methodName)
    {
        // Get the method info
        var method = GetType().GetMethod(methodName);
        if (method == null)
        {
            _logger.LogWarning("Method {MethodName} not found for authorization check", methodName);
            return false;
        }

        // Check for McpAuthorize attribute
        var authorizeAttribute = method.GetCustomAttribute<McpAuthorizeAttribute>();
        if (authorizeAttribute == null)
        {
            // No authorization attribute - require authentication by default
            return _authService.IsAuthenticated();
        }

        // Allow anonymous access if specified
        if (authorizeAttribute.AllowAnonymous)
        {
            return true;
        }

        // Check authentication
        if (!_authService.IsAuthenticated())
        {
            _logger.LogWarning("Unauthorized access attempt to {MethodName} - user not authenticated", methodName);
            return false;
        }

        // Check role requirements
        if (authorizeAttribute.Roles.Any())
        {
            var hasRequiredRole = authorizeAttribute.Roles.Any(role => _authService.HasRole(role));
            if (!hasRequiredRole)
            {
                var userRoles = string.Join(", ", _authService.GetCurrentUserRoles());
                var requiredRoles = string.Join(", ", authorizeAttribute.Roles);
                _logger.LogWarning("Unauthorized access attempt to {MethodName} - user has roles [{UserRoles}] but requires [{RequiredRoles}]", 
                    methodName, userRoles, requiredRoles);
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Set GUID context for disabled authentication mode
    /// </summary>
    protected void SetGuidContext(string? userGuid)
    {
        if (!string.IsNullOrWhiteSpace(userGuid))
        {
            _authService.SetUserGuidContext(userGuid);
            _logger.LogDebug("Set GUID context for tool execution: {UserGuid}", userGuid);
        }
    }

    /// <summary>
    /// Validate and process user GUID parameter
    /// </summary>
    protected bool ValidateAndSetGuidContext(string? userGuid, string methodName)
    {
        if (string.IsNullOrWhiteSpace(userGuid))
        {
            _logger.LogWarning("No user GUID provided for {MethodName} in disabled authentication mode", methodName);
            return false;
        }

        if (!Guid.TryParse(userGuid, out var guidValue) || guidValue == Guid.Empty)
        {
            _logger.LogWarning("Invalid GUID format provided for {MethodName}: {UserGuid}", methodName, userGuid);
            return false;
        }

        SetGuidContext(userGuid);
        return true;
    }

    /// <summary>
    /// Create an authentication-aware error response
    /// </summary>
    protected object CreateAuthenticationErrorResponse(string methodName)
    {
        var context = _authService.CreateAuthenticationContext();
        
        string errorMessage;
        if (!context.IsAuthenticated)
        {
            errorMessage = "Authentication required. Please provide a valid JWT bearer token.";
        }
        else
        {
            errorMessage = $"Insufficient permissions. Your roles: [{string.Join(", ", context.Roles)}]";
        }

        _logger.LogWarning("Authentication error for {MethodName}: {ErrorMessage} (User: {User})", 
            methodName, errorMessage, context.GetDisplayName());

        return new
        {
            error = new
            {
                code = context.IsAuthenticated ? 403 : 401,
                message = errorMessage,
                method = methodName,
                timestamp = DateTime.UtcNow
            }
        };
    }

    /// <summary>
    /// Log tool usage for auditing
    /// </summary>
    protected void LogToolUsage(string methodName, object? parameters = null)
    {
        var context = _authService.CreateAuthenticationContext();
        
        _logger.LogInformation("MCP Tool Usage: {MethodName} by {User} with roles [{Roles}]", 
            methodName, context.GetDisplayName(), string.Join(", ", context.Roles));

        if (parameters != null)
        {
            _logger.LogDebug("MCP Tool Parameters for {MethodName}: {@Parameters}", methodName, parameters);
        }
    }

    /// <summary>
    /// Get the API base URL from configuration
    /// </summary>
    protected string GetApiBaseUrl()
    {
        return _configuration["FabrikamApi:BaseUrl"] ?? "https://localhost:7297";
    }

    /// <summary>
    /// Create HTTP headers with authentication if available
    /// </summary>
    protected async Task AddAuthenticationHeadersAsync(HttpRequestMessage request)
    {
        // In pure disabled mode, try to get token but don't fail if unavailable
        try
        {
            // Get JWT token if available (async to support service JWT generation)
            var jwtToken = await _authService.GetCurrentJwtTokenAsync();
            if (!string.IsNullOrEmpty(jwtToken))
            {
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwtToken);
                _logger.LogDebug("Added JWT authentication header to API request");
            }
            else
            {
                _logger.LogDebug("No JWT token available for API request");
            }
        }
        catch (Exception ex)
        {
            // In disabled mode, if JWT generation fails, continue without authentication
            _logger.LogDebug(ex, "Failed to get JWT token for API request - continuing without authentication");
        }

        // Add X-User-GUID header from the current context
        // In disabled mode, extract GUID from the current context
        var context = _authService.CreateAuthenticationContext();
        if (context.IsAuthenticated && !string.IsNullOrEmpty(context.UserId))
        {
            // Extract GUID from the UserId format "disabled-user-{guid}"
            if (context.UserId.StartsWith("disabled-user-") && context.UserId.Length > 14)
            {
                var guidPart = context.UserId.Substring(14);
                if (Guid.TryParse(guidPart, out var userGuid))
                {
                    request.Headers.Add("X-User-GUID", guidPart);
                    _logger.LogDebug("Added X-User-GUID header to API request: {UserGuid}", guidPart);
                }
                else
                {
                    _logger.LogWarning("Failed to parse GUID from UserId: {UserId}", context.UserId);
                }
            }
            else
            {
                _logger.LogWarning("UserId does not match expected disabled mode format: {UserId}", context.UserId);
            }
        }
        else
        {
            _logger.LogWarning("No authenticated user context available for API request");
        }
    }

    /// <summary>
    /// Create HTTP headers with authentication if available (legacy sync version)
    /// </summary>
    protected void AddAuthenticationHeaders(HttpRequestMessage request)
    {
        AddAuthenticationHeadersAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Create an authenticated HTTP client request with proper headers
    /// </summary>
    protected async Task<HttpResponseMessage> SendAuthenticatedRequest(string url, HttpMethod? method = null)
    {
        method ??= HttpMethod.Get;
        
        using var request = new HttpRequestMessage(method, url);
        await AddAuthenticationHeadersAsync(request);
        
        return await _httpClient.SendAsync(request);
    }

    /// <summary>
    /// Check if we're in Disabled authentication mode
    /// </summary>
    protected bool IsDisabledAuthenticationMode()
    {
        return _authService is DisabledAuthenticationService;
    }

    /// <summary>
    /// Get user GUID from HTTP context header
    /// </summary>
    protected string? GetUserGuidFromContext()
    {
        if (_httpContextAccessor?.HttpContext?.Request?.Headers != null)
        {
            // Check for X-User-GUID header
            if (_httpContextAccessor.HttpContext.Request.Headers.TryGetValue("X-User-GUID", out var headerValue))
            {
                var guidValue = headerValue.FirstOrDefault();
                if (!string.IsNullOrWhiteSpace(guidValue))
                {
                    _logger.LogDebug("Found user GUID in X-User-GUID header: {UserGuid}", guidValue);
                    return guidValue;
                }
            }

            // Fallback: Check query parameters
            if (_httpContextAccessor.HttpContext.Request.Query.TryGetValue("userGuid", out var queryValue))
            {
                var guidValue = queryValue.FirstOrDefault();
                if (!string.IsNullOrWhiteSpace(guidValue))
                {
                    _logger.LogDebug("Found user GUID in query parameter: {UserGuid}", guidValue);
                    return guidValue;
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Validate GUID requirement based on authentication mode
    /// </summary>
    protected async Task<bool> ValidateGuidRequirement(string? userGuid, string methodName)
    {
        // Get userGuid from HTTP context if not provided in parameters
        if (string.IsNullOrWhiteSpace(userGuid))
        {
            userGuid = GetUserGuidFromContext();
        }

        // In Disabled authentication mode, GUID is required
        if (IsDisabledAuthenticationMode())
        {
            // If no GUID provided, check if this is a Copilot Studio request
            if (string.IsNullOrWhiteSpace(userGuid))
            {
                // Check for Copilot Studio user agent or create default user
                userGuid = await GetOrCreateCopilotStudioUser();
                
                if (string.IsNullOrWhiteSpace(userGuid))
                {
                    _logger.LogWarning("User GUID is required in Disabled authentication mode for {MethodName}", methodName);
                    return false;
                }
            }

            if (!Guid.TryParse(userGuid, out var guidValue) || guidValue == Guid.Empty)
            {
                _logger.LogWarning("Invalid GUID format provided for {MethodName}: {UserGuid}", methodName, userGuid);
                return false;
            }

            // Set GUID context for disabled authentication
            SetGuidContext(userGuid);
            _logger.LogDebug("GUID validated and context set for Disabled mode: {UserGuid}", userGuid);
            return true;
        }

        // In BearerToken mode, GUID is optional but still useful for enhanced tracking
        if (!string.IsNullOrWhiteSpace(userGuid))
        {
            if (Guid.TryParse(userGuid, out var guidValue) && guidValue != Guid.Empty)
            {
                SetGuidContext(userGuid);
                _logger.LogDebug("Optional GUID provided for enhanced tracking in BearerToken mode: {UserGuid}", userGuid);
            }
            else
            {
                _logger.LogWarning("Invalid GUID format provided for {MethodName}, ignoring: {UserGuid}", methodName, userGuid);
            }
        }

        return true; // Always valid in BearerToken mode (GUID is optional)
    }

    /// <summary>
    /// Create GUID validation error response for Disabled mode
    /// </summary>
    protected object CreateGuidValidationErrorResponse(string? userGuid, string methodName)
    {
        string errorMessage;
        if (string.IsNullOrWhiteSpace(userGuid))
        {
            errorMessage = "❌ **User GUID Required**\n\n" +
                          "In Disabled authentication mode, you must provide a valid user GUID.\n\n" +
                          "**How to provide GUID:**\n" +
                          "• Via parameter: `\"userGuid\": \"12345678-1234-1234-1234-123456789012\"`\n" +
                          "• Via header: `X-User-GUID: 12345678-1234-1234-1234-123456789012`\n\n" +
                          "**Expected format:** `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`";
        }
        else
        {
            errorMessage = $"❌ **Invalid GUID Format**\n\n" +
                          $"The provided GUID `{userGuid}` is not in the correct format.\n\n" +
                          "**Expected format:** `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`\n" +
                          "**Example:** `12345678-1234-1234-1234-123456789012`";
        }

        return new
        {
            content = new object[]
            {
                new
                {
                    type = "text",
                    text = errorMessage
                }
            },
            isError = true
        };
    }

    /// <summary>
    /// Creates or retrieves a fallback user for Copilot Studio requests that don't provide userGuid
    /// </summary>
    /// <returns>A GUID for the Copilot Studio fallback user</returns>
    protected virtual async Task<string> GetOrCreateCopilotStudioUser()
    {
        try
        {
            // Use a deterministic GUID for Copilot Studio (matches Swagger default)
            var copilotStudioGuid = "a1b2c3d4-e5f6-7890-abcd-123456789012";
            
            var baseUrl = _configuration["FabrikamApi:BaseUrl"] ?? "https://localhost:7297";
            
            // Check if the user exists
            var checkResponse = await _httpClient.GetAsync($"{baseUrl}/api/customers/{copilotStudioGuid}");
            
            if (checkResponse.IsSuccessStatusCode)
            {
                _logger.LogInformation("Using existing Copilot Studio fallback user: {UserGuid}", copilotStudioGuid);
                return copilotStudioGuid;
            }
            
            // Create the fallback user if it doesn't exist
            var createUserRequest = new
            {
                Id = copilotStudioGuid,
                FirstName = "Copilot",
                LastName = "Studio",
                Email = "copilot.studio@fabrikam.com",
                Phone = "555-0100",
                Address = "Microsoft AI Campus",
                City = "Redmond",
                State = "WA",
                ZipCode = "98052",
                Country = "USA",
                IsActive = true,
                CreatedAt = DateTime.UtcNow
            };
            
            var json = JsonSerializer.Serialize(createUserRequest);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            
            var createResponse = await _httpClient.PostAsync($"{baseUrl}/api/customers", content);
            
            if (createResponse.IsSuccessStatusCode)
            {
                _logger.LogInformation("Created new Copilot Studio fallback user: {UserGuid}", copilotStudioGuid);
                return copilotStudioGuid;
            }
            
            _logger.LogWarning("Failed to create Copilot Studio fallback user. Status: {StatusCode}", createResponse.StatusCode);
            
            // If creation fails, still return the GUID - the user might exist but the check failed
            return copilotStudioGuid;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating Copilot Studio fallback user");
            
            // Return a deterministic fallback GUID even if the API call fails
            return "a1b2c3d4-e5f6-7890-abcd-123456789012";
        }
    }
}
