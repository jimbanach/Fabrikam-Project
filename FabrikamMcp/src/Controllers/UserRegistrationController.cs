using FabrikamContracts.DTOs;
using FabrikamMcp.Services;
using Microsoft.AspNetCore.Mvc;

namespace FabrikamMcp.Controllers;

/// <summary>
/// Controller for user registration and GUID management across all authentication modes
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class UserRegistrationController : ControllerBase
{
    private readonly IUserRegistrationService _userRegistrationService;
    private readonly IServiceJwtService _serviceJwtService;
    private readonly ILogger<UserRegistrationController> _logger;
    private readonly GuidValidationSettings _guidSettings;

    public UserRegistrationController(
        IUserRegistrationService userRegistrationService,
        IServiceJwtService serviceJwtService,
        ILogger<UserRegistrationController> logger,
        IOptions<AuthenticationSettings> authSettings)
    {
        _userRegistrationService = userRegistrationService;
        _serviceJwtService = serviceJwtService;
        _logger = logger;
        _guidSettings = authSettings.Value.GuidValidation;
    }

    /// <summary>
    /// Register a new user for Disabled authentication mode
    /// </summary>
    /// <param name="request">User registration request</param>
    /// <returns>User registration response with GUID and service JWT</returns>
    [HttpPost("disabled-mode")]
    public async Task<ActionResult<UserRegistrationResponse>> RegisterDisabledModeUser(
        [FromBody] DisabledModeUserRegistrationRequest request)
    {
        try
        {
            // Validate input
            if (string.IsNullOrWhiteSpace(request.Name))
                return BadRequest("Name is required");
            
            if (string.IsNullOrWhiteSpace(request.Email))
                return BadRequest("Email is required");

            // Validate Microsoft GUID format if provided
            if (request.UserGuid.HasValue && request.UserGuid != Guid.Empty)
            {
                if (!IsValidMicrosoftGuid(request.UserGuid.Value))
                    return BadRequest("Invalid Microsoft GUID format");
            }

            // Register the user
            var userGuid = await _userRegistrationService.RegisterDisabledModeUserAsync(
                request.Name, 
                request.Email, 
                request.Organization, 
                request.SessionId);

            // Generate service JWT for API access
            var serviceJwt = await _serviceJwtService.GenerateServiceTokenAsync(
                userGuid, 
                AuthenticationMode.Disabled, 
                request.SessionId);

            var response = new UserRegistrationResponse
            {
                UserGuid = userGuid,
                ServiceJwt = serviceJwt,
                AuthenticationMode = AuthenticationMode.Disabled,
                ExpiresAt = DateTime.UtcNow.AddMinutes(60), // Default 1 hour
                Message = "User registered successfully for Disabled authentication mode"
            };

            _logger.LogInformation("Successfully registered disabled mode user {UserGuid} for {Email}", 
                userGuid, request.Email);

            return CreatedAtAction(nameof(GetUserByGuid), new { userGuid }, response);
        }
        catch (ArgumentException ex)
        {
            _logger.LogWarning("Invalid registration request: {Error}", ex.Message);
            return BadRequest(ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error registering disabled mode user for {Email}", request.Email);
            return StatusCode(500, "An error occurred while registering the user");
        }
    }

    /// <summary>
    /// Get user details by GUID
    /// </summary>
    /// <param name="userGuid">User GUID</param>
    /// <returns>User details</returns>
    [HttpGet("{userGuid:guid}")]
    public async Task<ActionResult<UserDetailsResponse>> GetUserByGuid(Guid userGuid)
    {
        try
        {
            if (userGuid == Guid.Empty)
                return BadRequest("Valid user GUID is required");

            // Validate Microsoft GUID format
            if (!IsValidMicrosoftGuid(userGuid))
                return BadRequest("Invalid Microsoft GUID format");

            var user = await _userRegistrationService.GetUserByGuidAsync(userGuid);
            
            if (user == null)
                return NotFound($"User with GUID {userGuid} not found");

            var response = new UserDetailsResponse
            {
                UserGuid = user.AuditGuid,
                Name = user.Name,
                Email = user.Email,
                AuthenticationMode = user.AuthenticationMode,
                RegistrationDate = user.RegistrationDate
            };

            return Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving user details for GUID {UserGuid}", userGuid);
            return StatusCode(500, "An error occurred while retrieving user details");
        }
    }

    /// <summary>
    /// Validate that a user GUID exists in the system
    /// </summary>
    /// <param name="userGuid">User GUID to validate</param>
    /// <returns>Validation result</returns>
    [HttpGet("{userGuid:guid}/validate")]
    public async Task<ActionResult<GuidValidationResponse>> ValidateUserGuid(Guid userGuid)
    {
        try
        {
            if (userGuid == Guid.Empty)
                return BadRequest("Valid user GUID is required");

            // Validate Microsoft GUID format
            if (!IsValidMicrosoftGuid(userGuid))
            {
                return Ok(new GuidValidationResponse
                {
                    UserGuid = userGuid,
                    IsValid = false,
                    Message = "Invalid Microsoft GUID format"
                });
            }

            var isValid = await _userRegistrationService.ValidateUserGuidAsync(userGuid);
            
            var response = new GuidValidationResponse
            {
                UserGuid = userGuid,
                IsValid = isValid,
                Message = isValid ? "User GUID is valid" : "User GUID not found in registry"
            };

            return Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating user GUID {UserGuid}", userGuid);
            return StatusCode(500, "An error occurred while validating the user GUID");
        }
    }

    /// <summary>
    /// Generate a new service JWT for an existing user
    /// </summary>
    /// <param name="userGuid">User GUID</param>
    /// <param name="request">JWT generation request</param>
    /// <returns>New service JWT</returns>
    [HttpPost("{userGuid:guid}/service-jwt")]
    public async Task<ActionResult<ServiceJwtResponse>> GenerateServiceJwt(
        Guid userGuid, 
        [FromBody] ServiceJwtRequest request)
    {
        try
        {
            if (userGuid == Guid.Empty)
                return BadRequest("Valid user GUID is required");

            // Validate Microsoft GUID format
            if (!IsValidMicrosoftGuid(userGuid))
                return BadRequest("Invalid Microsoft GUID format");

            // Validate user exists
            var userExists = await _userRegistrationService.ValidateUserGuidAsync(userGuid);
            if (!userExists)
                return NotFound($"User with GUID {userGuid} not found");

            // Generate new service JWT
            var serviceJwt = await _serviceJwtService.GenerateServiceTokenAsync(
                userGuid, 
                request.AuthenticationMode ?? AuthenticationMode.Disabled, 
                request.SessionId);

            var response = new ServiceJwtResponse
            {
                UserGuid = userGuid,
                ServiceJwt = serviceJwt,
                AuthenticationMode = request.AuthenticationMode ?? AuthenticationMode.Disabled,
                ExpiresAt = DateTime.UtcNow.AddMinutes(60), // Default 1 hour
                Message = "Service JWT generated successfully"
            };

            _logger.LogInformation("Generated new service JWT for user {UserGuid}", userGuid);

            return Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating service JWT for user {UserGuid}", userGuid);
            return StatusCode(500, "An error occurred while generating the service JWT");
        }
    }

    /// <summary>
    /// Health check endpoint for user registration service
    /// </summary>
    [HttpGet("health")]
    public IActionResult HealthCheck()
    {
        return Ok(new
        {
            Status = "Healthy",
            Service = "UserRegistration",
            Timestamp = DateTime.UtcNow,
            GuidValidation = new
            {
                Enabled = _guidSettings.ValidateMicrosoftGuidFormat,
                DatabaseValidation = _guidSettings.ValidateGuidInDatabase,
                CacheMinutes = _guidSettings.ValidationCacheMinutes
            }
        });
    }

    /// <summary>
    /// Validate Microsoft GUID format
    /// </summary>
    private bool IsValidMicrosoftGuid(Guid guid)
    {
        if (!_guidSettings.ValidateMicrosoftGuidFormat)
            return true;

        // Microsoft GUID format: a1b2c3d4-e5f6-7890-abcd-ef1234567890
        var guidString = guid.ToString().ToLower();
        return System.Text.RegularExpressions.Regex.IsMatch(guidString, _guidSettings.MicrosoftGuidPattern);
    }
}
