using Microsoft.AspNetCore.Mvc;

namespace FabrikamApi.Controllers;

/// <summary>
/// Base controller providing common functionality for GUID-authenticated endpoints
/// </summary>
public abstract class GuidAuthenticatedControllerBase : ControllerBase
{
    /// <summary>
    /// Get the current user's GUID from the request context
    /// </summary>
    protected Guid GetCurrentUserGuid()
    {
        if (HttpContext.Items.TryGetValue("UserGuid", out var guidObj) && guidObj is Guid guid)
        {
            return guid;
        }
        
        // This should never happen if RequireUserGuidAttribute is applied correctly
        throw new InvalidOperationException("No valid user GUID found in request context");
    }

    /// <summary>
    /// Get the current user's GUID as a string from the request context
    /// </summary>
    protected string GetCurrentUserGuidString()
    {
        return GetCurrentUserGuid().ToString();
    }
}
