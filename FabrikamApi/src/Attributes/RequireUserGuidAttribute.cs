using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace FabrikamApi.Attributes;

/// <summary>
/// Attribute to require and validate X-User-GUID header for API endpoints
/// </summary>
public class RequireUserGuidAttribute : ActionFilterAttribute
{
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        var request = context.HttpContext.Request;
        
        // Check for X-User-GUID header
        if (!request.Headers.TryGetValue("X-User-GUID", out var guidHeader))
        {
            context.Result = new BadRequestObjectResult(new
            {
                error = "Missing required X-User-GUID header",
                message = "All API requests must include a valid X-User-GUID header"
            });
            return;
        }

        var guidValue = guidHeader.FirstOrDefault();
        if (string.IsNullOrWhiteSpace(guidValue))
        {
            context.Result = new BadRequestObjectResult(new
            {
                error = "Empty X-User-GUID header",
                message = "X-User-GUID header cannot be empty"
            });
            return;
        }

        // Validate GUID format
        if (!Guid.TryParse(guidValue, out var parsedGuid) || parsedGuid == Guid.Empty)
        {
            context.Result = new BadRequestObjectResult(new
            {
                error = "Invalid X-User-GUID format",
                message = $"X-User-GUID must be a valid GUID format, received: {guidValue}"
            });
            return;
        }

        // Store the GUID in HttpContext.Items for use in controllers
        context.HttpContext.Items["UserGuid"] = parsedGuid;
        
        base.OnActionExecuting(context);
    }
}
