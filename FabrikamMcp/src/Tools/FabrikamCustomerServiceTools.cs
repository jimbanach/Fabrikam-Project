using System.ComponentModel;
using System.Net.Http.Json;
using System.Text.Json;
using FabrikamMcp.Services;
using ModelContextProtocol.Server;

namespace FabrikamMcp.Tools;

[McpServerToolType]
public class FabrikamCustomerServiceTools : AuthenticatedMcpToolBase
{
    public FabrikamCustomerServiceTools(
        HttpClient httpClient, 
        IConfiguration configuration,
        IAuthenticationService authService,
        ILogger<FabrikamCustomerServiceTools> logger) 
        : base(httpClient, configuration, authService, logger)
    {
    }

    // Temporarily disabled complex tools for build success
    // TODO: Convert to JsonDocument approach
    /*
    [McpServerTool, Description("Get support tickets with optional filtering by status, priority, category, region, assigned agent, or specific ticket ID. Use ticketId for detailed ticket info, or use filters for ticket lists. Set urgent=true for high/critical priority tickets. When called without parameters, returns active tickets requiring attention.")]
    public async Task<object> GetSupportTickets(
        int? ticketId = null,
        string? status = null,
        string? priority = null,
        string? category = null,
        string? region = null,
        string? assignedTo = null,
        bool urgent = false,
        int page = 1,
        int pageSize = 20)
    {
        try
        {
            var baseUrl = _configuration["FabrikamApi:BaseUrl"] ?? "https://localhost:7297";
            
            // If ticketId is provided, get specific ticket details
            if (ticketId.HasValue)
            {
                var ticketResponse = await _httpClient.GetAsync($"{baseUrl}/api/supporttickets/{ticketId.Value}");
                
                if (ticketResponse.IsSuccessStatusCode)
                {
                    var ticketJson = await ticketResponse.Content.ReadAsStringAsync();
                    var ticket = JsonSerializer.Deserialize<SupportTicketDetailDto>(ticketJson, new JsonSerializerOptions 
                    { 
                        PropertyNameCaseInsensitive = true 
                    });

                    return new
                    {
                        content = new object[]
                        {
                            new
                            {
                                type = "resource",
                                resource = new
                                {
                                    uri = $"{baseUrl}/api/supporttickets/{ticketId.Value}",
                                    name = $"Ticket #{ticket?.Id ?? ticketId.Value}",
                                    description = $"Support ticket for {ticket?.Customer.Name ?? "customer"}: {ticket?.Title ?? "N/A"}",
                                    mimeType = "application/json"
                                }
                            },
                            new
                            {
                                type = "text",
                                text = FormatTicketDetailText(ticket)
                            }
                        },
                        ticketData = ticket,
                        outputSchema = new
                        {
                            type = "object",
                            properties = new
                            {
                                id = new { type = "integer", description = "Ticket ID" },
                                ticketNumber = new { type = "string", description = "Ticket number" },
                                status = new { type = "string", description = "Current ticket status" },
                                priority = new { type = "string", description = "Ticket priority level" },
                                customerInfo = new { type = "object", description = "Customer information" },
                                resolutionDetails = new { type = "object", description = "Resolution information" }
                            }
                        }
                    };
                }
                
                if (ticketResponse.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    return new
                    {
                        error = new
                        {
                            code = 404,
                            message = $"Support ticket with ID {ticketId.Value} not found"
                        }
                    };
                }
                
                return new
                {
                    error = new
                    {
                        code = (int)ticketResponse.StatusCode,
                        message = $"Error retrieving support ticket {ticketId.Value}: {ticketResponse.StatusCode} - {ticketResponse.ReasonPhrase}"
                    }
                };
            }
            
            // Build query parameters for ticket list
            var queryParams = new List<string>();
            
            // If no filters provided, default to active tickets requiring attention
            if (string.IsNullOrEmpty(status) && string.IsNullOrEmpty(priority) && 
                string.IsNullOrEmpty(category) && string.IsNullOrEmpty(region) && 
                string.IsNullOrEmpty(assignedTo) && !urgent)
            {
                // Default to open/in-progress tickets that need attention
                queryParams.Add("status=Open,InProgress");
            }
            else
            {
                if (!string.IsNullOrEmpty(status)) queryParams.Add($"status={Uri.EscapeDataString(status)}");
                if (!string.IsNullOrEmpty(priority)) queryParams.Add($"priority={Uri.EscapeDataString(priority)}");
                if (!string.IsNullOrEmpty(category)) queryParams.Add($"category={Uri.EscapeDataString(category)}");
                if (!string.IsNullOrEmpty(region)) queryParams.Add($"region={Uri.EscapeDataString(region)}");
                if (!string.IsNullOrEmpty(assignedTo)) queryParams.Add($"assignedTo={Uri.EscapeDataString(assignedTo)}");
                
                // Handle urgent tickets filter
                if (urgent)
                {
                    queryParams.Add("urgent=true");
                }
            }
            
            queryParams.Add($"page={page}");
            queryParams.Add($"pageSize={pageSize}");

            var queryString = "?" + string.Join("&", queryParams);
            var response = await _httpClient.GetAsync($"{baseUrl}/api/supporttickets{queryString}");
            
            if (response.IsSuccessStatusCode)
            {
                var ticketsJson = await response.Content.ReadAsStringAsync();
                var tickets = JsonSerializer.Deserialize<SupportTicketInfoDto>(ticketsJson, new JsonSerializerOptions 
                { 
                    PropertyNameCaseInsensitive = true 
                });
                var totalCount = response.Headers.GetValues("X-Total-Count").FirstOrDefault();
                
                return new
                {
                    content = new object[]
                    {
                        new
                        {
                            type = "resource",
                            resource = new
                            {
                                uri = $"{baseUrl}/api/supporttickets{queryString}",
                                name = "Support Tickets",
                                description = GetTicketFilterDescription(status, priority, category, region, assignedTo, urgent),
                                mimeType = "application/json"
                            }
                        },
                        new
                        {
                            type = "text",
                            text = FormatTicketListText(tickets, totalCount, page, status, priority, urgent)
                        }
                    },
                    ticketsData = tickets,
                    pagination = new
                    {
                        page = page,
                        pageSize = pageSize,
                        totalCount = totalCount
                    },
                    outputSchema = new
                    {
                        type = "object",
                        properties = new
                        {
                            summary = new { type = "object", description = "Support ticket summary metrics" },
                            byPriority = new { type = "array", description = "Tickets grouped by priority" },
                            byCategory = new { type = "array", description = "Tickets grouped by category" },
                            recentTickets = new { type = "array", description = "Recent ticket details" }
                        }
                    }
                };
            }
            
            return new
            {
                error = new
                {
                    code = (int)response.StatusCode,
                    message = $"Error retrieving support tickets: {response.StatusCode} - {response.ReasonPhrase}"
                }
            };
        }
        catch (Exception ex)
        {
            return new
            {
                error = new
                {
                    code = 500,
                    message = $"Error retrieving support tickets: {ex.Message}"
                }
            };
        }
    }

    [McpServerTool, Description("Get customer service analytics including ticket volume, resolution times, and breakdowns by status, priority, and category.")]
    public async Task<object> GetCustomerServiceAnalytics(string? userGuid = null, string? fromDate = null, string? toDate = null)
    {
        // Validate GUID requirement based on authentication mode
        if (!await ValidateGuidRequirement(userGuid, nameof(GetCustomerServiceAnalytics)))
        {
            return CreateGuidValidationErrorResponse(userGuid, nameof(GetCustomerServiceAnalytics));
        }

        try
        {
            var baseUrl = GetApiBaseUrl();
            var queryParams = new List<string>();
            
            if (!string.IsNullOrEmpty(fromDate)) queryParams.Add($"fromDate={Uri.EscapeDataString(fromDate)}");
            if (!string.IsNullOrEmpty(toDate)) queryParams.Add($"toDate={Uri.EscapeDataString(toDate)}");

            var queryString = queryParams.Count > 0 ? "?" + string.Join("&", queryParams) : "";
            var response = await _httpClient.GetAsync($"{baseUrl}/api/supporttickets/analytics{queryString}");
            
            if (response.IsSuccessStatusCode)
            {
                var analytics = await response.Content.ReadAsStringAsync();
                return new
                {
                    content = new object[]
                    {
                        new
                        {
                            type = "text",
                            text = $"Customer service analytics:\n{analytics}"
                        }
                    }
                };
            }
            
            return new
            {
                content = new object[]
                {
                    new
                    {
                        type = "text",
                        text = $"Error retrieving customer service analytics: {response.StatusCode} - {response.ReasonPhrase}"
                    }
                },
                isError = true
            };
        }
        catch (Exception ex)
        {
            return new
            {
                content = new object[]
                {
                    new
                    {
                        type = "text",
                        text = $"Error retrieving customer service analytics: {ex.Message}"
                    }
                },
                isError = true
            };
        }
    }

    [McpServerTool, Description("Add a note to an existing support ticket. Specify if the note is internal (visible only to staff) or external (visible to customer).")]
    public async Task<string> AddTicketNote(int ticketId, string note, string createdBy, bool isInternal = false)
    {
        try
        {
            var baseUrl = _configuration["FabrikamApi:BaseUrl"] ?? "https://localhost:7297";
            var noteData = new
            {
                note = note,
                createdBy = createdBy,
                isInternal = isInternal
            };

            var response = await _httpClient.PostAsJsonAsync($"{baseUrl}/api/supporttickets/{ticketId}/notes", noteData);
            
            if (response.IsSuccessStatusCode)
            {
                return $"Successfully added {(isInternal ? "internal" : "external")} note to ticket {ticketId} by {createdBy}";
            }
            
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return $"Support ticket with ID {ticketId} not found";
            }
            
            var errorContent = await response.Content.ReadAsStringAsync();
            return $"Error adding note to ticket {ticketId}: {response.StatusCode} - {errorContent}";
        }
        catch (Exception ex)
        {
            return $"Error adding note to ticket {ticketId}: {ex.Message}";
        }
    }

    [McpServerTool, Description("Update a support ticket's status, priority, and/or assignment. Available statuses: Open, InProgress, PendingCustomer, Resolved, Closed, Cancelled")]
    public async Task<string> UpdateTicketStatus(
        int ticketId, 
        string status, 
        string? assignedTo = null, 
        string? priority = null)
    {
        try
        {
            var baseUrl = _configuration["FabrikamApi:BaseUrl"] ?? "https://localhost:7297";
            var updateData = new
            {
                status = status,
                assignedTo = assignedTo,
                priority = priority
            };

            var response = await _httpClient.PatchAsJsonAsync($"{baseUrl}/api/supporttickets/{ticketId}/status", updateData);
            
            if (response.IsSuccessStatusCode)
            {
                var details = new List<string> { $"Status updated to: {status}" };
                if (!string.IsNullOrEmpty(assignedTo)) details.Add($"Assigned to: {assignedTo}");
                if (!string.IsNullOrEmpty(priority)) details.Add($"Priority set to: {priority}");
                
                return $"Successfully updated ticket {ticketId}:\n{string.Join("\n", details)}";
            }
            
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return $"Support ticket with ID {ticketId} not found";
            }
            
            var errorContent = await response.Content.ReadAsStringAsync();
            return $"Error updating ticket {ticketId}: {response.StatusCode} - {errorContent}";
        }
        catch (Exception ex)
        {
            return $"Error updating ticket {ticketId}: {ex.Message}";
        }
    }

    private static string FormatTicketDetailText(SupportTicketDetailDto? ticket)
    {
        if (ticket == null) return "Ticket details not available.";

        return $"""
            🎫 SUPPORT TICKET DETAILS
            
            🆔 Ticket Information
            • ID: {ticket.Id}
            • Status: {GetTicketStatusEmoji(ticket.Status)} {ticket.Status}
            • Priority: {GetPriorityEmoji(ticket.Priority)} {ticket.Priority}
            • Category: {ticket.Category}
            • Created: {ticket.CreatedDate:MMM dd, yyyy HH:mm}
            {(ticket.LastUpdated.HasValue ? $"• Last Updated: {ticket.LastUpdated:MMM dd, yyyy HH:mm}" : "")}
            {(ticket.ResolvedDate.HasValue ? $"• Resolved: {ticket.ResolvedDate:MMM dd, yyyy HH:mm}" : "")}
            
            👤 Customer
            • Name: {ticket.Customer.Name}
            • Email: {ticket.Customer.Email}
            {(!string.IsNullOrEmpty(ticket.Customer.Phone) ? $"• Phone: {ticket.Customer.Phone}" : "")}
            
            📋 Issue Details
            • Title: {ticket.Title}
            • Description: {ticket.Description}
            
            {(ticket.AssignedAgent != null ? $"""
            👨‍💼 Assigned Agent
            • Name: {ticket.AssignedAgent.Name}
            • Email: {ticket.AssignedAgent.Email}
            • Department: {ticket.AssignedAgent.Department ?? "General"}
            
            """ : "👨‍💼 Assigned Agent: Unassigned\n\n")}
            
            {(ticket.Resolution != null ? $"""
            ✅ Resolution
            • Resolution: {ticket.Resolution.Resolution}
            • Resolved By: {ticket.Resolution.ResolvedBy.Name}
            • Resolved Date: {ticket.Resolution.ResolvedDate:MMM dd, yyyy HH:mm}
            {(ticket.Resolution.SatisfactionRating.HasValue ? $"• Satisfaction: {ticket.Resolution.SatisfactionRating}/5 ⭐" : "")}
            {(!string.IsNullOrEmpty(ticket.Resolution.CustomerFeedback) ? $"• Feedback: {ticket.Resolution.CustomerFeedback}" : "")}
            
            """ : "")}
            
            {(ticket.RelatedInfo.ProductId.HasValue ? $"""
            🔗 Related Information
            • Product: {ticket.RelatedInfo.ProductName} (ID: {ticket.RelatedInfo.ProductId})
            {(ticket.RelatedInfo.OrderId.HasValue ? $"• Order ID: {ticket.RelatedInfo.OrderId}" : "")}
            
            """ : "")}
            """;
    }

    private static string FormatTicketListText(SupportTicketInfoDto? tickets, string? totalCount, int page, string? status, string? priority, bool urgent)
    {
        if (tickets == null) return "No support tickets found.";

        var text = $"""
            🎫 FABRIKAM SUPPORT TICKETS
            
            📊 Summary
            • Total Tickets: {totalCount ?? "N/A"}
            • Page: {page}
            • Open: {tickets.Summary.OpenTickets}
            • In Progress: {tickets.Summary.InProgressTickets}
            • Resolved: {tickets.Summary.ResolvedTickets}
            """;

        // Add filter info if applied
        var filters = GetAppliedTicketFilters(status, priority, urgent);
        if (!string.IsNullOrEmpty(filters))
        {
            text += $"\n\n🔍 Applied Filters:\n{filters}";
        }

        // Show tickets by priority
        if (tickets.Summary.ByPriority?.Any() == true)
        {
            text += "\n\n⚡ By Priority:";
            foreach (var priorityGroup in tickets.Summary.ByPriority)
            {
                var emoji = GetPriorityEmoji(priorityGroup.Priority);
                text += $"\n• {emoji} {priorityGroup.Priority}: {priorityGroup.Count} tickets";
            }
        }

        // Show tickets by category
        if (tickets.Summary.ByCategory?.Any() == true)
        {
            text += "\n\n📂 By Category:";
            foreach (var categoryGroup in tickets.Summary.ByCategory.Take(5))
            {
                text += $"\n• {categoryGroup.Category}: {categoryGroup.Count} tickets";
            }
        }

        // Show recent tickets if available
        if (tickets.Tickets?.Any() == true)
        {
            text += "\n\n🕒 Recent Tickets:";
            foreach (var ticket in tickets.Tickets.Take(8))
            {
                var statusEmoji = GetTicketStatusEmoji(ticket.Status);
                var priorityEmoji = GetPriorityEmoji(ticket.Priority);
                text += $"\n• #{ticket.Id}: {ticket.Title} {statusEmoji} {priorityEmoji}";
            }
            if (tickets.Tickets.Count > 8)
            {
                text += $"\n... and {tickets.Tickets.Count - 8} more tickets";
            }
        }

        return text;
    }

    private static string GetTicketFilterDescription(string? status, string? priority, string? category, string? region, string? assignedTo, bool urgent)
    {
        var filters = new List<string>();
        
        if (!string.IsNullOrEmpty(status)) filters.Add($"Status: {status}");
        if (!string.IsNullOrEmpty(priority)) filters.Add($"Priority: {priority}");
        if (!string.IsNullOrEmpty(category)) filters.Add($"Category: {category}");
        if (!string.IsNullOrEmpty(region)) filters.Add($"Region: {region}");
        if (!string.IsNullOrEmpty(assignedTo)) filters.Add($"Assigned: {assignedTo}");
        if (urgent) filters.Add("Urgent only");

        return filters.Any() ? $"Filtered support tickets ({string.Join(", ", filters)})" : "All support tickets";
    }

    private static string GetAppliedTicketFilters(string? status, string? priority, bool urgent)
    {
        var filters = new List<string>();
        
        if (!string.IsNullOrEmpty(status)) filters.Add($"• Status: {status}");
        if (!string.IsNullOrEmpty(priority)) filters.Add($"• Priority: {priority}");
        if (urgent) filters.Add("• Urgent tickets only");

        return filters.Any() ? string.Join("\n", filters) : "";
    }

    private static string GetTicketStatusEmoji(string status)
    {
        return status.ToLower() switch
        {
            "open" => "🔓",
            "in progress" => "⚙️",
            "inprogress" => "⚙️",
            "resolved" => "✅",
            "closed" => "🔒",
            "on hold" => "⏸️",
            "onhold" => "⏸️",
            _ => "🎫"
        };
    }

    private static string GetPriorityEmoji(string priority)
    {
        return priority.ToLower() switch
        {
            "critical" => "🔥",
            "high" => "🔴",
            "medium" => "🟡",
            "low" => "🟢",
            _ => "⚪"
        };
    }
    */
}
