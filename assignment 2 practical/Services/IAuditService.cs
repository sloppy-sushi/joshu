namespace AceJobAgency.Services;

public interface IAuditService
{
    Task LogAsync(string userIdOrEmail, string action, string? details, HttpContext? httpContext);
}
