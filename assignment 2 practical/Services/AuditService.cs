using AceJobAgency.Data;

namespace AceJobAgency.Services;

public class AuditService : IAuditService
{
    private readonly AppDbContext _db;

    public AuditService(AppDbContext db)
    {
        _db = db;
    }

    public async Task LogAsync(string userIdOrEmail, string action, string? details, HttpContext? httpContext)
    {
        var ip = httpContext?.Connection?.RemoteIpAddress?.ToString();
        var ua = httpContext?.Request?.Headers.UserAgent.ToString();
        _db.AuditLogs.Add(new Models.AuditLog
        {
            UserIdOrEmail = userIdOrEmail,
            Action = action,
            Details = details,
            IpAddress = ip,
            UserAgent = ua
        });
        await _db.SaveChangesAsync();
    }
}
