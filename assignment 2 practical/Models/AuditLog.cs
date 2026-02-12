namespace AceJobAgency.Models;

public class AuditLog
{
    public int Id { get; set; }
    public string UserIdOrEmail { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty; // Login, Logout, Register, FailedLogin, etc.
    public string? Details { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
