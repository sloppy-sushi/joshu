namespace AceJobAgency.Models;

public class LoginAttempt
{
    public int Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public bool Success { get; set; }
    public DateTime AttemptedAt { get; set; } = DateTime.UtcNow;
    public string? IpAddress { get; set; }
}
