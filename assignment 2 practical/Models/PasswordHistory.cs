namespace AceJobAgency.Models;

/// <summary>Used to prevent password reuse (max 2 history).</summary>
public class PasswordHistory
{
    public int Id { get; set; }
    public int MemberId { get; set; }
    public Member? Member { get; set; }
    public string PasswordHash { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
