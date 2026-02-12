using System.ComponentModel.DataAnnotations;

namespace AceJobAgency.Models;

/// <summary>
/// Ace Job Agency membership. All PII stored encrypted in DB (AES-256-CBC via ASP.NET Core Data Protection).
/// Email uniqueness enforced via EmailHash (SHA-256 of normalized email).
/// </summary>
public class Member
{
    public int Id { get; set; }

    /// <summary>Stored encrypted.</summary>
    public string FirstNameEncrypted { get; set; } = string.Empty;

    /// <summary>Stored encrypted.</summary>
    public string LastNameEncrypted { get; set; } = string.Empty;

    /// <summary>Stored encrypted.</summary>
    public string GenderEncrypted { get; set; } = string.Empty;

    /// <summary>Stored encrypted.</summary>
    public string NricEncrypted { get; set; } = string.Empty;

    /// <summary>Stored encrypted. Uniqueness via EmailHash.</summary>
    public string EmailEncrypted { get; set; } = string.Empty;

    /// <summary>SHA-256 hash of normalized email for unique lookup.</summary>
    [MaxLength(64)]
    public string EmailHash { get; set; } = string.Empty;

    /// <summary>Hashed password (BCrypt); never store plain text.</summary>
    public string PasswordHash { get; set; } = string.Empty;

    /// <summary>Stored encrypted (ISO date string).</summary>
    public string DateOfBirthEncrypted { get; set; } = string.Empty;

    /// <summary>Resume path stored encrypted (.docx or .pdf).</summary>
    public string? ResumeFileNameEncrypted { get; set; }

    /// <summary>Who Am I – all special chars allowed; stored encrypted.</summary>
    public string? WhoAmIEncrypted { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime? LastPasswordChangeAt { get; set; }

    public bool IsLockedOut { get; set; }
    public DateTime? LockoutEndUtc { get; set; }
}
