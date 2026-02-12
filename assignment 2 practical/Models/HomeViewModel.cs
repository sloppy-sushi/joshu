namespace AceJobAgency.Models;

public class HomeViewModel
{
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string Gender { get; set; } = string.Empty;
    public string Nric { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public DateTime DateOfBirth { get; set; }
    public string? WhoAmI { get; set; }
    public string? ResumeFileName { get; set; }
}
