namespace AceJobAgency.Services;

public interface IEmailService
{
    /// <summary>Send an email. Returns true if sent successfully.</summary>
    Task<bool> SendAsync(string toEmail, string subject, string body, CancellationToken ct = default);
}
