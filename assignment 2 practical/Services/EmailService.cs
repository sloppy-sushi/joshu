using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace AceJobAgency.Services;

public class EmailService : IEmailService
{
    private readonly IConfiguration _config;
    private readonly ILogger<EmailService> _logger;

    public EmailService(IConfiguration config, ILogger<EmailService> logger)
    {
        _config = config;
        _logger = logger;
    }

    /// <summary>Redact email for logging to avoid PII and log injection. Returns e.g. "***@domain.com".</summary>
    private static string RedactEmailForLog(string? email)
    {
        if (string.IsNullOrWhiteSpace(email)) return "(none)";
        var at = email.IndexOf('@', StringComparison.Ordinal);
        if (at <= 0) return "***";
        var domain = email[(at + 1)..].Trim();
        return string.IsNullOrEmpty(domain) ? "***" : "***@" + domain;
    }

    public async Task<bool> SendAsync(string toEmail, string subject, string body, CancellationToken ct = default)
    {
        var host = _config["Email:SmtpHost"];
        var port = _config.GetValue<int>("Email:SmtpPort", 587);
        var user = _config["Email:UserName"]?.Trim();
        // App Password is 16 chars; strip all whitespace (spaces, newlines, tabs) in case of copy-paste
        var password = _config["Email:Password"];
        if (!string.IsNullOrEmpty(password))
            password = string.Concat(password.Where(c => !char.IsWhiteSpace(c))).Trim();
        var fromAddress = (_config["Email:FromAddress"] ?? user)?.Trim();
        var fromName = _config["Email:FromName"] ?? "Ace Job Agency";

        if (string.IsNullOrEmpty(host) || string.IsNullOrEmpty(user) || string.IsNullOrEmpty(password))
        {
            _logger.LogWarning("Email not sent: SmtpHost, UserName or Password is missing in Email config.");
            return false;
        }

        try
        {
            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(fromName, fromAddress ?? user));
            message.To.Add(MailboxAddress.Parse(toEmail.Trim()));
            message.Subject = subject;
            message.Body = new TextPart("html") { Text = body };

            using var client = new SmtpClient();
            // Port 587: use STARTTLS; port 465 would use SSL
            var useSsl = _config.GetValue<bool>("Email:EnableSsl", true);
            if (port == 465)
                await client.ConnectAsync(host, port, SecureSocketOptions.SslOnConnect, ct);
            else
                await client.ConnectAsync(host, port, useSsl ? SecureSocketOptions.StartTlsWhenAvailable : SecureSocketOptions.None, ct);

            await client.AuthenticateAsync(user, password, ct);
            await client.SendAsync(message, ct);
            await client.DisconnectAsync(true, ct);

            _logger.LogInformation("Email sent successfully to {Recipient}.", RedactEmailForLog(toEmail));
            return true;
        }
        catch (MailKit.Security.AuthenticationException)
        {
            _logger.LogError("SMTP authentication failed. Check Email:UserName (full Gmail address) and Email:Password (16-char App Password from Google Account → Security → 2-Step Verification → App passwords).");
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send email to {Recipient}.", RedactEmailForLog(toEmail));
            return false;
        }
    }
}
