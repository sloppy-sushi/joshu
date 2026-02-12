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

            _logger.LogInformation("Email sent to {To}", toEmail);
            return true;
        }
        catch (MailKit.Security.AuthenticationException ex)
        {
            // Safe diagnostic: never log the password. Gmail App Passwords are 16 chars (no spaces).
            var at = user?.IndexOf('@', StringComparison.Ordinal) ?? -1;
            var userHint = (string.IsNullOrEmpty(user) || at <= 0) ? "?" : $"{user[0]}***@{user[(at + 1)..]}";
            _logger.LogError("SMTP login rejected. Check: (1) Email:UserName is your full Gmail address. (2) Email:Password is a 16-character App Password from Google Account → Security → 2-Step Verification → App passwords. Current config: User like {UserHint}, password length {PwdLen} chars (expect 16 for App Password).", userHint, password?.Length ?? 0);
            _logger.LogError(ex, "Failed to send email to {To}: {Message}", toEmail, ex.Message);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send email to {To}: {Message}", toEmail, ex.Message);
            return false;
        }
    }
}
