using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;

namespace AceJobAgency.Services;

/// <summary>Server-side input sanitization and validation to prevent injection and XSS.</summary>
public static class InputValidationService
{
    /// <summary>Normalize name input: trim and remove BOM, zero-width chars, non-breaking space so regex validation passes.</summary>
    public static string NormalizeName(string? input)
    {
        if (input == null) return string.Empty;
        var s = input.Trim();
        if (s.Length == 0) return string.Empty;
        s = s.Replace("\uFEFF", "");   // BOM
        s = s.Replace("\u200B", "");   // zero-width space
        s = s.Replace("\u200C", "");   // zero-width non-joiner
        s = s.Replace("\u200D", "");   // zero-width joiner
        s = s.Replace("\u00A0", " ");  // non-breaking space -> normal space
        return s.Trim();
    }

    /// <summary>Sanitize for safe display and DB storage (encode dangerous chars).</summary>
    public static string SanitizeForDisplay(string? input)
    {
        if (string.IsNullOrWhiteSpace(input)) return string.Empty;
        return System.Net.WebUtility.HtmlEncode(input.Trim());
    }

    /// <summary>Allow all special chars for Who Am I but still encode for XSS when storing/displaying.</summary>
    public static string SanitizeWhoAmI(string? input)
    {
        if (input == null) return string.Empty;
        return System.Net.WebUtility.HtmlEncode(input.Trim());
    }

    /// <summary>Validate email format (server-side).</summary>
    public static bool IsValidEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email)) return false;
        try
        {
            var addr = new System.Net.Mail.MailAddress(email);
            return addr.Address == email;
        }
        catch { return false; }
    }

    /// <summary>Validate NRIC format (e.g. S1234567A).</summary>
    public static bool IsValidNric(string? nric)
    {
        if (string.IsNullOrWhiteSpace(nric) || nric.Length != 9) return false;
        return Regex.IsMatch(nric, @"^[STFG]\d{7}[A-Z]$", RegexOptions.IgnoreCase);
    }

    /// <summary>Check password complexity: min 12, upper, lower, digit, special.</summary>
    public static (bool isValid, string? message) ValidatePasswordComplexity(string? password)
    {
        if (string.IsNullOrEmpty(password)) return (false, "Password is required.");
        if (password.Length < 12) return (false, "Password must be at least 12 characters.");
        if (!Regex.IsMatch(password, @"[a-z]")) return (false, "Password must contain a lowercase letter.");
        if (!Regex.IsMatch(password, @"[A-Z]")) return (false, "Password must contain an uppercase letter.");
        if (!Regex.IsMatch(password, @"\d")) return (false, "Password must contain a number.");
        if (!Regex.IsMatch(password, @"[^\da-zA-Z]")) return (false, "Password must contain a special character.");
        return (true, null);
    }

    /// <summary>Validate resume file: only .docx and .pdf allowed; checks extension and file content (magic bytes).</summary>
    public static async Task<(bool isValid, string? errorMessage)> ValidateResumeFileAsync(IFormFile? file, CancellationToken ct = default)
    {
        if (file == null || file.Length == 0) return (true, null);
        var ext = Path.GetExtension(file.FileName)?.ToLowerInvariant();
        if (ext != ".docx" && ext != ".pdf")
            return (false, "Only .docx (Word document) and .pdf files are allowed.");
        if (file.Length > 5 * 1024 * 1024) // 5MB
            return (false, "File size must be 5MB or less.");
        var header = new byte[5];
        await using (var stream = file.OpenReadStream())
        {
            var read = await stream.ReadAsync(header.AsMemory(0, 5), ct);
            if (read < 5) return (false, "File is too small or invalid.");
        }
        if (ext == ".pdf")
        {
            if (header[0] != 0x25 || header[1] != 0x50 || header[2] != 0x44 || header[3] != 0x46 || header[4] != 0x2D)
                return (false, "File content is not a valid PDF. Only .docx and .pdf files are allowed.");
        }
        else if (ext == ".docx")
        {
            if (header[0] != 0x50 || header[1] != 0x4B)
                return (false, "File content is not a valid Word document. Only .docx and .pdf files are allowed.");
        }
        return (true, null);
    }
}
