using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;

namespace AceJobAgency.Services;

/// <summary>
/// Customer data encryption using ASP.NET Core Data Protection.
/// Algorithm: AES-256-CBC with HMACSHA256 (authenticated encryption).
/// See: https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/implementation/authenticated-encryption-details
/// </summary>
public class DataEncryptionService : IDataEncryptionService
{
    private readonly IDataProtector _protector;
    private const string Purpose = "AceJobAgency.MemberData";

    public DataEncryptionService(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector(Purpose);
    }

    public string Encrypt(string plainText)
    {
        if (string.IsNullOrEmpty(plainText)) return string.Empty;
        return _protector.Protect(plainText);
    }

    public string Decrypt(string cipherText)
    {
        if (string.IsNullOrEmpty(cipherText)) return string.Empty;
        try
        {
            return _protector.Unprotect(cipherText);
        }
        catch
        {
            return string.Empty;
        }
    }

    public string ComputeEmailHash(string email)
    {
        if (string.IsNullOrWhiteSpace(email)) return string.Empty;
        var normalized = email.Trim().ToLowerInvariant();
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(normalized));
        return Convert.ToHexString(bytes);
    }
}
