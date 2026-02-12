namespace AceJobAgency.Services;

/// <summary>
/// Encrypt/decrypt sensitive customer data. Encryption uses ASP.NET Core Data Protection
/// (AES-256-CBC + HMACSHA256). Email hash is for unique lookup only (SHA-256).
/// </summary>
public interface IDataEncryptionService
{
    string Encrypt(string plainText);
    string Decrypt(string cipherText);

    /// <summary>SHA-256 hash of normalized email for unique index (not reversible).</summary>
    string ComputeEmailHash(string email);
}
