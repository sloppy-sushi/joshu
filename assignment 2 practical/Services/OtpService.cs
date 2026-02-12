using Microsoft.Extensions.Caching.Memory;

namespace AceJobAgency.Services;

public class OtpService : IOtpService
{
    private const int OtpLength = 6;
    private static readonly TimeSpan DefaultExpiry = TimeSpan.FromMinutes(5);
    private readonly IMemoryCache _cache;

    public OtpService(IMemoryCache cache)
    {
        _cache = cache;
    }

    public string GenerateAndStore(string email, string purpose, TimeSpan? expiry = null)
    {
        var key = NormalizeKey(email, purpose);
        var code = Random.Shared.Next(0, (int)Math.Pow(10, OtpLength)).ToString("D" + OtpLength);
        _cache.Set(key, code, expiry ?? DefaultExpiry);
        return code;
    }

    public bool ValidateAndConsume(string email, string purpose, string code)
    {
        if (string.IsNullOrWhiteSpace(code)) return false;
        var key = NormalizeKey(email, purpose);
        if (!_cache.TryGetValue(key, out string? stored) || stored != code.Trim())
            return false;
        _cache.Remove(key);
        return true;
    }

    private static string NormalizeKey(string email, string purpose)
    {
        var normalized = (email ?? "").Trim().ToLowerInvariant();
        return $"Otp:{purpose}:{normalized}";
    }
}
