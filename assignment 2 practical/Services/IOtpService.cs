namespace AceJobAgency.Services;

public interface IOtpService
{
    /// <summary>Generate a 6-digit OTP, store it for the given email and purpose, and return the code.</summary>
    string GenerateAndStore(string email, string purpose, TimeSpan? expiry = null);

    /// <summary>Validate the OTP for the given email and purpose. Returns true if valid; removes the OTP on success.</summary>
    bool ValidateAndConsume(string email, string purpose, string code);
}
