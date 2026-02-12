using System.ComponentModel.DataAnnotations;

namespace AceJobAgency.Models;

public class VerifyOtpViewModel
{
    [Required(ErrorMessage = "Login token is required.")]
    public string Token { get; set; } = string.Empty;

    [Required(ErrorMessage = "Verification code is required.")]
    [StringLength(6, MinimumLength = 6, ErrorMessage = "Enter the 6-digit code from your email.")]
    [Display(Name = "Verification code")]
    public string OtpCode { get; set; } = string.Empty;
}
