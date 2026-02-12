using System.ComponentModel.DataAnnotations;

namespace AceJobAgency.Models;

public class ForgotPasswordViewModel
{
    [Required(ErrorMessage = "Email is required.")]
    [EmailAddress(ErrorMessage = "Invalid email format.")]
    [Display(Name = "Email address")]
    public string Email { get; set; } = string.Empty;
}
