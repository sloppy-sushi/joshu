using System.ComponentModel.DataAnnotations;

namespace AceJobAgency.Models;

public class RegisterViewModel
{
    [Required(ErrorMessage = "First name is required.")]
    [StringLength(100, MinimumLength = 1)]
    [RegularExpression(@"^[a-zA-Z\s\-'.]+$", ErrorMessage = "First name: only letters, spaces, hyphen, apostrophe and period allowed.")]
    [Display(Name = "First Name")]
    public string FirstName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Last name is required.")]
    [StringLength(100, MinimumLength = 1)]
    [RegularExpression(@"^[a-zA-Z\s\-'.]+$", ErrorMessage = "Last name: only letters, spaces, hyphen, apostrophe and period allowed.")]
    [Display(Name = "Last Name")]
    public string LastName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Gender is required.")]
    [StringLength(20)]
    [RegularExpression(@"^(Male|Female|Other)$", ErrorMessage = "Please select a valid gender.")]
    public string Gender { get; set; } = string.Empty;

    [Required(ErrorMessage = "NRIC is required.")]
    [StringLength(9, MinimumLength = 9)]
    [RegularExpression(@"^[STFG]\d{7}[A-Z]$", ErrorMessage = "Invalid NRIC format (e.g. S1234567A).")]
    [Display(Name = "NRIC")]
    public string Nric { get; set; } = string.Empty;

    [Required(ErrorMessage = "Email is required.")]
    [EmailAddress(ErrorMessage = "Invalid email format.")]
    [StringLength(256)]
    [Display(Name = "Email")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required.")]
    [DataType(DataType.Password)]
    [StringLength(256, MinimumLength = 12, ErrorMessage = "Password must be at least 12 characters.")]
    [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{12,}$",
        ErrorMessage = "Password must have 12+ chars with upper, lower, number and special character.")]
    [Display(Name = "Password")]
    public string Password { get; set; } = string.Empty;

    [Required(ErrorMessage = "Confirm password is required.")]
    [DataType(DataType.Password)]
    [Compare("Password", ErrorMessage = "Password and confirmation do not match.")]
    [Display(Name = "Confirm Password")]
    public string ConfirmPassword { get; set; } = string.Empty;

    [Required(ErrorMessage = "Date of birth is required.")]
    [DataType(DataType.Date)]
    [Display(Name = "Date of Birth")]
    public DateTime? DateOfBirth { get; set; }

    [Display(Name = "Resume (.docx or .pdf)")]
    public IFormFile? Resume { get; set; }

    [StringLength(2000)]
    [Display(Name = "Who Am I")]
    public string? WhoAmI { get; set; }
}
