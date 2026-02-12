using AceJobAgency.Data;
using AceJobAgency.Models;
using AceJobAgency.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using reCAPTCHA.AspNetCore;

namespace AceJobAgency.Controllers;

public class AccountController : Controller
{
    private const int MaxFailedLoginAttempts = 3;
    private const int LockoutMinutes = 1;
    private const int SessionTimeoutMinutes = 1;
    private const string SessionKeyUserId = "AceJob_UserId";
    private const string SessionKeyEmail = "AceJob_Email";
    private const string SessionKeyCreated = "AceJob_SessionCreated";

    private readonly AppDbContext _db;
    private readonly IDataEncryptionService _encryption;
    private readonly IAuditService _audit;
    private readonly IRecaptchaService _recaptcha;
    private readonly IMemoryCache _cache;
    private readonly IWebHostEnvironment _env;
    private readonly IConfiguration _config;
    private readonly IEmailService _email;
    private readonly IOtpService _otp;

    public AccountController(
        AppDbContext db,
        IDataEncryptionService encryption,
        IAuditService audit,
        IRecaptchaService recaptcha,
        IMemoryCache cache,
        IWebHostEnvironment env,
        IConfiguration config,
        IEmailService email,
        IOtpService otp)
    {
        _db = db;
        _encryption = encryption;
        _audit = audit;
        _recaptcha = recaptcha;
        _cache = cache;
        _env = env;
        _config = config;
        _email = email;
        _otp = otp;
    }

    private bool IsSessionValid()
    {
        if (HttpContext.Session.GetInt32(SessionKeyUserId) == null) return false;
        var created = HttpContext.Session.GetString(SessionKeyCreated);
        if (string.IsNullOrEmpty(created) || !DateTime.TryParse(created, out var dt)) return false;
        if ((DateTime.UtcNow - dt).TotalMinutes > SessionTimeoutMinutes) return false;
        var userId = HttpContext.Session.GetInt32(SessionKeyUserId)!.Value;
        var expectedSessionId = _cache.Get<string>($"Session_{userId}");
        var currentSessionId = HttpContext.Session.Id;
        if (expectedSessionId != null && expectedSessionId != currentSessionId)
            return false; // Different device/tab login detected
        return true;
    }

    private void CreateSecureSession(Member member, string emailForSession)
    {
        HttpContext.Session.SetInt32(SessionKeyUserId, member.Id);
        HttpContext.Session.SetString(SessionKeyEmail, emailForSession);
        HttpContext.Session.SetString(SessionKeyCreated, DateTime.UtcNow.ToString("O"));
        _cache.Set($"Session_{member.Id}", HttpContext.Session.Id, TimeSpan.FromMinutes(SessionTimeoutMinutes + 5));
    }

    private void ClearSession()
    {
        var userId = HttpContext.Session.GetInt32(SessionKeyUserId);
        if (userId.HasValue) _cache.Remove($"Session_{userId}");
        HttpContext.Session.Clear();
    }

    [HttpGet]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None, Duration = 0)]
    public IActionResult Login(string? returnUrl = null)
    {
        if (IsSessionValid())
            return RedirectToAction("Index", "Home");
        ViewData["ReturnUrl"] = returnUrl;
        return View(new LoginViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl, CancellationToken ct)
    {
        ViewData["ReturnUrl"] = returnUrl;
        if (string.IsNullOrWhiteSpace(model.Email) || string.IsNullOrWhiteSpace(model.Password))
        {
            ModelState.AddModelError(string.Empty, "Email and password are required.");
            return View(model);
        }

        // reCAPTCHA v3 (skip when keys not configured, e.g. development)
        var secretKey = _config["RecaptchaSettings:SecretKey"] ?? "";
        if (!string.IsNullOrEmpty(secretKey) && !secretKey.StartsWith("YOUR_"))
        {
            var recaptcha = await _recaptcha.Validate(model.RecaptchaToken ?? string.Empty);
            if (!recaptcha.success)
            {
                ModelState.AddModelError(string.Empty, "reCAPTCHA validation failed. Please try again.");
                return View(model);
            }
        }

        var emailHash = _encryption.ComputeEmailHash(model.Email);
        var member = await _db.Members.AsNoTracking().FirstOrDefaultAsync(m => m.EmailHash == emailHash, ct);
        if (member == null)
        {
            await RecordFailedLogin(model.Email);
            await _audit.LogAsync(model.Email, "FailedLogin", "User not found", HttpContext);
            ModelState.AddModelError(string.Empty, "Invalid email or password.");
            return View(model);
        }

        if (member.IsLockedOut && member.LockoutEndUtc.HasValue && member.LockoutEndUtc.Value > DateTime.UtcNow)
        {
            var remaining = (member.LockoutEndUtc.Value - DateTime.UtcNow).TotalMinutes;
            ModelState.AddModelError(string.Empty, $"Account is locked. Try again in {Math.Ceiling(remaining)} minutes.");
            return View(model);
        }

        if (!BCrypt.Net.BCrypt.Verify(model.Password, member.PasswordHash))
        {
            await RecordFailedLogin(model.Email);
            await _audit.LogAsync(model.Email, "FailedLogin", "Invalid password", HttpContext);
            await CheckAndLockout(member, model.Email.Trim());
            ModelState.AddModelError(string.Empty, "Invalid email or password.");
            return View(model);
        }

        var emailTrimmed = model.Email.Trim();
        var attempts = await _db.LoginAttempts
            .Where(a => a.Email == emailTrimmed && !a.Success && a.AttemptedAt > DateTime.UtcNow.AddMinutes(-LockoutMinutes))
            .ToListAsync(ct);
        _db.LoginAttempts.RemoveRange(attempts);
        if (member.IsLockedOut)
        {
            member.IsLockedOut = false;
            member.LockoutEndUtc = null;
            _db.Members.Update(member);
        }
        await _db.SaveChangesAsync(ct);

        await _audit.LogAsync(emailTrimmed, "Login", "Success", HttpContext);

        var emailForSession = emailTrimmed.ToLowerInvariant();
        var loginToken = Guid.NewGuid().ToString("N");
        _cache.Set($"LoginToken_{loginToken}", (member.Id, emailForSession), TimeSpan.FromMinutes(5));

        // 2FA: send OTP to email and require verification before establishing session
        var otpCode = _otp.GenerateAndStore(emailForSession, "Login");
        var otpSent = await _email.SendAsync(emailForSession,
            "Your Ace Job Agency login code",
            $"<p>Your verification code is: <strong>{otpCode}</strong></p><p>It expires in 5 minutes. If you did not request this, ignore this email.</p>",
            ct);
        if (!otpSent)
            ModelState.AddModelError(string.Empty, "We could not send the verification code to your email. Please try again later.");
        if (!otpSent)
            return View(model);

        TempData["OtpSent"] = true;
        return RedirectToAction("VerifyOtp", new { token = loginToken });
    }

    [HttpGet]
    public IActionResult VerifyOtp(string? token)
    {
        if (string.IsNullOrEmpty(token))
            return RedirectToAction("Login");
        var key = $"LoginToken_{token}";
        var payload = _cache.Get<(int userId, string email)>(key);
        if (payload.userId <= 0 || string.IsNullOrEmpty(payload.email))
            return RedirectToAction("Login");
        return View(new VerifyOtpViewModel { Token = token });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult VerifyOtp(VerifyOtpViewModel model)
    {
        if (string.IsNullOrEmpty(model.Token))
            return RedirectToAction("Login");
        var key = $"LoginToken_{model.Token}";
        var payload = _cache.Get<(int userId, string email)>(key);
        if (payload.userId <= 0 || string.IsNullOrEmpty(payload.email))
        {
            ModelState.AddModelError(string.Empty, "This verification link has expired. Please log in again.");
            return View(model);
        }
        if (!_otp.ValidateAndConsume(payload.email, "Login", model.OtpCode ?? ""))
        {
            ModelState.AddModelError(nameof(model.OtpCode), "Invalid or expired code. Please check your email and try again.");
            return View(model);
        }
        return RedirectToAction("EstablishSession", new { token = model.Token });
    }

    [HttpGet]
    public async Task<IActionResult> EstablishSession(string? token, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(token))
            return RedirectToAction("Login");
        var key = $"LoginToken_{token}";
        var payload = _cache.Get<(int userId, string email)>(key);
        if (payload.userId <= 0 || string.IsNullOrEmpty(payload.email))
            return RedirectToAction("Login");

        var hasExistingSession = HttpContext.Session.GetInt32(SessionKeyUserId) != null;
        if (hasExistingSession)
        {
            Response.Cookies.Delete(".AspNetCore.Session", new CookieOptions { Path = "/" });
            return RedirectToAction("EstablishSession", new { token });
        }

        var (userId, emailForSession) = payload;
        var member = await _db.Members.AsNoTracking().FirstOrDefaultAsync(m => m.Id == userId, ct);
        if (member == null)
        {
            _cache.Remove(key);
            return RedirectToAction("Login");
        }

        CreateSecureSession(member, emailForSession);
        _cache.Remove(key);

        var maxPasswordAgeDays = _config.GetValue<int>("PasswordPolicy:MaxPasswordAgeDays", 90);
        if (member.LastPasswordChangeAt.HasValue &&
            (DateTime.UtcNow - member.LastPasswordChangeAt.Value).TotalDays > maxPasswordAgeDays)
        {
            TempData["Message"] = "Your password has expired. Please change it.";
            return RedirectToAction("ChangePassword");
        }
        return RedirectToAction("Index", "Home");
    }

    private async Task RecordFailedLogin(string email)
    {
        _db.LoginAttempts.Add(new LoginAttempt { Email = email, Success = false, IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() });
        await _db.SaveChangesAsync();
    }

    private async Task CheckAndLockout(Member member, string email)
    {
        var recentFailures = await _db.LoginAttempts
            .CountAsync(a => a.Email == email && !a.Success && a.AttemptedAt > DateTime.UtcNow.AddMinutes(-LockoutMinutes));
        if (recentFailures >= MaxFailedLoginAttempts)
        {
            member.IsLockedOut = true;
            member.LockoutEndUtc = DateTime.UtcNow.AddMinutes(LockoutMinutes);
            _db.Members.Update(member);
            await _db.SaveChangesAsync();
            await _audit.LogAsync(email, "AccountLocked", $"After {MaxFailedLoginAttempts} failed attempts", HttpContext);
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None, Duration = 0)]
    public async Task<IActionResult> Logout()
    {
        var email = HttpContext.Session.GetString(SessionKeyEmail);
        if (!string.IsNullOrEmpty(email))
            await _audit.LogAsync(email, "Logout", "User logged out", HttpContext);
        ClearSession();
        return RedirectToAction("Login");
    }

    [HttpGet]
    public IActionResult ForgotPassword()
    {
        if (IsSessionValid())
            return RedirectToAction("Index", "Home");
        return View(new ForgotPasswordViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model, CancellationToken ct)
    {
        if (IsSessionValid())
            return RedirectToAction("Index", "Home");
        if (!ModelState.IsValid)
            return View(model);
        var email = model.Email.Trim().ToLowerInvariant();
        var emailHash = _encryption.ComputeEmailHash(email);
        var member = await _db.Members.AsNoTracking().FirstOrDefaultAsync(m => m.EmailHash == emailHash, ct);
        if (member == null)
        {
            // Don't reveal that the email doesn't exist
            TempData["ForgotPasswordSent"] = "If an account exists for that email, we sent a verification code. Check your inbox.";
            return RedirectToAction("Login");
        }
        var resetToken = Guid.NewGuid().ToString("N");
        _cache.Set($"ResetToken_{resetToken}", email, TimeSpan.FromMinutes(5));
        var otpCode = _otp.GenerateAndStore(email, "ForgotPassword");
        var sent = await _email.SendAsync(email,
            "Reset your Ace Job Agency password",
            $"<p>Your verification code is: <strong>{otpCode}</strong></p><p>Use it on the reset password page. It expires in 5 minutes. If you did not request this, ignore this email.</p>",
            ct);
        if (!sent)
        {
            ModelState.AddModelError(string.Empty, "We could not send the code to your email. Please try again.");
            return View(model);
        }
        TempData["ForgotPasswordSent"] = "A verification code was sent to your email. Enter it on the next page.";
        return RedirectToAction("ResetPassword", new { token = resetToken });
    }

    [HttpGet]
    public IActionResult ResetPassword(string? token)
    {
        if (IsSessionValid())
            return RedirectToAction("Index", "Home");
        if (string.IsNullOrEmpty(token) || _cache.Get<string>($"ResetToken_{token}") == null)
            return RedirectToAction("ForgotPassword");
        return View(new ResetPasswordViewModel { Token = token });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model, CancellationToken ct)
    {
        if (IsSessionValid())
            return RedirectToAction("Login");
        var email = _cache.Get<string>($"ResetToken_{model.Token}");
        if (string.IsNullOrEmpty(email))
        {
            ModelState.AddModelError(string.Empty, "This reset link has expired. Please start again from Forgot password.");
            return View(model);
        }
        if (!_otp.ValidateAndConsume(email, "ForgotPassword", model.OtpCode ?? ""))
        {
            ModelState.AddModelError(nameof(model.OtpCode), "Invalid or expired code. Request a new code from Forgot password.");
            return View(model);
        }
        var (pwdValid, pwdMsg) = InputValidationService.ValidatePasswordComplexity(model.NewPassword);
        if (!pwdValid)
        {
            ModelState.AddModelError(nameof(model.NewPassword), pwdMsg ?? "Invalid password.");
            return View(model);
        }
        var emailHash = _encryption.ComputeEmailHash(email);
        var member = await _db.Members.FirstOrDefaultAsync(m => m.EmailHash == emailHash, ct);
        if (member == null)
        {
            _cache.Remove($"ResetToken_{model.Token}");
            return RedirectToAction("Login");
        }
        var lastTwo = await _db.PasswordHistories
            .Where(p => p.MemberId == member.Id)
            .OrderByDescending(p => p.CreatedAt)
            .Take(2)
            .ToListAsync(ct);
        foreach (var h in lastTwo)
        {
            if (BCrypt.Net.BCrypt.Verify(model.NewPassword, h.PasswordHash))
            {
                ModelState.AddModelError(nameof(model.NewPassword), "Cannot reuse any of your last 2 passwords.");
                return View(model);
            }
        }
        var newHash = BCrypt.Net.BCrypt.HashPassword(model.NewPassword, BCrypt.Net.BCrypt.GenerateSalt(12));
        member.PasswordHash = newHash;
        member.LastPasswordChangeAt = DateTime.UtcNow;
        _db.Members.Update(member);
        _db.PasswordHistories.Add(new PasswordHistory { MemberId = member.Id, PasswordHash = newHash });
        await _db.SaveChangesAsync(ct);
        var recent = await _db.PasswordHistories.Where(p => p.MemberId == member.Id).OrderByDescending(p => p.CreatedAt).Take(2).Select(p => p.Id).ToListAsync(ct);
        var toRemove = await _db.PasswordHistories.Where(p => p.MemberId == member.Id && !recent.Contains(p.Id)).ToListAsync(ct);
        _db.PasswordHistories.RemoveRange(toRemove);
        await _db.SaveChangesAsync(ct);
        _cache.Remove($"ResetToken_{model.Token}");
        await _audit.LogAsync(email, "ResetPassword", "Password reset via forgot password", HttpContext);
        TempData["Message"] = "Your password has been reset. You can now log in.";
        return RedirectToAction("Login");
    }

    [HttpGet]
    public IActionResult Register()
    {
        if (IsSessionValid())
            return RedirectToAction("Index", "Home");
        return View(new RegisterViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterViewModel model, CancellationToken ct)
    {
        // Normalize names (strip BOM, zero-width chars, etc.) so "Justin" / "Tan" don't fail from invisible characters
        model.FirstName = InputValidationService.NormalizeName(model.FirstName);
        model.LastName = InputValidationService.NormalizeName(model.LastName);
        ModelState.Remove(nameof(model.FirstName));
        ModelState.Remove(nameof(model.LastName));
        TryValidateModel(model);

        // Server-side validation
        var (pwdValid, pwdMsg) = InputValidationService.ValidatePasswordComplexity(model.Password);
        if (!pwdValid)
            ModelState.AddModelError(nameof(model.Password), pwdMsg ?? "Invalid password.");

        if (!InputValidationService.IsValidEmail(model.Email))
            ModelState.AddModelError(nameof(model.Email), "Invalid email format.");

        if (!InputValidationService.IsValidNric(model.Nric))
            ModelState.AddModelError(nameof(model.Nric), "Invalid NRIC format (e.g. S1234567A).");

        var today = DateTime.Today;
        var maxDob = today.AddYears(-16);
        var minDob = today.AddYears(-120);
        if (model.DateOfBirth.HasValue)
        {
            if (model.DateOfBirth.Value > maxDob)
                ModelState.AddModelError(nameof(model.DateOfBirth), "You must be at least 16 years old.");
            if (model.DateOfBirth.Value < minDob)
                ModelState.AddModelError(nameof(model.DateOfBirth), "Date of birth is not valid.");
        }

        if (model.Resume != null)
        {
            var (resumeValid, resumeError) = await InputValidationService.ValidateResumeFileAsync(model.Resume, ct);
            if (!resumeValid)
                ModelState.AddModelError(nameof(model.Resume), resumeError ?? "Invalid file.");
        }

        if (!ModelState.IsValid)
            return View(model);

        var emailHash = _encryption.ComputeEmailHash(model.Email);
        if (await _db.Members.AnyAsync(m => m.EmailHash == emailHash, ct))
        {
            ModelState.AddModelError(nameof(model.Email), "This email is already registered.");
            return View(model);
        }

        string? resumePathForDb = null;
        if (model.Resume != null && model.Resume.Length > 0)
        {
            var ext = Path.GetExtension(model.Resume.FileName)?.ToLowerInvariant();
            var safeName = $"{Guid.NewGuid()}{ext}";
            var uploads = Path.Combine(_env.WebRootPath, "uploads", "resumes");
            Directory.CreateDirectory(uploads);
            var path = Path.Combine(uploads, safeName);
            await using (var stream = new FileStream(path, FileMode.Create))
                await model.Resume.CopyToAsync(stream, ct);
            resumePathForDb = $"uploads/resumes/{safeName}";
        }

        var whoAmIRaw = (model.WhoAmI ?? string.Empty).Trim();
        if (whoAmIRaw.Length > 2000) whoAmIRaw = whoAmIRaw[..2000];

        var member = new Member
        {
            FirstNameEncrypted = _encryption.Encrypt(InputValidationService.SanitizeForDisplay(model.FirstName)),
            LastNameEncrypted = _encryption.Encrypt(InputValidationService.SanitizeForDisplay(model.LastName)),
            GenderEncrypted = _encryption.Encrypt(model.Gender),
            NricEncrypted = _encryption.Encrypt(model.Nric.Trim().ToUpperInvariant()),
            EmailEncrypted = _encryption.Encrypt(model.Email.Trim().ToLowerInvariant()),
            EmailHash = emailHash,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(model.Password, BCrypt.Net.BCrypt.GenerateSalt(12)),
            DateOfBirthEncrypted = _encryption.Encrypt(model.DateOfBirth!.Value.ToString("O")),
            ResumeFileNameEncrypted = string.IsNullOrEmpty(resumePathForDb) ? null : _encryption.Encrypt(resumePathForDb),
            WhoAmIEncrypted = string.IsNullOrEmpty(whoAmIRaw) ? null : _encryption.Encrypt(whoAmIRaw),
            LastPasswordChangeAt = DateTime.UtcNow
        };
        _db.Members.Add(member);
        await _db.SaveChangesAsync(ct);

        _db.PasswordHistories.Add(new PasswordHistory { MemberId = member.Id, PasswordHash = member.PasswordHash });
        await _db.SaveChangesAsync(ct);

        await _audit.LogAsync(model.Email.Trim(), "Register", "New member registered", HttpContext);
        TempData["Message"] = "Registration successful. Please log in.";
        return RedirectToAction("Login");
    }

    [HttpGet]
    public IActionResult ChangePassword()
    {
        if (!IsSessionValid())
            return RedirectToAction("Login");
        return View(new ChangePasswordViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SendChangePasswordOtp(CancellationToken ct)
    {
        if (!IsSessionValid())
            return RedirectToAction("Login");
        var email = HttpContext.Session.GetString(SessionKeyEmail);
        if (string.IsNullOrEmpty(email))
            return RedirectToAction("Login");
        var otpCode = _otp.GenerateAndStore(email, "ChangePassword");
        var sent = await _email.SendAsync(email,
            "Your Ace Job Agency password change code",
            $"<p>Your verification code is: <strong>{otpCode}</strong></p><p>It expires in 5 minutes. If you did not request this, ignore this email and secure your account.</p>",
            ct);
        if (sent)
            TempData["OtpSent"] = "A verification code was sent to your email.";
        else
            TempData["OtpError"] = "We could not send the code. Please try again.";
        return RedirectToAction("ChangePassword");
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model, CancellationToken ct)
    {
        if (!IsSessionValid())
            return RedirectToAction("Login");

        var email = HttpContext.Session.GetString(SessionKeyEmail);
        if (string.IsNullOrEmpty(email))
            return RedirectToAction("Login");

        if (!_otp.ValidateAndConsume(email, "ChangePassword", model.OtpCode ?? ""))
            ModelState.AddModelError(nameof(model.OtpCode), "Invalid or expired code. Request a new code and try again.");

        var (pwdValid, pwdMsg) = InputValidationService.ValidatePasswordComplexity(model.NewPassword);
        if (!pwdValid)
            ModelState.AddModelError(nameof(model.NewPassword), pwdMsg ?? "Invalid password.");

        if (!ModelState.IsValid)
            return View(model);

        var userId = HttpContext.Session.GetInt32(SessionKeyUserId)!.Value;
        var member = await _db.Members.FirstOrDefaultAsync(m => m.Id == userId, ct);
        if (member == null) return RedirectToAction("Login");

        var minPasswordAgeMinutes = _config.GetValue<int>("PasswordPolicy:MinPasswordAgeMinutes", 1);
        if (member.LastPasswordChangeAt.HasValue &&
            (DateTime.UtcNow - member.LastPasswordChangeAt.Value).TotalMinutes < minPasswordAgeMinutes)
        {
            var waitMins = Math.Ceiling(minPasswordAgeMinutes - (DateTime.UtcNow - member.LastPasswordChangeAt.Value).TotalMinutes);
            ModelState.AddModelError(string.Empty, $"You cannot change your password yet. Please wait {waitMins} more minute(s) (minimum password age).");
            return View(model);
        }

        var lastTwo = await _db.PasswordHistories
            .Where(p => p.MemberId == userId)
            .OrderByDescending(p => p.CreatedAt)
            .Take(2)
            .ToListAsync(ct);
        foreach (var h in lastTwo)
        {
            if (BCrypt.Net.BCrypt.Verify(model.NewPassword, h.PasswordHash))
            {
                ModelState.AddModelError(nameof(model.NewPassword), "Cannot reuse any of your last 2 passwords.");
                return View(model);
            }
        }

        var newHash = BCrypt.Net.BCrypt.HashPassword(model.NewPassword, BCrypt.Net.BCrypt.GenerateSalt(12));
        member.PasswordHash = newHash;
        member.LastPasswordChangeAt = DateTime.UtcNow;
        _db.Members.Update(member);
        _db.PasswordHistories.Add(new PasswordHistory { MemberId = member.Id, PasswordHash = newHash });
        await _db.SaveChangesAsync(ct);
        var recent = await _db.PasswordHistories.Where(p => p.MemberId == userId).OrderByDescending(p => p.CreatedAt).Take(2).Select(p => p.Id).ToListAsync(ct);
        var toRemove = await _db.PasswordHistories.Where(p => p.MemberId == userId && !recent.Contains(p.Id)).ToListAsync(ct);
        _db.PasswordHistories.RemoveRange(toRemove);
        await _db.SaveChangesAsync(ct);
        var sessionEmail = HttpContext.Session.GetString(SessionKeyEmail) ?? "";
        await _audit.LogAsync(sessionEmail, "ChangePassword", "Password changed", HttpContext);
        TempData["Message"] = "Password changed successfully.";
        return RedirectToAction("Index", "Home");
    }
}
