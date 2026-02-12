using System.Diagnostics;
using AceJobAgency.Data;
using AceJobAgency.Models;
using AceJobAgency.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;

namespace AceJobAgency.Controllers;

public class HomeController : Controller
{
    private const string SessionKeyUserId = "AceJob_UserId";
    private const string SessionKeyEmail = "AceJob_Email";
    private const string SessionKeyCreated = "AceJob_SessionCreated";
    private const int SessionTimeoutMinutes = 1;

    private readonly ILogger<HomeController> _logger;
    private readonly AppDbContext _db;
    private readonly IDataEncryptionService _encryption;
    private readonly IMemoryCache _cache;

    public HomeController(ILogger<HomeController> logger, AppDbContext db, IDataEncryptionService encryption, IMemoryCache cache)
    {
        _logger = logger;
        _db = db;
        _encryption = encryption;
        _cache = cache;
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
            return false;
        return true;
    }

    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None, Duration = 0)]
    public async Task<IActionResult> Index(CancellationToken cancellationToken)
    {
        if (!IsSessionValid())
        {
            var uid = HttpContext.Session.GetInt32(SessionKeyUserId);
            var cachedSessionId = uid.HasValue ? _cache.Get<string>($"Session_{uid}") : null;
            if (uid.HasValue && cachedSessionId != null && HttpContext.Session.Id != cachedSessionId)
                TempData["Message"] = "You were logged in from another device or tab. Please log in again.";
            return RedirectToAction("Login", "Account");
        }

        var userId = HttpContext.Session.GetInt32(SessionKeyUserId)!.Value;
        var member = await _db.Members.AsNoTracking().FirstOrDefaultAsync(m => m.Id == userId, cancellationToken);
        if (member == null)
        {
            HttpContext.Session.Clear();
            return RedirectToAction("Login", "Account");
        }

        Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0";
        Response.Headers["Pragma"] = "no-cache";
        Response.Headers["Expires"] = "0";

        var vm = new HomeViewModel
        {
            FirstName = _encryption.Decrypt(member.FirstNameEncrypted),
            LastName = _encryption.Decrypt(member.LastNameEncrypted),
            Gender = _encryption.Decrypt(member.GenderEncrypted),
            Nric = _encryption.Decrypt(member.NricEncrypted),
            Email = _encryption.Decrypt(member.EmailEncrypted),
            DateOfBirth = DateTime.TryParse(_encryption.Decrypt(member.DateOfBirthEncrypted), out var dob) ? dob : default,
            WhoAmI = string.IsNullOrEmpty(member.WhoAmIEncrypted) ? null : _encryption.Decrypt(member.WhoAmIEncrypted),
            ResumeFileName = string.IsNullOrEmpty(member.ResumeFileNameEncrypted) ? null : _encryption.Decrypt(member.ResumeFileNameEncrypted)
        };
        return View(vm);
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error(int? statusCode = null)
    {
        if (statusCode.HasValue)
            Response.StatusCode = statusCode.Value;
        return View(new ErrorViewModel
        {
            RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier,
            StatusCode = statusCode ?? Response.StatusCode
        });
    }
}
