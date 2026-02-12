# Ace Job Agency – Application Security Assignment

.NET 8 ASP.NET Core MVC web application for **Ace Job Agency** (Membership Service) with the security features required by the practical assignment.

## Ace Job Agency Requirements (IT2163-01 to ITN2163-03)

- **Registration fields:** First Name, Last Name, Gender, NRIC (encrypted), Email (unique), Password, Confirm Password, Date of Birth, Resume (.docx or .pdf), Who Am I (all special chars allowed).
- **Security:** Strong password, **all PII encrypted in DB** (First Name, Last Name, Gender, NRIC, Email, DOB, Resume path, Who Am I — AES-256-CBC via Data Protection), min/max password age, session management, rate limiting, reCAPTCHA v3, input validation, CSRF/XSS/SQLi protection, audit logging, custom error pages.

## How to Run

1. **Prerequisites:** .NET 8 SDK.
2. **Restore and run:**
   ```bash
   dotnet restore
   dotnet run
   ```
3. Open `https://localhost:5xxx` or `http://localhost:5xxx` (see console for URL).
4. **Register** a new member, then **Login**. Homepage shows your details with NRIC decrypted for display.

## reCAPTCHA v3 (optional for local testing)

- To enable reCAPTCHA, get keys from [Google reCAPTCHA Admin](https://www.google.com/recaptcha/admin) (reCAPTCHA v3).
- In `appsettings.json` (or `appsettings.Development.json`), set:
  - `RecaptchaSettings:SiteKey` – your site key
  - `RecaptchaSettings:SecretKey` – your secret key
- If these are left as placeholders (`YOUR_RECAPTCHA_...`), login still works without reCAPTCHA (for development).

## Database

- SQLite file: `acejob.db` in the project directory (created on first run).
- Tables: Members, AuditLogs, LoginAttempts, PasswordHistories.
- **Encryption:** All member PII is stored encrypted (see **ENCRYPTION.md** for algorithm and fields).
- **Password age:** Configure `PasswordPolicy:MinPasswordAgeMinutes` and `PasswordPolicy:MaxPasswordAgeDays` in `appsettings.json`.

## Security Checklist

See `SECURITY-CHECKLIST-ACE-JOB.md` for the completed checklist for this application.
