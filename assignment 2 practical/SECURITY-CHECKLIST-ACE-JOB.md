# Web Application Security Checklist – Ace Job Agency

## Registration and User Data Management
- [x] Implement successful saving of member info into the database
- [x] Check for duplicate email addresses and handle appropriately
- [x] Implement strong password requirements:
  - [x] Minimum 12 characters
  - [x] Combination of lowercase, uppercase, numbers, and special characters
  - [x] Provide feedback on password strength
  - [x] Implement both client-side and server-side password checks
- [x] Encrypt sensitive user data in the database (First Name, Last Name, Gender, NRIC, Email, Date of Birth, Resume path, Who Am I — all encrypted with AES-256-CBC via Data Protection; decrypted only for display on homepage)
- [x] Implement proper password hashing and storage (BCrypt)
- [x] Implement file upload restrictions (.docx and .pdf only for Ace Job Agency)

## Session Management
- [x] Create a secure session upon successful login
- [x] Implement session timeout (20 minutes)
- [x] Route to homepage/login page after session timeout
- [x] Detect and handle multiple logins from different devices/browser tabs

## Login/Logout Security
- [x] Implement proper login functionality
- [x] Implement rate limiting (account lockout after 3 failed login attempts)
- [x] Perform proper and safe logout (clear session and redirect to login page)
- [x] Implement audit logging (save user activities in the database)
- [x] Redirect to homepage after successful login, displaying user info (including decrypted NRIC)

## Anti-Bot Protection
- [x] Implement Google reCAPTCHA v3 service

## Input Validation and Sanitization
- [x] Prevent injection attacks (parameterized queries via EF Core; no raw SQL)
- [x] Implement Cross-Site Request Forgery (CSRF) protection (ValidateAntiForgeryToken on forms)
- [x] Prevent Cross-Site Scripting (XSS) attacks (input sanitization and encoding before save/display)
- [x] Perform proper input sanitization, validation, and verification for all user inputs
- [x] Implement both client-side and server-side input validation
- [x] Display error or warning messages for improper input
- [x] Perform proper encoding before saving data into the database

## Error Handling
- [x] Implement graceful error handling on all pages
- [x] Create and display custom error pages (404, 403, and generic error)

## Software Testing and Security Analysis
- [ ] Perform source code analysis using external tools (e.g., GitHub) — *to be done by student*
- [ ] Address security vulnerabilities identified in the source code — *to be done by student*

## Advanced Security Features
- [x] Implement automatic account recovery after lockout period (15-minute lockout then auto-unlock)
- [x] Enforce password history (avoid password reuse, max 2 password history)
- [x] Implement change password functionality
- [ ] Implement reset password functionality (using email link or SMS)
- [x] Enforce minimum and maximum password age policies (min: cannot change within X minutes; max: must change after X days — configurable in appsettings)
- [ ] Implement Two-Factor Authentication (2FA)

## General Security Best Practices
- [x] Use HTTPS for all communications (configure in deployment)
- [x] Implement proper access controls and authorization (session-based; homepage requires login)
- [x] Follow secure coding practices
- [x] Implement logging and monitoring for security events (audit log)

## Documentation and Reporting
- [ ] Prepare a report on implemented security features — *to be done by student*
- [x] Complete and submit the security checklist
