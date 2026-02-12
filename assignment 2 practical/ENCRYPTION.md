# Encryption Used in Ace Job Agency

## Type of Encryption

**Algorithm:** **AES-256-CBC** with **HMACSHA256** (authenticated encryption).

This is provided by **ASP.NET Core Data Protection** (`Microsoft.AspNetCore.DataProtection`). The implementation uses:

- **AES-256-CBC** for confidentiality
- **HMACSHA256** for authenticity (tamper detection)
- Key derivation via **NIST SP800-108** (KDF in Counter Mode with HMACSHA512)

Reference: [Authenticated encryption details in ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/implementation/authenticated-encryption-details)

## What Is Encrypted in the Database

All of the following member fields are stored **encrypted** in the database (same algorithm above):

| Field           | Stored as (column)        | Notes |
|----------------|---------------------------|--------|
| First Name     | `FirstNameEncrypted`       | Encrypted |
| Last Name      | `LastNameEncrypted`       | Encrypted |
| Gender         | `GenderEncrypted`         | Encrypted |
| NRIC           | `NricEncrypted`           | Encrypted |
| Email          | `EmailEncrypted`           | Encrypted; uniqueness enforced via `EmailHash` |
| Date of Birth  | `DateOfBirthEncrypted`    | Encrypted (ISO date string) |
| Resume path    | `ResumeFileNameEncrypted` | Encrypted file path |
| Who Am I       | `WhoAmIEncrypted`         | Encrypted (all special chars allowed) |

**Email uniqueness** is enforced using a **SHA-256** hash of the normalized email (`EmailHash`). The hash is not reversible; it is used only for duplicate checks and login lookup. The actual email value is in `EmailEncrypted` and is decrypted only when displaying on the homepage.

## Where Encryption/Decryption Happens

- **Encryption:** In `AccountController` during **Register**, before saving to the database. Implemented in `IDataEncryptionService` / `DataEncryptionService` (uses Data Protection with purpose `AceJobAgency.MemberData`).
- **Decryption:** In `HomeController` **Index** when loading the current member to show on the homepage. All encrypted columns are decrypted for display only; they are never stored or logged in plain text.

## Password Storage

Passwords are **hashed** with **BCrypt** (not encrypted). They are not reversible. This is separate from the AES encryption used for the fields above.
