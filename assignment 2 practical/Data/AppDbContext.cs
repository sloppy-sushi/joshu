using Microsoft.EntityFrameworkCore;

namespace AceJobAgency.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<Models.Member> Members => Set<Models.Member>();
    public DbSet<Models.AuditLog> AuditLogs => Set<Models.AuditLog>();
    public DbSet<Models.LoginAttempt> LoginAttempts => Set<Models.LoginAttempt>();
    public DbSet<Models.PasswordHistory> PasswordHistories => Set<Models.PasswordHistory>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Models.Member>(e =>
        {
            e.HasIndex(m => m.EmailHash).IsUnique();
            e.Property(m => m.FirstNameEncrypted).HasMaxLength(500);
            e.Property(m => m.LastNameEncrypted).HasMaxLength(500);
            e.Property(m => m.GenderEncrypted).HasMaxLength(200);
            e.Property(m => m.NricEncrypted).HasMaxLength(500);
            e.Property(m => m.EmailEncrypted).HasMaxLength(1000);
            e.Property(m => m.DateOfBirthEncrypted).HasMaxLength(500);
            e.Property(m => m.ResumeFileNameEncrypted).HasMaxLength(1000);
            e.Property(m => m.WhoAmIEncrypted).HasMaxLength(4000);
        });
    }
}
