using Microsoft.EntityFrameworkCore;

namespace SecureMedicalTransfer.Models
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        // Định nghĩa các bảng dữ liệu kết nối tới SQL Server
        public DbSet<User> Users { get; set; }
        public DbSet<MedicalRecord> MedicalRecords { get; set; }
        public DbSet<AccessLog> AccessLogs { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Cấu hình Khóa chính cho các bảng dữ liệu
            modelBuilder.Entity<User>().HasKey(u => u.UserID);
            modelBuilder.Entity<MedicalRecord>().HasKey(m => m.RecordID);
            modelBuilder.Entity<AccessLog>().HasKey(a => a.LogID);
        }
    }
}