using System;

namespace SecureMedicalTransfer.Models
{
    public class AccessLog
    {
        public int LogID { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public string Username { get; set; } = string.Empty;
        public string Action { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public string? Details { get; set; }
    }
}