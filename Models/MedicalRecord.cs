using System;

namespace SecureMedicalTransfer.Models
{
    public class MedicalRecord
    {
        public int RecordID { get; set; }
        public string PatientName { get; set; } = string.Empty;
        public byte[] Ciphertext { get; set; } = Array.Empty<byte>();
        public byte[] AuthTag { get; set; } = Array.Empty<byte>();
        public byte[] IV { get; set; } = Array.Empty<byte>();
        public DateTime CreatedAt { get; set; } = DateTime.Now;
    }
}