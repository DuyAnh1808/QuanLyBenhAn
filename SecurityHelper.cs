using System;
using System.Security.Cryptography;
using System.Text;
using BCrypt.Net;

namespace SecureMedicalTransfer
{
    public static class SecurityHelper
    {
        // AES-256 yêu cầu khóa đúng 32 bytes (256 bits)
        private static readonly byte[] EncryptionKey = Encoding.UTF8.GetBytes("SuperSecretKeyForMedical12345678");

        // 1. XỬ LÝ MẬT KHẨU (BCRYPT)
        public static string HashPassword(string password)
        {
            // Tự động thêm muối (Salt) và băm mật khẩu
            return BCrypt.Net.BCrypt.HashPassword(password);
        }

        public static bool VerifyPassword(string password, string hashedPassword)
        {
            // Kiểm tra mật khẩu gốc nhập vào với chuỗi hash trong DB
            try { return BCrypt.Net.BCrypt.Verify(password, hashedPassword); }
            catch { return false; }
        }

        // 2. MÃ HÓA BỆNH ÁN (AES-GCM)
        public static (byte[] ciphertext, byte[] tag, byte[] iv) EncryptMedicalRecord(string plaintext)
        {
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] ciphertext = new byte[plaintextBytes.Length];
            byte[] tag = new byte[16]; // Thẻ xác thực 16 bytes bắt buộc cho AES-GCM
            byte[] iv = new byte[12];  // Vector khởi tạo 12 bytes chuẩn GCM

            // Sinh IV ngẫu nhiên an toàn sinh học cho mỗi lần mã hóa
            RandomNumberGenerator.Fill(iv);

            using (AesGcm aesGcm = new AesGcm(EncryptionKey, tag.Length))
            {
                aesGcm.Encrypt(iv, plaintextBytes, ciphertext, tag);
            }

            return (ciphertext, tag, iv);
        }

        // 3. GIẢI MÃ BỆNH ÁN VÀ KIỂM TRA TÍNH TOÀN VẸN
        public static string DecryptMedicalRecord(byte[] ciphertext, byte[] tag, byte[] iv)
        {
            byte[] decryptedBytes = new byte[ciphertext.Length];

            using (AesGcm aesGcm = new AesGcm(EncryptionKey, tag.Length))
            {
                aesGcm.Decrypt(iv, ciphertext, tag, decryptedBytes);
            }

            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }
}