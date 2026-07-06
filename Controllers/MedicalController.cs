using Microsoft.AspNetCore.Mvc;
using SecureMedicalTransfer.Models;
using System;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http; // Đảm bảo dòng này có để sử dụng HttpContext.Session

namespace SecureMedicalTransfer.Controllers
{
    public class MedicalController : Controller
    {
        private readonly ApplicationDbContext _context;

        public MedicalController(ApplicationDbContext context)
        {
            _context = context;
        }

        // TRANG CHỦ ĐIỀU HƯỚNG THEO ROLE
        public IActionResult Index()
        {
            var username = HttpContext.Session.GetString("Username");
            var role = HttpContext.Session.GetString("Role");

            if (string.IsNullOrEmpty(username)) return RedirectToAction("Login", "Auth");

            ViewBag.Username = username;
            ViewBag.Role = role;

            // Lấy danh sách bệnh án từ DB để hiển thị
            var records = _context.MedicalRecords.ToList();
            return View(records);
        }

        // CHỨC NĂNG 1: BÁC SĨ TẠO VÀ MÃ HÓA BỆNH ÁN
        [HttpPost]
        public IActionResult CreateRecord(string patientName, string plainTextContent)
        {
            var username = HttpContext.Session.GetString("Username");
            var role = HttpContext.Session.GetString("Role");

            // Kiểm tra quyền tối thiểu của Bác sĩ (Yêu cầu phân quyền)
            if (role != "BacSi")
            {
                LogAction(username ?? "Khách", "Tạo bệnh án", "Thất bại", $"Tài khoản không đủ thẩm quyền (Role: {role})");
                return RedirectToAction("Index");
            }

            try
            {
                // Gọi thư viện mã hóa AES-GCM (Mã hóa có xác thực)
                var (ciphertext, tag, iv) = SecurityHelper.EncryptMedicalRecord(plainTextContent);

                var record = new MedicalRecord
                {
                    PatientName = patientName,
                    Ciphertext = ciphertext,
                    AuthTag = tag,
                    IV = iv,
                    CreatedAt = DateTime.Now
                };

                _context.MedicalRecords.Add(record);
                _context.SaveChanges();

                LogAction(username!, "Mã hóa bệnh án", "Thành công", $"Đã mã hóa dữ liệu của bệnh nhân {patientName}");
                TempData["Success"] = "Mã hóa và lưu bệnh án thành công!";
            }
            catch (Exception ex)
            {
                LogAction(username!, "Mã hóa bệnh án", "Thất bại", ex.Message);
            }

            return RedirectToAction("Index");
        }

        // 🔥 CHỨC NĂNG BỔ SUNG: BÁC SĨ CHỈNH SỬA VÀ MÃ HÓA LẠI BỆNH ÁN (HỢP PHÁP)
        [HttpPost]
        public IActionResult UpdateRecord(int recordId, string newPlainTextContent, string dateToken)
        {
            var username = HttpContext.Session.GetString("Username");
            var role = HttpContext.Session.GetString("Role");

            // 1. Kiểm tra quyền phân quyền (Chỉ Bác sĩ mới được sửa đổi)
            if (role != "BacSi")
            {
                LogAction(username ?? "Khách", "Chỉnh sửa bệnh án", "Thất bại", $"Từ chối truy cập: Tài khoản không phải Bác sĩ (Role: {role})");
                TempData["Error"] = "Chỉ có Bác sĩ mới có quyền chỉnh sửa nội dung bệnh án!";
                return RedirectToAction("Index");
            }

            // 1b. [BẬY AN NINH] Kiểm tra mã bảo mật động theo ngày hệ thống (Ví dụ: 6/7/2026 -> "672026")
            string todayExpectedToken = DateTime.Now.ToString("dMyyyy");
            if (string.IsNullOrEmpty(dateToken) || dateToken.Trim() != todayExpectedToken)
            {
                string inputToken = string.IsNullOrEmpty(dateToken) ? "Để trống" : dateToken;

                // Ghi nhận lịch sử tấn công của hacker vào hệ thống Log để Auditor theo dõi
                LogAction(username ?? "Hacker", "Chỉnh sửa bệnh án", "Phát hiện tấn công",
                    $"[CẢNH BÁO] Nhập sai mã xác thực động. Nhập vào: '{inputToken}'. Mã đúng yêu cầu: '{todayExpectedToken}'");

                TempData["Error"] = "CẢNH BÁO BẢO MẬT: Mã xác thực không chính xác! Hành động chỉnh sửa trái phép đã bị chặn đứng và ghi lại lịch sử kiểm toán.";
                return RedirectToAction("Index");
            }

            var record = _context.MedicalRecords.Find(recordId);
            if (record == null)
            {
                TempData["Error"] = "Không tìm thấy bệnh án cần chỉnh sửa.";
                return RedirectToAction("Index");
            }

            try
            {
                // 2. Gọi hàm mã hóa chuẩn của hệ thống để sinh ra bộ dữ liệu mã hóa mới hoàn toàn
                var (ciphertext, tag, iv) = SecurityHelper.EncryptMedicalRecord(newPlainTextContent);

                // 3. Ghi đè cập nhật lại toàn bộ các trường bảo mật liên quan đến thuật toán AES-GCM
                record.Ciphertext = ciphertext;
                record.AuthTag = tag;
                record.IV = iv;

                _context.SaveChanges();

                // 4. Lưu vết lại hành động vào hệ thống kiểm toán (Auditor)
                LogAction(username!, "Chỉnh sửa bệnh án", "Thành công", $"Bác sĩ đã cập nhật thành công nội dung mới cho bệnh án ID: {recordId}");
                TempData["Success"] = $"Cập nhật và tái mã hóa dữ liệu bệnh án #{recordId} thành công!";
            }
            catch (Exception ex)
            {
                LogAction(username!, "Chỉnh sửa bệnh án", "Thất bại", ex.Message);
                TempData["Error"] = "Lỗi xảy ra trong quá trình mã hóa lại dữ liệu: " + ex.Message;
            }

            return RedirectToAction("Index");
        }

        // CHỨC NĂNG 2: GIẢI MÃ BỆNH ÁN (Bác sĩ hoặc Nhân viên lưu trữ hợp lệ)
        [HttpPost]
        public IActionResult DecryptRecord(int id)
        {
            var username = HttpContext.Session.GetString("Username");
            var role = HttpContext.Session.GetString("Role");

            if (role != "BacSi" && role != "NhanVienLuuTru")
            {
                LogAction(username ?? "Khách", "Giải mã bệnh án", "Thất bại", "Từ chối truy cập: Sai vai trò.");
                TempData["Error"] = "Bạn không có quyền truy cập vào chức năng này!";
                return RedirectToAction("Index");
            }

            var record = _context.MedicalRecords.Find(id);
            if (record == null) return NotFound();

            try
            {
                // Giải mã dữ liệu gốc
                string decryptedText = SecurityHelper.DecryptMedicalRecord(record.Ciphertext, record.AuthTag, record.IV);

                LogAction(username!, "Giải mã bệnh án", "Thành công", $"Giải mã bệnh án ID: {id}");
                TempData["DecryptedText_" + id] = decryptedText;
            }
            catch (CryptographicException)
            {
                LogAction(username!, "Giải mã bệnh án", "Thất bại", $"Cảnh báo: Lỗi xác thực dữ liệu tại ID: {id}");
                TempData["Error"] = "Hệ thống bảo mật AES-GCM đã phát hiện dữ liệu bị chỉnh sửa trái phép và chặn giải mã thành công!";
            }

            return RedirectToAction("Index");
        }

        // CHỨC NĂNG 3: KIỂM THỬ BẮT BUỘC - SỬA CIPHERTEXT (Giả lập hacker)
        [HttpPost]
        public IActionResult AttackRecord(int id)
        {
            var username = HttpContext.Session.GetString("Username") ?? "Hacker";
            var record = _context.MedicalRecords.Find(id);
            if (record == null) return NotFound();

            try
            {
                // Giả lập hacker: Sửa đổi trực tiếp 1 bit dữ liệu Ciphertext trong bộ nhớ
                byte[] corruptedCiphertext = (byte[])record.Ciphertext.Clone();
                corruptedCiphertext[0] ^= 0x1; // Đảo bit đầu tiên

                // Cố gắng giải mã dữ liệu đã bị sửa đổi
                string decryptedText = SecurityHelper.DecryptMedicalRecord(corruptedCiphertext, record.AuthTag, record.IV);
                TempData["Error"] = "CẢNH BÁO NGUY HIỂM: Hệ thống vẫn giải mã được dữ liệu bị sửa đổi!";
            }
            catch (CryptographicException)
            {
                // AES-GCM sẽ tự động bắt được sai sót toàn vẹn và ném lỗi vào đây
                LogAction(username, "Kiểm thử phá hoại Ciphertext", "Chặn đứng thành công", $"Hệ thống phát hiện Ciphertext bệnh án ID {id} đã bị chỉnh sửa bit.");
                TempData["Error"] = "Hệ thống bảo mật AES-GCM đã phát hiện dữ liệu bị chỉnh sửa trái phép và chặn giải mã thành công!";
            }

            return RedirectToAction("Index");
        }

        // CHỨC NĂNG 4: XEM LOG TRUY CẬP (Chỉ dành cho Auditor)
        public IActionResult ViewLogs()
        {
            var username = HttpContext.Session.GetString("Username");
            var role = HttpContext.Session.GetString("Role");

            if (role != "Auditor")
            {
                LogAction(username ?? "Khách", "Xem Log hệ thống", "Thất bại", "Tài khoản không đủ quyền.");
                TempData["Error"] = "Bạn không có quyền truy cập vào chức năng này!";
                return RedirectToAction("Index");
            }

            var logs = _context.AccessLogs.OrderByDescending(l => l.Timestamp).ToList();
            return View(logs);
        }

        private void LogAction(string username, string action, string status, string? details)
        {
            var log = new AccessLog
            {
                Username = username,
                Action = action,
                Status = status,
                Details = details,
                Timestamp = DateTime.Now
            };
            _context.AccessLogs.Add(log);
            _context.SaveChanges();
        }
    }
}