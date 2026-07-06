using Microsoft.AspNetCore.Mvc;
using SecureMedicalTransfer.Models;
using System;
using System.Linq;

namespace SecureMedicalTransfer.Controllers
{
    public class AuthController : Controller
    {
        private readonly ApplicationDbContext _context;

        public AuthController(ApplicationDbContext context)
        {
            _context = context;
        }

        // MÀN HÌNH ĐĂNG NHẬP (BƯỚC 1)
        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }
        [HttpPost]
        public IActionResult Login(string username, string password)
        {
            var user = _context.Users.FirstOrDefault(u => u.Username == username);
            
            if (user != null && password == "123456")
            {
                // Giữ tạm Username trong Session chờ xác thực bước 2
                HttpContext.Session.SetString("PendingUsername", username);

                // Sinh mã OTP giả lập gồm 6 số (Yêu cầu OTP giả lập)
                Random rand = new Random();
                string mockOtp = rand.Next(100000, 999999).ToString();

                // Lưu OTP vào Session để đối chiếu
                HttpContext.Session.SetString("CurrentOTP", mockOtp);

                // Ghi nhận vào log: Đăng nhập bước 1 thành công
                LogAction(username, "Đăng nhập Bước 1 (Mật khẩu)", "Thành công", $"Mã OTP giả lập hệ thống vừa sinh ra là: {mockOtp}");

                // Chuyển hướng sang màn hình nhập OTP
                return RedirectToAction("VerifyOTP");
            }

            // Ghi log đăng nhập thất bại
            LogAction(username ?? "Unknown", "Đăng nhập Bước 1 (Mật khẩu)", "Thất bại", "Sai tài khoản hoặc mật khẩu");
            ViewBag.Error = "Sai tài khoản hoặc mật khẩu!";
            return View();
        }

        // MÀN HÌNH XÁC THỰC OTP (BƯỚC 2)
        [HttpGet]
        public IActionResult VerifyOTP()
        {
            var pendingUser = HttpContext.Session.GetString("PendingUsername");
            if (string.IsNullOrEmpty(pendingUser)) return RedirectToAction("Login");

            // Lấy OTP từ Session để hiển thị "giả lập" cho người dùng thấy để copy điền vào
            ViewBag.MockOtpHint = HttpContext.Session.GetString("CurrentOTP");
            return View();
        }

        [HttpPost]
        public IActionResult VerifyOTP(string otp)
        {
            var username = HttpContext.Session.GetString("PendingUsername");
            var serverOtp = HttpContext.Session.GetString("CurrentOTP");

            if (string.IsNullOrEmpty(username)) return RedirectToAction("Login");

            // Kiểm tra mã OTP nhập vào có khớp không
            if (otp == serverOtp)
            {
                var user = _context.Users.First(u => u.Username == username);

                // Đăng nhập thành công hoàn toàn -> Lưu chính thức vào Session
                HttpContext.Session.SetString("Username", user.Username);
                HttpContext.Session.SetString("Role", user.Role);

                // Xóa các dữ liệu tạm
                HttpContext.Session.Remove("PendingUsername");
                HttpContext.Session.Remove("CurrentOTP");

                LogAction(username, "Xác thực 2FA (OTP)", "Thành công", "Đăng nhập hoàn tất vào hệ thống");

                // Điều hướng về trang chủ điều khiển dựa trên vai trò
                return RedirectToAction("Index", "Medical");
            }

            LogAction(username, "Xác thực 2FA (OTP)", "Thất bại", $"Nhập sai mã OTP (Nhập: {otp})");
            ViewBag.Error = "Mã OTP không chính xác!";
            ViewBag.MockOtpHint = serverOtp; // Hiện lại mã để người dùng thử lại
            return View();
        }

        // ĐĂNG XUẤT
        public IActionResult Logout()
        {
            string username = HttpContext.Session.GetString("Username") ?? "Unknown";
            LogAction(username, "Đăng xuất", "Thành công", null);
            HttpContext.Session.Clear();
            return RedirectToAction("Login");
        }

        // Hàm phụ để ghi Log nhanh vào SQL Server (Yêu cầu ghi log)
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