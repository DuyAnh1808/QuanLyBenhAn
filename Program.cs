using Microsoft.EntityFrameworkCore;
using SecureMedicalTransfer.Models;

var builder = WebApplication.CreateBuilder(args);

// 1. Đăng ký các dịch vụ (Services) vào Builder - PHẢI ĐẶT TRƯỚC builder.Build()
builder.Services.AddControllersWithViews();

// Đăng ký SQL Server DbContext
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Đăng ký Session (Đã sửa lại nằm đúng vị trí hợp lệ)
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(20);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

// =========================================================================
// ĐÂY LÀ ĐƯỜNG RANH GIỚI: Đọc dòng này xong hệ thống sẽ khóa cấu hình dịch vụ lại
var app = builder.Build();
// =========================================================================

// 2. Cấu hình HTTP request pipeline (Middleware) - PHẢI ĐẶT SAU builder.Build()
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

// BẮT BUỘC: Kích hoạt Session middleware (Đặt trước UseEndpoints hoặc MapControllerRoute)
app.UseSession();

// Định tuyến mặc định chạy thẳng vào trang đăng nhập
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Auth}/{action=Login}/{id?}");

app.Run();