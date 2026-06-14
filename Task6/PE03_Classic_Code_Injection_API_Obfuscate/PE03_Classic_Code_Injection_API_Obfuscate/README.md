# Classic Code Injection with API Obfuscation (PE 3)

## Tổng Quan Kỹ Thuật
Kỹ thuật tiêm mã từ xa kết hợp ẩn giấu dấu vết API nhằm vô hiệu hóa khả năng phân tích tĩnh (Static Analysis) của các giải pháp Antivirus/EDR bằng cách loại bỏ tên các hàm nhạy cảm ra khỏi bảng Import Address Table (IAT).

## Cơ Chế Hoạt Động
- Chương trình không liên kết trực tiếp với các hàm API Win32 khi biên dịch.
- Chuyển sang định nghĩa các kiểu dữ liệu đại diện cho hàm hệ thống (Function Pointers).
- Khi thục thi, chương trình tự động gọi `LoadLibraryW` để nạp `kernel32.dll` và dùng `GetProcAddress` để trỏ trực tiếp vào ô nhớ chứa hàm trên RAM, giúp bảng IAT hoàn toàn sạch sẽ.