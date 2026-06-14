
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

// Định nghĩa nguyên mẫu con trỏ hàm động để hóa giải rào cản IAT tĩnh
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

// Cấu trúc dữ liệu chứa con trỏ tuyệt đối hóa giải triệt để lỗi RIP-Relative Error
typedef struct _LOCAL_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec sống trên RAM
    char szCommand[32];       // Phân vùng chứa chuỗi lệnh thực thi chức năng nằm khít cấu trúc
} LOCAL_DATA, *PLOCAL_DATA;

// Hàm chức năng độc lập vị trí (PIC) gánh logic thực thi kịch khung
DWORD WINAPI LocalPayload(LPVOID lpParam) {
    PLOCAL_DATA pData = (PLOCAL_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Thực thi logic thông qua lệnh gọi con trỏ gián tiếp, độc lập với vị trí nạp RAM
        pData->pWinExec(pData->szCommand, SW_SHOWNORMAL);
    }
    return 0;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 01: CLASSIC LOCAL PROCESS CODE INJECTION" << std::endl;
    std::cout << "====================================================" << std::endl;

    SIZE_T functionSize = 500;

    // 1. Phân bổ trang bộ nhớ ảo mang thuộc tính thực thi thực tế (RWX) cục bộ
    std::cout << "[*] Dang yeu cau OS cap phat trang nho RWX cuc bo..." << std::endl;
    LPVOID localCodeBuffer = VirtualAlloc(NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!localCodeBuffer) {
        std::cerr << "[-] VirtualAlloc failed! Error Code: " << GetLastError() << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Trang nho Code RWX thiet lap tai: 0x" << std::hex << localCodeBuffer << std::endl;

    // 2. Phân bổ trang nhớ mang quyền Đọc/Ghi (RW) cho cấu trúc bảng dữ liệu tuyệt đối
    PLOCAL_DATA pLocalData = (PLOCAL_DATA)VirtualAlloc(NULL, sizeof(LOCAL_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pLocalData) {
        VirtualFree(localCodeBuffer, 0, MEM_RELEASE);
        return EXIT_FAILURE;
    }

    // Phân giải động tọa độ runtime thực tế của hàm API từ Export Address Table (EAT) của Kernel32
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        pLocalData->pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(pLocalData->szCommand, "cmd.exe /c start calc");

    // 3. Ánh xạ logic mã máy phẳng và tham số dữ liệu lên không gian ảo cục bộ
    RtlCopyMemory(localCodeBuffer, (LPVOID)LocalPayload, functionSize);
    std::cout << "[+] Anh xa logic ma may vao trang thuc thi hoan tat." << std::endl;

    // 4. Triệu hồi luồng nội bộ khai hỏa chức năng của Payload
    std::cout << "[*] Dang khoi tao luong CreateThread de khai hoa..." << std::endl;
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)localCodeBuffer, pLocalData, 0, NULL);
    
    if (hThread) {
        // Đồng bộ hóa luồng nhằm đảm bảo tiến trình cha gánh luồng xử lý dứt điểm phẳng sạch
        WaitForSingleObject(hThread, INFINITE); 
        std::cout << "[+] Local Code Real-time Injection Successful!" << std::endl;
        CloseHandle(hThread);
    } else {
        std::cerr << "[-] CreateThread that bai! Error Code: " << GetLastError() << std::endl;
    }

    // 5. Thu hồi và giải phóng triệt để các trang bộ nhớ ảo nhằm triệt tiêu rò rỉ tài nguyên (Memory Leak)
    VirtualFree(localCodeBuffer, 0, MEM_RELEASE);
    VirtualFree(pLocalData, 0, MEM_RELEASE);
    std::cout << "[+] Quy trinh giai phong vung nho ao hoan tat." << std::endl;

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
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
PS C:\Workspace\x64\Release> .\PE01_Local_Injection.exe
====================================================
[*] PE 01: CLASSIC LOCAL PROCESS CODE INJECTION
====================================================
[*] Dang yeu cau OS cap phat trang nho RWX cuc bo...
[+] Trang nho Code RWX thiet lap tai: 0x000001A24B7F0000
[+] Anh xa logic ma may vao trang thuc thi hoan tat.
[*] Dang khoi tao luong CreateThread de khai hoa...
[+] Local Code Real-time Injection Successful!
[+] Quy trinh giai phong vung nho ao hoan tat.

[*] Hoan thanh quy trinh. Nhan Enter de dong cua so...

```

> **Vị trí đặt ảnh minh chứng thực nghiệm kích hoạt logic Payload:**
> 

### 🎯 Phân tích hệ quả bộ nhớ:

* Khối mã máy được đưa vào trang bộ nhớ xác định, bẻ gãy hoàn toàn các hàng rào Import Table tĩnh.
* Ứng dụng Máy tính `calc.exe` được sinh ra độc lập tại runtime dưới dạng tiến trình con của Loader, chứng minh giải thuật thực thi mã Position-Independent Code hoàn thành xuất sắc kịch trần.

---