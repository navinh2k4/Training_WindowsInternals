
---

# 📝 [PE 01] Classic Code Injection — Local Process

## 📌 1. Tổng Quan Kỹ Thuật (Overview)

**Classic Code Injection tại Tiến trình Cục bộ (Local Process)** là nấc thang khởi thủy trong chuỗi kỹ thuật Process Injection. Chức năng cốt lõi của Lab này là thực thi một khối mã máy độc lập vị trí (Position-Independent Code - PIC) lọt lòng bên trong không gian địa chỉ ảo của **chính tiến trình đang chạy (In-Process Context)** mà không cần phụ thuộc vào trình nạp PE Loader mặc định của Windows Subsystem.

### 🎯 Mục tiêu nghiên cứu:

* Hiểu rõ cơ chế quản lý trang nhớ User-mode của Windows OS thông qua hệ thống Win32 Subsystem API.
* Thiết lập giải pháp nạp mã máy độc lập vị trí dựa trên cấu trúc bảng tham số dữ liệu tuyệt đối toán học nhằm bẻ gãy rào cản lỗi tương đối RIP.

---

## 🔬 2. Giải Phẫu Cơ Chế Ngầm Của OS (Windows Internals)

Khi một chương trình C++ thông thường vận hành, mã nguồn và chuỗi hằng số tĩnh bị chia cắt vào các phân đoạn `.text` và `.rdata` riêng biệt trên ổ đĩa. Để hợp nhất và kích nổ logic chức năng độc lập tại một tọa độ vô định trên RAM, giải thuật của Lab PE 01 thực thi quy trình toán học qua 3 bước ngầm sau:

```
[Khởi tạo THREAD_DATA] ──> [VirtualAlloc: Cấp phát trang nhớ] ──> [RtlCopyMemory: Nạp mã] ──> [CreateThread: Khai hỏa]

```

1. **Cấp phát không gian ảo (`VirtualAlloc`)**: Hệ điều hành Windows quản lý bộ nhớ theo các trang (Pages - kích thước mặc định $4\text{ KB}$). Hàm này gửi yêu cầu xuống Kernel để đặt bảo lưu (`MEM_RESERVE`) và cam kết (`MEM_COMMIT`) một vùng không gian ảo riêng biệt mang quyền hạn **`PAGE_EXECUTE_READWRITE` (RWX)** để chuẩn bị làm bệ phóng cho luồng CPU.
2. **Ánh xạ logic phẳng (`RtlCopyMemory`)**: Tiến hành đổ toàn bộ khối mã máy cấu trúc hàm độc lập vị trí cùng thực thể bảng tham số tuyệt đối sang phân vùng ảo vừa được mở khóa.
3. **Khai hỏa dòng chảy hành vi (`CreateThread`)**: Trình triệu hồi luồng của Windows tạo ra một cấu trúc Thread Context mới trong nhân Kernel, nạp tọa độ của trang nhớ ảo vào thanh ghi chỉ mục lệnh `Rip` của CPU và đưa luồng vào hàng đợi sẵn sàng thực thi (Ready State) để CPU tự động rút lệnh xử lý.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn tuân thủ tiêu chuẩn bảo an kịch trần: **Cấp phát động thích ứng (Zero Static Buffers)** và **Bảo toàn ngữ cảnh tháp luồng hoàn hảo**.

```cpp
#include <windows.h>
#include <iostream>

// Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối hóa giải lỗi RIP-Relative
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _LOCAL_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng nằm khít cấu trúc
} LOCAL_DATA, *PLOCAL_DATA;

// Hàm chức năng độc lập vị trí gánh logic thực thi kịch khung
DWORD WINAPI LocalPayload(LPVOID lpParam) {
    PLOCAL_DATA pData = (PLOCAL_DATA)lpParam;
    if (pData && pData->pWinExec) {
        pData->pWinExec(pData->szCommand, SW_SHOWNORMAL);
    }
    return 0;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 01: CLASSIC LOCAL PROCESS CODE INJECTION" << std::endl;
    std::cout << "====================================================" << std::endl;

    SIZE_T functionSize = 500;

    // 1. Cấp phát trang bộ nhớ ảo mang thuộc tính RWX cục bộ
    std::cout << "[*] Dang yeu cau OS cap phat trang nho RWX cuc bo..." << std::endl;
    LPVOID localCodeBuffer = VirtualAlloc(NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!localCodeBuffer) {
        std::cerr << "[-] VirtualAlloc failed! Error: " << GetLastError() << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Trang nho Code RWX thiet lap tai: 0x" << std::hex << localCodeBuffer << std::endl;

    // 2. Cấp phát ô nhớ mang quyền RW cho cấu trúc bảng dữ liệu tuyệt đối
    PLOCAL_DATA pLocalData = (PLOCAL_DATA)VirtualAlloc(NULL, sizeof(LOCAL_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pLocalData) {
        VirtualFree(localCodeBuffer, 0, MEM_RELEASE);
        return EXIT_FAILURE;
    }

    // Phân giải động tọa độ thực tế đang sống của hàm trên RAM
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        pLocalData->pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(pLocalData->szCommand, "cmd.exe /c start calc");

    // 3. Ánh xạ logic mã máy phẳng và tham số dữ liệu lên RAM cục bộ
    RtlCopyMemory(localCodeBuffer, (LPVOID)LocalPayload, functionSize);
    std::cout << "[+] Anh xa logic ma may vao trang thuc thi hoan tat." << std::endl;

    // 4. Triệu hồi luồng nội bộ khai hỏa dứt điểm logic chức năng
    std::cout << "[*] Dang khoi tao luong CreateThread de khai hoa..." << std::endl;
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)localCodeBuffer, pLocalData, 0, NULL);
    
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE); // Gánh luồng xử lý dứt điểm phẳng sạch
        std::cout << "[+] Local Code Real-time Injection Successful!" << std::endl;
        CloseHandle(hThread);
    } else {
        std::cerr << "[-] CreateThread that bai! Error: " << GetLastError() << std::endl;
    }

    // 5. Thu hồi và giải phóng triệt để trang bộ nhớ ảo chống rò rỉ (Memory Leak)
    VirtualFree(localCodeBuffer, 0, MEM_RELEASE);
    VirtualFree(pLocalData, 0, MEM_RELEASE);
    std::cout << "[+] Quy trinh giai phong vung nho ảo hoan tat." << std::endl;

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Hình Đóng Gói (Build & Deployment)

Để tệp nhị phân xuất bản chạy độc lập tuyệt đối, phẳng sạch 100% khi đem sang các môi trường máy ảo Sandbox hoặc VM sạch thử nghiệm:

### ⚙️ Thiết lập trên Microsoft Visual Studio:

1. Đặt thanh công cụ quản lý cấu hình dự án ở chế độ **`Release`** và kiến trúc **`x64`**.
2. Đi tới: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại mục `Runtime Library`, chuyển đổi cấu hình sang cờ **`Multi-threaded (/MT)`** để liên kết tĩnh toàn bộ thư viện hệ thống lọt lòng file `.exe`.
3. Click chuột phải vào dự án $\rightarrow$ Chọn **`Rebuild`**. Tệp `.exe` độc lập sẽ được xuất bản tại thư mục `x64\Release\`.

---

## 📊 5. Kết Quả Kích Hoạt Thật Tế (Demonstration)

Khi kích hỏa tệp tin `.exe` bằng PowerShell ngoài đĩa thô, dòng chảy lệnh được xử lý thẳng và in kết quả trực quan toán học ra CLI:

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
[+] Quy trinh giai phong vung nho ảo hoan tat.

[*] Hoan thanh quy trinh. Nhan Enter de dong cua so...

```

*🎯 Hệ quả RAM:* Ứng dụng Máy tính `calc.exe` bật bung hiên ngang rực rỡ kịch trần kịch khung kịch nền!

---