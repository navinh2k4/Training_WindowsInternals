#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "user32.lib")

// Bộ quét RAM động tìm PID thích ứng theo tên tiến trình (Không phân biệt chữ hoa/thường)
DWORD GetTargetProcessPID(const std::wstring& procName) {
    DWORD pid = 0;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            // Tự động hóa đối chiếu hoa thường để detect Notepad.exe chính xác
            if (_wcsicmp(procName.c_str(), pe32.szExeFile) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return pid;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 05: CLASSIC DLL INJECTION REMOTE (CALC.EXE)" << std::endl;
    std::cout << "====================================================" << std::endl;

    // Tự động nhận diện file DLL nằm cùng thư mục chạy mà không cần gõ CLI
    const char* localDllName = "PandaDLL.dll";
    char fullDllPath[MAX_PATH];
    if (!GetFullPathNameA(localDllName, MAX_PATH, fullDllPath, NULL)) {
        std::cerr << "[-] Failed to resolve full DLL path!" << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }

    std::wstring targetName = L"notepad.exe";
    DWORD dwPID = GetTargetProcessPID(targetName);

    if (dwPID == 0) {
        MessageBoxA(NULL, "[-] Target process not found! Please open Notepad first.", "Error", MB_OK | MB_ICONERROR);
        return EXIT_FAILURE;
    }

    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << dwPID << std::endl;
    std::cout << "[*] Duong dan DLL tuyet doi: " << fullDllPath << std::endl;

    // 1. Mở tiến trình đích với nhóm quyền cấu hình luồng bộ nhớ chéo tối giản
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, dwPID);

    if (!hProcess) {
        std::cerr << "[-] OpenProcess failed! Error code: " << GetLastError() << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }

    // 2. Cấp phát trang nhớ động thích ứng an toàn từ xa gánh chuỗi đường dẫn
    SIZE_T dllPathLen = strlen(fullDllPath) + 1;
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, dllPathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        std::cerr << "[-] VirtualAllocEx failed!" << std::endl;
        CloseHandle(hProcess);
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] Trang nho chứa chuoi duong dan thiet lap tai: 0x" << std::hex << remoteMem << std::endl;

    // 3. Đẩy chuỗi đường dẫn tệp tin DLL xuyên biên giới sang RAM tiến trình đích
    if (!WriteProcessMemory(hProcess, remoteMem, fullDllPath, dllPathLen, NULL)) {
        std::cerr << "[-] WriteProcessMemory failed!" << std::endl;
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] Ghi chuoi duong dan sang Notepad hoan tat." << std::endl;

    // 4. Định vị địa chỉ của hàm nạp thư viện LoadLibraryA mặc định trên hệ thống
    LPVOID loadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!loadLibAddr) {
        std::cerr << "[-] Failed to resolve LoadLibraryA address!" << std::endl;
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        std::cin.get();
        return EXIT_FAILURE;
    }

    std::cout << "[*] Dang khoi tao luong CreateRemoteThread goi LoadLibraryA..." << std::endl;

    // 5. Ép tiến trình đích tự tạo Thread chạy LoadLibraryA để tự nạp DLL của ta
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibAddr, remoteMem, 0, NULL);
    if (!hThread) {
        std::cerr << "[-] CreateRemoteThread failed!" << std::endl;
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        std::cin.get();
        return EXIT_FAILURE;
    }

    // Đồng bộ chờ luồng tiêm thực thi hoàn tất dứt điểm cấu trúc
    WaitForSingleObject(hThread, INFINITE);

    // Thu hoạch địa chỉ Base Address của DLL trên vùng nhớ đích để chứng minh thành công
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    std::cout << "[+] DLL injected successfully!" << std::endl;
    std::cout << "[+] Base Address cua module trong Notepad: 0x" << std::hex << exitCode << std::endl;

    // 6. Giải phóng tài nguyên hệ thống chống rò rỉ bộ nhớ ảo (Memory Leak)
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();

    return EXIT_SUCCESS;
}