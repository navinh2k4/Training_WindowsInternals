#include <windows.h>
#include <iostream>

#pragma comment(lib, "user32.lib")

// 1. Định nghĩa cấu trúc dữ liệu chứa tham số và con trỏ hàm tuyệt đối
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Lưu địa chỉ tuyệt đối của hàm WinExec
    char szCommand[32];       // Lưu chuỗi lệnh thực thi
} THREAD_DATA, * PTHREAD_DATA;

// 2. Hàm thực thi luồng sử dụng dữ liệu được truyền vào thông qua tham số lpParam
// Hàm này được thiết kế theo cấu trúc độc lập vị trí hoàn toàn
DWORD WINAPI LaunchCalculator(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Gọi hàm thông qua con trỏ địa chỉ tuyệt đối, bẻ gãy hoàn toàn lỗi RIP-Relative
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Hàm giả lập tính toán kích thước gần đúng của logic thực thi
SIZE_T GetFunctionSize() {
    return 500;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 01: CLASSIC CODE INJECTION LOCAL (CALC.EXE)" << std::endl;
    std::cout << "====================================================" << std::endl;

    SIZE_T functionSize = GetFunctionSize();

    // 1. Cấp phát vùng nhớ động RWX tại tiến trình cục bộ để chứa mã máy của hàm
    LPVOID localCodeBuffer = VirtualAlloc(NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!localCodeBuffer) {
        std::cerr << "[-] VirtualAlloc cap phat bo nho that bai!" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Vung nho Code mang quyen RWX tai dia chi: 0x" << std::hex << localCodeBuffer << std::endl;

    // 2. Cấp phát vùng nhớ động RW cho cấu trúc dữ liệu tham số
    PTHREAD_DATA pLocalData = (PTHREAD_DATA)VirtualAlloc(NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pLocalData) {
        VirtualFree(localCodeBuffer, 0, MEM_RELEASE);
        return EXIT_FAILURE;
    }

    // 3. Khởi tạo dữ liệu tuyệt đối cho cấu trúc tham số
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        pLocalData->pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(pLocalData->szCommand, "cmd.exe /c start calc");

    // 4. Sao chép thân hàm thực thi vào phân vùng mã máy RWX
    RtlCopyMemory(localCodeBuffer, (LPVOID)LaunchCalculator, functionSize);
    std::cout << "[+] Sao chep logic ham va khoi tao du lieu tuyet doi hoan tat." << std::endl;

    std::cout << "[*] Dang khoi tao luong Thread de thuc thi..." << std::endl;

    // 5. Tạo luồng Thread, truyền phân vùng mã máy làm điểm chạy và pLocalData làm tham số đầu vào
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)localCodeBuffer, pLocalData, 0, NULL);
    if (!hThread) {
        std::cerr << "[-] CreateThread that bai!" << std::endl;
        VirtualFree(localCodeBuffer, 0, MEM_RELEASE);
        VirtualFree(pLocalData, 0, MEM_RELEASE);
        return EXIT_FAILURE;
    }

    // Đợi luồng hoàn thành chu kỳ xử lý mở Máy tính
    WaitForSingleObject(hThread, INFINITE);
    std::cout << "[+] Luong Thread cuc bo da hoan thanh chu ky song." << std::endl;

    // ── ĐƯA HỘP THOẠI LÊN ĐÂY ĐỂ ĐÓNG BĂNG TIẾN TRÌNH TRƯỚC KHI GIẢI PHÓNG ──
    MessageBoxA(NULL,
        "[+] PAUSE: Check System Informer Memory Map NOW for RWX region!",
        "Research Phase",
        MB_OK | MB_ICONINFORMATION);

    // 6. Thu hồi tài nguyên và giải phóng triệt để vùng nhớ ảo (Sẽ chạy sau khi bấm OK)
    CloseHandle(hThread);
    VirtualFree(localCodeBuffer, 0, MEM_RELEASE);
    VirtualFree(pLocalData, 0, MEM_RELEASE);
    std::cout << "[+] Quy trinh giai phong RAM hoan tat." << std::endl;

    return EXIT_SUCCESS;
}