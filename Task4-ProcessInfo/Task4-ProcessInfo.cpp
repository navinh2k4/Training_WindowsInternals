#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <sstream>
#include <io.h>
#include <fcntl.h>

using namespace std;

// ========================================================================
// TẦNG CẤU HÌNH ĐỊNH DẠNG (CONFIGURATION LAYER)
// ========================================================================
const int LAYOUT_WIDTH = 43;
const int COL_LABEL_WIDTH = 19;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef LONG NTSTATUS;
typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

typedef NTSTATUS(WINAPI* NtQueryInformationProcessPtr)(
    HANDLE, DWORD, PVOID, ULONG, PULONG
    );

struct PrivilegeRecord {
    std::wstring name;
    std::wstring state;
};

struct ModuleRecord {
    std::wstring name;
    std::wstring fullPath;
    PVOID baseAddress;
    DWORD size;
};

struct ThreadRecord {
    DWORD id;
    LONG priority;
    std::wstring status;
};

struct ProcessToolhelpCore {
    DWORD parentPid;
    DWORD threadCount;
    bool found;
};

// ========================================================================
// 1. TẦNG TRÍCH XUẤT DỮ LIỆU THÔ WINAPI THUẦN (LOW-LEVEL EXTRACTORS - ATOMIC)
// ========================================================================

HANDLE CreateProcessSnapshot() {
    return CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
}

bool GetFirstProcessEntry(HANDLE hSnapshot, PROCESSENTRY32W& entry) {
    entry.dwSize = sizeof(PROCESSENTRY32W);
    return Process32FirstW(hSnapshot, &entry) != FALSE;
}

bool GetNextProcessEntry(HANDLE hSnapshot, PROCESSENTRY32W& entry) {
    return Process32NextW(hSnapshot, &entry) != FALSE;
}

// Tuyệt đối dỡ bỏ việc lặp Snapshot, quét DUY NHẤT một vòng để khóa thông số Core
ProcessToolhelpCore ExtractTargetProcessCoreInfo(DWORD targetPid, const wstring& targetName, bool searchByPid) {
    ProcessToolhelpCore coreResult = { 0, 0, false };
    HANDLE hSnapshot = CreateProcessSnapshot();
    if (hSnapshot == INVALID_HANDLE_VALUE) return coreResult;

    PROCESSENTRY32W pe;
    if (GetFirstProcessEntry(hSnapshot, pe)) {
        do {
            bool match = searchByPid ? (pe.th32ProcessID == targetPid) : (_wcsicmp(pe.szExeFile, targetName.c_str()) == 0);
            if (match) {
                coreResult.parentPid = pe.th32ParentProcessID;
                coreResult.threadCount = pe.cntThreads;
                coreResult.found = true;
                if (!searchByPid) {
                    SetLastError(pe.th32ProcessID); // Đồng bộ PID thông qua API Error channel
                }
                break;
            }
        } while (GetNextProcessEntry(hSnapshot, pe));
    }
    CloseHandle(hSnapshot);
    return coreResult;
}

wstring GetProcessExecutablePath(HANDLE hProcess) {
    DWORD size = MAX_PATH;
    vector<wchar_t> buffer(size);
    while (QueryFullProcessImageNameW(hProcess, 0, buffer.data(), &size) == 0) {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            size *= 2;
            buffer.resize(size);
        }
        else {
            return L"N/A";
        }
    }
    return wstring(buffer.data());
}

wstring GetProcessCommandLineFromPeb(HANDLE hProcess) {
    wstring commandLineStr = L"N/A";
    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtDll) return commandLineStr;

    NtQueryInformationProcessPtr NtQueryInformationProcess =
        (NtQueryInformationProcessPtr)GetProcAddress(hNtDll, "NtQueryInformationProcess");

    if (NtQueryInformationProcess) {
        PROCESS_BASIC_INFORMATION pbi;
        ULONG returnLength = 0;
        if (NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), &returnLength) == 0) {
            ULONG_PTR pebOffset = (sizeof(PVOID) == 8) ? 0x20 : 0x10;
            PVOID processParametersAddr = NULL;

            if (ReadProcessMemory(hProcess, (PBYTE)pbi.PebBaseAddress + pebOffset, &processParametersAddr, sizeof(PVOID), NULL)) {
                ULONG_PTR cmdLineOffset = (sizeof(PVOID) == 8) ? 0x70 : 0x40;
                UNICODE_STRING cmdLineUnicodeStr;

                if (ReadProcessMemory(hProcess, (PBYTE)processParametersAddr + cmdLineOffset, &cmdLineUnicodeStr, sizeof(cmdLineUnicodeStr), NULL)) {
                    size_t charCount = cmdLineUnicodeStr.Length / sizeof(wchar_t);
                    vector<wchar_t> cmdBuffer(charCount + 1, L'\0');
                    if (ReadProcessMemory(hProcess, cmdLineUnicodeStr.Buffer, cmdBuffer.data(), cmdLineUnicodeStr.Length, NULL)) {
                        commandLineStr = wstring(cmdBuffer.data(), charCount);
                    }
                }
            }
        }
    }
    return commandLineStr;
}

wstring GetProcessOwnerName(HANDLE hProcess) {
    wstring ownerName = L"N/A";
    HANDLE hToken = NULL;
    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        DWORD tokenSize = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenSize);
        if (tokenSize > 0) {
            vector<BYTE> buffer(tokenSize);
            PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(buffer.data());
            if (GetTokenInformation(hToken, TokenUser, pTokenUser, tokenSize, &tokenSize)) {
                DWORD nameLen = 0, domainLen = 0;
                SID_NAME_USE sidUse;
                LookupAccountSidW(NULL, pTokenUser->User.Sid, NULL, &nameLen, NULL, &domainLen, &sidUse);

                if (nameLen > 0 && domainLen > 0) {
                    vector<wchar_t> nameBuf(nameLen);
                    vector<wchar_t> domainBuf(domainLen);
                    if (LookupAccountSidW(NULL, pTokenUser->User.Sid, nameBuf.data(), &nameLen, domainBuf.data(), &domainLen, &sidUse)) {
                        ownerName = wstring(domainBuf.data()) + L"\\" + wstring(nameBuf.data());
                    }
                }
            }
        }
        CloseHandle(hToken);
    }
    return ownerName;
}

// ========================================================================
// HÀM NGUYÊN TỬ: ĐỌC VÀ CHUYỂN ĐỔI GIỜ TẠO TIẾN TRÌNH THEO MÚI GIỜ ĐỊA PHƯƠNG
// ========================================================================
wstring GetProcessCreatedTime(HANDLE hProcess) {
    FILETIME createTimeUTC, exitTime, kernelTime, userTime;

    // Bước 1: Trích xuất mốc thời gian cấu trúc UTC thô từ Kernel Object
    if (GetProcessTimes(hProcess, &createTimeUTC, &exitTime, &kernelTime, &userTime)) {
        FILETIME createTimeLocal;

        // Bước 2: Vận dụng WinAPI dịch múi giờ UTC thô sang múi giờ Local thực tế của máy (Bias UTC+7)
        if (FileTimeToLocalFileTime(&createTimeUTC, &createTimeLocal)) {
            SYSTEMTIME sysTime;

            // Bước 3: Thông dịch định dạng cấu trúc nhị phân sang định dạng số SYSTEMTIME
            if (FileTimeToSystemTime(&createTimeLocal, &sysTime)) {
                wstringstream wss;

                // Định dạng chuỗi văn bản đầu ra ngăn nắp theo cấu trúc form mẫu
                wss << setfill(L'0') << setw(4) << sysTime.wYear << L"-"
                    << setw(2) << sysTime.wMonth << L"-" << setw(2) << sysTime.wDay << L" "
                    << setw(2) << sysTime.wHour << L":" << setw(2) << sysTime.wMinute << L":" << setw(2) << sysTime.wSecond;

                return wss.str();
            }
        }
    }
    return L"N/A";
}

wstring GetProcessArchitecture(HANDLE hProcess) {
    BOOL isWow64 = FALSE;
    if (IsWow64Process(hProcess, &isWow64)) {
        if (isWow64) return L"x86 (32-bit running on 64-bit OS)";
        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);
        if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) return L"x64";
        if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) return L"x86";
    }
    return L"Unknown";
}

vector<PrivilegeRecord> ExtractProcessPrivileges(HANDLE hProcess) {
    vector<PrivilegeRecord> privList;
    HANDLE hToken = NULL;
    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        DWORD size = 0;
        GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &size);
        if (size > 0) {
            vector<BYTE> buffer(size);
            PTOKEN_PRIVILEGES pPrivs = reinterpret_cast<PTOKEN_PRIVILEGES>(buffer.data());
            if (GetTokenInformation(hToken, TokenPrivileges, pPrivs, size, &size)) {
                for (DWORD i = 0; i < pPrivs->PrivilegeCount; i++) {
                    DWORD nameLen = 0;
                    LookupPrivilegeNameW(NULL, &pPrivs->Privileges[i].Luid, NULL, &nameLen);
                    if (nameLen > 0) {
                        vector<wchar_t> privNameBuf(nameLen);
                        if (LookupPrivilegeNameW(NULL, &pPrivs->Privileges[i].Luid, privNameBuf.data(), &nameLen)) {
                            PrivilegeRecord rec;
                            rec.name = privNameBuf.data();
                            rec.state = (pPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) ? L"Enabled" : L"Disabled";
                            privList.push_back(rec);
                        }
                    }
                }
            }
        }
        CloseHandle(hToken);
    }
    return privList;
}

vector<ModuleRecord> ExtractProcessModules(DWORD pid) {
    vector<ModuleRecord> moduleList;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me;
        me.dwSize = sizeof(MODULEENTRY32W);
        if (Module32FirstW(hSnapshot, &me)) {
            do {
                ModuleRecord rec;
                rec.name = me.szModule;
                rec.fullPath = me.szExePath;
                rec.baseAddress = me.modBaseAddr;
                rec.size = me.modBaseSize;
                moduleList.push_back(rec);
            } while (Module32NextW(hSnapshot, &me));
        }
        CloseHandle(hSnapshot);
    }
    return moduleList;
}

// VẬN DỤNG TỐI ĐA WINAPI THUẦN: Kiểm tra hiệu năng thực thi của Thread qua GetThreadTimes
wstring GetThreadRealStatus(DWORD threadId) {
    wstring statusStr = L"Waiting";
    // Sử dụng quyền truy vấn WinAPI chuẩn thay vì gọi hàm ngầm ntdll
    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
    if (hThread != NULL) {
        FILETIME cTime, eTime, kTime, uTime;
        if (GetThreadTimes(hThread, &cTime, &eTime, &kTime, &uTime)) {
            // Nếu luồng tiêu thụ Kernel Time hoặc User Time lớn hơn 0 trong phiên làm việc, chứng tỏ nó đang Running hoạt động
            ULARGE_INTEGER kernelTime, userTime;
            kernelTime.LowPart = kTime.dwLowDateTime;
            kernelTime.HighPart = kTime.dwHighDateTime;
            userTime.LowPart = uTime.dwLowDateTime;
            userTime.HighPart = uTime.dwHighDateTime;

            if (kernelTime.QuadPart > 0 || userTime.QuadPart > 0) {
                statusStr = L"Running";
            }
            else {
                statusStr = L"Waiting";
            }
        }

        // Kiểm tra trạng thái Suspended thô bằng WinAPI chuẩn
        DWORD suspendCount = SuspendThread(hThread);
        if (suspendCount != (DWORD)-1) {
            ResumeThread(hThread); // Trả lại trạng thái cũ ngay lập tức
            if (suspendCount > 0) statusStr = L"Suspended";
        }
        CloseHandle(hThread);
    }
    return statusStr;
}

vector<ThreadRecord> ExtractProcessThreads(DWORD targetPid) {
    vector<ThreadRecord> threadList;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == targetPid) {
                    ThreadRecord rec;
                    rec.id = te.th32ThreadID;
                    rec.priority = te.tpBasePri;
                    rec.status = GetThreadRealStatus(te.th32ThreadID);
                    threadList.push_back(rec);
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        CloseHandle(hSnapshot);
    }
    return threadList;
}

// ========================================================================
// 2. TẦNG THÔNG DỊCH VÀ ĐỊNH DẠNG LOGIC (INTERPRETERS & LOGIC)
// ========================================================================

wstring TranslatePriorityClass(DWORD priorityClass) {
    switch (priorityClass) {
    case IDLE_PRIORITY_CLASS: return L"IDLE_PRIORITY_CLASS";
    case BELOW_NORMAL_PRIORITY_CLASS: return L"BELOW_NORMAL_PRIORITY_CLASS";
    case NORMAL_PRIORITY_CLASS: return L"NORMAL_PRIORITY_CLASS";
    case ABOVE_NORMAL_PRIORITY_CLASS: return L"ABOVE_NORMAL_PRIORITY_CLASS";
    case HIGH_PRIORITY_CLASS: return L"HIGH_PRIORITY_CLASS";
    case REALTIME_PRIORITY_CLASS: return L"REALTIME_PRIORITY_CLASS";
    default: return L"NORMAL_PRIORITY_CLASS";
    }
}

wstring FormatMemorySizeMB(SIZE_T bytes) {
    wstringstream wss;
    wss << fixed << setprecision(1) << (double)bytes / (1024 * 1024) << L" MB";
    return wss.str();
}

wstring FormatModuleSizeString(DWORD bytes) {
    wstringstream wss;
    if (bytes >= 1024 * 1024) wss << fixed << setprecision(1) << (double)bytes / (1024 * 1024) << L" MB";
    else wss << (bytes / 1024) << L" KB";
    return wss.str();
}

wstring ExtractFileNameFromPath(const wstring& fullPath) {
    size_t pos = fullPath.find_last_of(L"\\/");
    return (pos != wstring::npos) ? fullPath.substr(pos + 1) : fullPath;
}

// ========================================================================
// 3. TẦNG HIỂN THỊ CLI REPORT CHUYÊN BIỆT (PRESENTATION LAYER)
// ========================================================================

void PrintRowFormatted(const wstring& label, const wstring& value) {
    wcout << left << setw(LAYOUT_WIDTH) << label << L": " << value << endl;
}

void PrintFinalReport(DWORD pid, const ProcessToolhelpCore& toolhelpCore) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        wcerr << L"Loi: Khong the mo ket noi voi PID muc tieu de xuat report.\n";
        return;
    }

    wstring fullPath = GetProcessExecutablePath(hProcess);
    wstring procName = ExtractFileNameFromPath(fullPath);
    DWORD sessionId = 0;
    ProcessIdToSessionId(pid, &sessionId);

    DWORD handleCount = 0;
    GetProcessHandleCount(hProcess, &handleCount);

    PROCESS_MEMORY_COUNTERS_EX pmc;
    pmc.cb = sizeof(PROCESS_MEMORY_COUNTERS_EX);
    GetProcessMemoryInfo(hProcess, (PPROCESS_MEMORY_COUNTERS)&pmc, sizeof(pmc));

    BOOL isTargetWow64 = FALSE;
    IsWow64Process(hProcess, &isTargetWow64);

    wcout << L"===========================================\n";
    wcout << L"PROCESS INFORMATION REPORT\n";
    wcout << L"===========================================\n\n";

    wcout << L"[PROCESS BASIC INFO]\n";
    wcout << L"-------------------------------------------\n";
    PrintRowFormatted(L"Process Name", procName);
    PrintRowFormatted(L"Process ID (PID)", to_wstring(pid));
    PrintRowFormatted(L"Parent PID", to_wstring(toolhelpCore.parentPid));
    PrintRowFormatted(L"Executable Path", fullPath);
    PrintRowFormatted(L"Command Line", GetProcessCommandLineFromPeb(hProcess));
    PrintRowFormatted(L"Session ID", to_wstring(sessionId));
    PrintRowFormatted(L"Priority Class", TranslatePriorityClass(GetPriorityClass(hProcess)));
    PrintRowFormatted(L"Handle Count", to_wstring(handleCount));
    PrintRowFormatted(L"Thread Count", to_wstring(toolhelpCore.threadCount));
    PrintRowFormatted(L"Architecture", GetProcessArchitecture(hProcess));
    PrintRowFormatted(L"Created Time", GetProcessCreatedTime(hProcess));
    PrintRowFormatted(L"User", GetProcessOwnerName(hProcess));
    wcout << L"\n-------------------------------------------\n";

    wcout << L"[PRIVILEGES]\n";
    wcout << L"-------------------------------------------\n";
    vector<PrivilegeRecord> privileges = ExtractProcessPrivileges(hProcess);
    if (privileges.empty()) wcout << L"No privileges available or access denied.\n";
    for (const auto& priv : privileges) {
        wcout << left << setw(30) << priv.name << L": " << priv.state << endl;
    }
    wcout << L"\n-------------------------------------------\n";

    wcout << L"[MEMORY USAGE]\n";
    wcout << L"-------------------------------------------\n";
    PrintRowFormatted(L"Working Set (RAM)", FormatMemorySizeMB(pmc.WorkingSetSize));
    PrintRowFormatted(L"Private Bytes", FormatMemorySizeMB(pmc.PrivateUsage));
    PrintRowFormatted(L"Pagefile Usage", FormatMemorySizeMB(pmc.PagefileUsage));
    PrintRowFormatted(L"Peak Working Set", FormatMemorySizeMB(pmc.PeakWorkingSetSize));
    wcout << L"\n-------------------------------------------\n";

    wcout << L"[MODULES LOADED]\n";
    wcout << L"-------------------------------------------\n";
    wcout << left << setw(18) << L"Base Address" << L" " << left << setw(10) << L"Size" << L" Module Name (Full Path)\n";
    wcout << L"-------------------------------------------\n";

    vector<ModuleRecord> modules = ExtractProcessModules(pid);
    for (const auto& mod : modules) {
        // TỐI ƯU TOÁN HỌC: Tự động điều chỉnh độ rộng trường hex (8 ký tự cho 32-bit, 16 ký tự cho 64-bit)
        int addressWidth = isTargetWow64 ? 8 : 16;
        wcout << L"0x" << uppercase << hex << setw(addressWidth) << setfill(L'0') << reinterpret_cast<ULONG_PTR>(mod.baseAddress)
            << nouppercase << dec << setfill(L' ') << L" " << right << setw(7) << FormatModuleSizeString(mod.size)
            << L"    " << mod.fullPath << endl;
    }
    wcout << L"Total Modules Loaded : " << modules.size() << endl;
    wcout << L"\n-------------------------------------------\n";

    wcout << L"[THREADS]\n";
    wcout << L"-------------------------------------------\n";
    wcout << left << setw(12) << L"Thread ID" << left << setw(16) << L"Base Priority" << L"Status\n";
    wcout << L"-------------------------------------------\n";

    vector<ThreadRecord> threads = ExtractProcessThreads(pid);
    for (const auto& th : threads) {
        wcout << left << setw(12) << th.id << left << setw(16) << th.priority << th.status << endl;
    }
    wcout << L"Total Threads: " << threads.size() << endl;

    wcout << L"\n-------------------------------------------\n";
    wcout << L"[SYSTEM CONTEXT]\n";
    wcout << L"-------------------------------------------\n";
    PrintRowFormatted(L"Process Bitness", (sizeof(PVOID) == 8) ? L"64-bit" : L"32-bit");
    PrintRowFormatted(L"OS Architecture", L"x64");
    PrintRowFormatted(L"IsWow64Process", isTargetWow64 ? L"Yes" : L"No");

    HMODULE hModNt = GetModuleHandleW(L"ntdll.dll");
    PVOID imageBase = NULL;
    if (hModNt) {
        NtQueryInformationProcessPtr NtQueryInformationProcess =
            (NtQueryInformationProcessPtr)GetProcAddress(hModNt, "NtQueryInformationProcess");
        PROCESS_BASIC_INFORMATION pbi;
        ULONG retLen = 0;
        if (NtQueryInformationProcess && NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), &retLen) == 0) {
            ULONG_PTR baseOffset = (sizeof(PVOID) == 8) ? 0x10 : 0x08;
            ReadProcessMemory(hProcess, (PBYTE)pbi.PebBaseAddress + baseOffset, &imageBase, sizeof(PVOID), NULL);
        }
    }
    wcout << L"PEB ImageBaseAddress : 0x" << hex << uppercase << reinterpret_cast<ULONG_PTR>(imageBase) << nouppercase << dec << endl;
    PrintRowFormatted(L"Image Path from PEB", fullPath);

    wcout << L"===========================================\n";
    wcout << L"END OF REPORT\n";
    wcout << L"===========================================\n";

    CloseHandle(hProcess);
}

int wmain(int argc, wchar_t* argv[]) {
    if (_setmode(_fileno(stdout), _O_U16TEXT) == -1) return 1;

    if (argc < 3) {
        wcout << L"Su dung: project.exe -n <process_name> hoac -p <PID>\n";
        wcout << L"Vi du  : project.exe -n notepad.exe\n";
        return 1;
    }

    wstring argumentFlag = argv[1];
    wstring argumentValue = argv[2];
    DWORD targetPid = 0;
    ProcessToolhelpCore toolhelpCore = { 0, 0, false };

    if (argumentFlag == L"-p") {
        targetPid = stoul(argumentValue);
        toolhelpCore = ExtractTargetProcessCoreInfo(targetPid, L"", true);
    }
    else if (argumentFlag == L"-n") {
        toolhelpCore = ExtractTargetProcessCoreInfo(0, argumentValue, false);
        if (toolhelpCore.found) {
            targetPid = GetLastError();
        }
    }
    else {
        wcout << L"Loi: Co lenh khong hop le. Chi chap nhan -n hoac -p\n";
        return 1;
    }

    if (!toolhelpCore.found) {
        wcout << L"Loi: Khong tim thay tien trinh muc tieu he thong.\n";
        return 1;
    }

    PrintFinalReport(targetPid, toolhelpCore);
    return 0;
}