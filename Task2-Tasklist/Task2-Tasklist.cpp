#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wtsapi32.h>     // Thư viện WinAPI quản lý Session chuyên sâu
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <io.h>
#include <fcntl.h>

#pragma comment(lib, "wtsapi32.lib") // Liên kết thư viện truy vấn Session hệ thống

using namespace std;

const int COL_NAME_WIDTH = 25;
const int COL_PID_WIDTH = 8;
const int COL_SESSION_NAME_WIDTH = 16;
const int COL_SESSION_ID_WIDTH = 11;
const int COL_MEM_WIDTH = 12;

// Hàm 1: Chỉ làm nhiệm vụ khởi tạo Snapshot từ nhân Kernel
HANDLE CreateSystemSnapshot() {
    return CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
}

// Hàm 2: Chỉ làm nhiệm vụ lấy tiến trình đầu tiên
bool GetFirstProcessRecord(HANDLE hSnapshot, PROCESSENTRY32W& entry) {
    entry.dwSize = sizeof(PROCESSENTRY32W);
    return Process32FirstW(hSnapshot, &entry) != FALSE;
}

// Hàm 3: Chỉ làm nhiệm vụ nhảy sang tiến trình tiếp theo
bool GetNextProcessRecord(HANDLE hSnapshot, PROCESSENTRY32W& entry) {
    return Process32NextW(hSnapshot, &entry) != FALSE;
}

// Hàm 4: Chỉ làm nhiệm vụ bóc tách dung lượng RAM thực tế của 1 PID
SIZE_T GetProcessWorkingSetSizeBytes(DWORD pid) {
    SIZE_T workingSetBytes = 0;
    // Sử dụng cờ tối thiểu PROCESS_QUERY_LIMITED_INFORMATION để tăng hiệu năng phòng thủ quyền hạn
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (hProcess != NULL) {
        PROCESS_MEMORY_COUNTERS pmc;
        pmc.cb = sizeof(PROCESS_MEMORY_COUNTERS);
        if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
            workingSetBytes = pmc.WorkingSetSize;
        }
        CloseHandle(hProcess);
    }
    return workingSetBytes;
}

// Hàm 5: Truy vấn tên Session thực tế từ Object Manager của OS
wstring GetWindowsSessionName(DWORD sessionId) {
    LPWSTR pSessionName = NULL;
    DWORD bytesReturned = 0;
    wstring result = L"N/A";

    // Gọi API chuyên dụng của Windows 
    if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSWinStationName, &pSessionName, &bytesReturned)) {
        if (pSessionName != NULL && wcslen(pSessionName) > 0) { 
            result = pSessionName;
        }
        WTSFreeMemory(pSessionName); // Giải phóng vùng nhớ do WinAPI tự cấp phát động
    }

    // Fallback chuẩn theo hành vi của lệnh tasklist gốc khi gặp Session rỗng
    if (result == L"N/A" || result.empty()) {
        result = (sessionId == 0) ? L"Services" : L"Console";
    }
    return result;
}

// Hàm 6: Chỉ làm nhiệm vụ chia tách hàng nghìn bằng toán học chuỗi
wstring FormatBytesToKBString(SIZE_T byteSize) {
    SIZE_T memKB = byteSize / 1024;
    wstring s = to_wstring(memKB);
    for (int i = (int)s.length() - 3; i > 0; i -= 3) {
        s.insert(i, L",");
    }
    return s + L" K";
}

// Hàm 7: Chỉ làm nhiệm vụ xử lý co giãn, cắt tỉa tên tiến trình để chống vỡ lề CLI
wstring TruncateProcessName(const wstring& originalName, size_t maxWidth) {
    if (originalName.length() > maxWidth) {
        return originalName.substr(0, maxWidth - 3) + L"...";
    }
    return originalName;
}

// Hàm 8: Chỉ làm nhiệm vụ in Header bảng
void PrintTasklistHeader() {
    wcout << left << setw(COL_NAME_WIDTH) << L"Image Name"
        << right << setw(COL_PID_WIDTH) << L"PID "
        << left << setw(COL_SESSION_NAME_WIDTH) << L"  Session Name"
        << right << setw(COL_SESSION_ID_WIDTH) << L"Session#"
        << right << setw(COL_MEM_WIDTH) << L"  Mem Usage\n"
        << L"========================= ======= ================ ========== ============\n";
}

// Hàm 9: Chỉ làm nhiệm vụ format đúng vị trí phân phối dòng dữ liệu thô
void PrintProcessRowData(const wstring& name, DWORD pid, const wstring& sessionName, DWORD sessionId, const wstring& memoryStr) {
    wcout << left << setw(COL_NAME_WIDTH) << name
        << right << setw(COL_PID_WIDTH) << pid << L" "
        << left << setw(COL_SESSION_NAME_WIDTH) << sessionName
        << right << setw(COL_SESSION_ID_WIDTH) << sessionId
        << right << setw(COL_MEM_WIDTH) << memoryStr << L"\n";
}

// Hàm 10: Hàm xử lý trung gian, nhận bản ghi thô, ra lệnh bóc tách cho các hàm con và đẩy ra bộ in
void ProcessSingleRecord(const PROCESSENTRY32W& processEntry) {
    DWORD pid = processEntry.th32ProcessID;

    // 1. Đo Đạc Session bằng WinAPI chuyên biệt
    DWORD sessionId = 0;
    ProcessIdToSessionId(pid, &sessionId);
    wstring sessionName = GetWindowsSessionName(sessionId);

    // 2. Quét RAM và xử lý định dạng văn bản thích ứng
    SIZE_T memoryBytes = GetProcessWorkingSetSizeBytes(pid);
    wstring formattedMem = FormatBytesToKBString(memoryBytes);
    wstring cleanName = TruncateProcessName(processEntry.szExeFile, COL_NAME_WIDTH);

    // 3. Đẩy sang hàm hiển thị chuyên biệt
    PrintProcessRowData(cleanName, pid, sessionName, sessionId, formattedMem);
}

// Hàm 11: Chỉ làm nhiệm vụ điều phối luồng vòng lặp dữ liệu trên toàn bộ Snapshot
void ExecuteProcessSieve() {
    HANDLE hSnapshot = CreateSystemSnapshot();

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        wcerr << L"Loi: Khong the khoi tao Snapshot. Ma loi: " << GetLastError() << L"\n";
        return;
    }

    PROCESSENTRY32W processEntry;

    if (GetFirstProcessRecord(hSnapshot, processEntry)) {
        do {
            ProcessSingleRecord(processEntry);
        } while (GetNextProcessRecord(hSnapshot, processEntry));
    }
    else {
        wcerr << L"Loi: Khong the truy vấn ban ghi tien trinh dau tien.\n";
    }

    CloseHandle(hSnapshot); // Giải phóng thẻ Handle hệ thống
}

int main() {
    _setmode(_fileno(stdout), _O_U16TEXT); // Bật Unicode UTF-16

    PrintTasklistHeader();
    ExecuteProcessSieve();

    return 0;
}