#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <iomanip>
#include <string>

using namespace std;

// ========================================================================
// 1. LOẠI BỎ MAGIC NUMBERS: Khai báo các hằng số định dạng cột
// ========================================================================
const int COL_NAME_WIDTH = 25;
const int COL_PID_WIDTH = 8;
const int COL_SESSION_NAME_WIDTH = 16;
const int COL_SESSION_ID_WIDTH = 11;
const int COL_MEM_WIDTH = 12;

// ========================================================================
// 2. HÀM CHUYÊN BIỆT XỬ LÝ FORMAT VÀ LOGIC NHỎ
// ========================================================================
wstring getSessionName(DWORD sessionId) {
    return (sessionId == 0) ? L"Services" : L"Console";
}

// [ĐÃ SỬA BUG]: Trả về wstring để đồng bộ với wcout
wstring formatMemoryKB(SIZE_T memKB) {
    wstring s = to_wstring(memKB);
    for (int i = (int)s.length() - 3; i > 0; i -= 3) {
        s.insert(i, L",");
    }
    return s + L" K";
}

// [ĐÃ SỬA BUG]: Thêm pmc.cb = sizeof(pmc);
SIZE_T getProcessMemoryKB(DWORD pid) {
    SIZE_T memoryUsageKB = 0;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (hProcess != NULL) {
        PROCESS_MEMORY_COUNTERS pmc;
        pmc.cb = sizeof(PROCESS_MEMORY_COUNTERS); // Luật WinAPI bắt buộc

        if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
            memoryUsageKB = pmc.WorkingSetSize / 1024;
        }
        CloseHandle(hProcess);
    }
    return memoryUsageKB;
}

// ========================================================================
// 3. HÀM XỬ LÝ GIAO DIỆN HIỂN THỊ (PRESENTATION LAYER)
// ========================================================================
void printHeader() {
    wcout << left << setw(COL_NAME_WIDTH) << L"Image Name"
        << right << setw(COL_PID_WIDTH) << L"PID "
        << left << setw(COL_SESSION_NAME_WIDTH) << L"  Session Name"
        << right << setw(COL_SESSION_ID_WIDTH) << L"Session#"
        << right << setw(COL_MEM_WIDTH) << L"  Mem Usage\n"
        << L"========================= ======= ================ ========== ============\n";
}

// Đổi tên hàm từ printProcessInfo thành printProcessRow để thể hiện đúng Hành động (Action)
void printProcessRow(const PROCESSENTRY32W& processEntry) {
    DWORD pid = processEntry.th32ProcessID;
    DWORD sessionId = 0;

    ProcessIdToSessionId(pid, &sessionId);
    SIZE_T memoryKB = getProcessMemoryKB(pid);

    wstring processName = processEntry.szExeFile;
    if (processName.length() > COL_NAME_WIDTH) {
        // Cắt chuỗi và thêm dấu ... nếu tên quá dài
        processName = processName.substr(0, COL_NAME_WIDTH - 3) + L"...";
    }

    wcout << left << setw(COL_NAME_WIDTH) << processName
        << right << setw(COL_PID_WIDTH) << pid << L" "
        << left << setw(COL_SESSION_NAME_WIDTH) << getSessionName(sessionId)
        << right << setw(COL_SESSION_ID_WIDTH) << sessionId
        << right << setw(COL_MEM_WIDTH) << formatMemoryKB(memoryKB) << L"\n";
}

// ========================================================================
// 4. CÁC HÀM BAO BỌC WINAPI (API WRAPPERS)
// ========================================================================
HANDLE createProcessSnapshot() {
    return CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
}

bool getFirstProcess(HANDLE hSnapshot, PROCESSENTRY32W& processEntry) {
    processEntry.dwSize = sizeof(PROCESSENTRY32W);
    return Process32FirstW(hSnapshot, &processEntry) != FALSE;
}

bool getNextProcess(HANDLE hSnapshot, PROCESSENTRY32W& processEntry) {
    return Process32NextW(hSnapshot, &processEntry) != FALSE;
}

// ========================================================================
// 5. HÀM ĐIỀU PHỐI CHÍNH (CONTROLLER)
// ========================================================================
// [ĐÃ SỬA BUG]: Khôi phục lại vòng lặp do-while đã bị mất
void listProcesses() {
    HANDLE hSnapshot = createProcessSnapshot();

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        wcerr << L"Loi: Khong the khoi tao Snapshot. Ma loi: " << GetLastError() << L"\n";
        return;
    }

    PROCESSENTRY32W processEntry;

    if (getFirstProcess(hSnapshot, processEntry)) {
        do {
            printProcessRow(processEntry);
        } while (getNextProcess(hSnapshot, processEntry));
    }
    else {
        wcerr << L"Loi: Khong the lay thong tin tien trinh dau tien.\n";
    }

    CloseHandle(hSnapshot);
}

// ========================================================================
// HÀM MAIN SẠCH SẼ NHƯ MỤC LỤC SÁCH
// ========================================================================
int main() {
    printHeader();
    listProcesses();

    return 0;
}