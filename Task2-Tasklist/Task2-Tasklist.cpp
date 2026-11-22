
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <wtsapi32.h>

#include <fcntl.h>
#include <io.h>

#include <cstddef>
#include <iomanip>
#include <iostream>
#include <string>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wtsapi32.lib")

namespace {

constexpr int kColNameWidth = 25;
constexpr int kColPidWidth = 8;
constexpr int kColSessionNameWidth = 16;
constexpr int kColSessionIdWidth = 11;
constexpr int kColMemWidth = 12;

HANDLE create_system_snapshot() noexcept {
  return ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
}

bool get_first_process_record(
    HANDLE h_snapshot,
    PROCESSENTRY32W& entry) noexcept {
  entry = {};
  entry.dwSize = static_cast<DWORD>(sizeof(PROCESSENTRY32W));
  return ::Process32FirstW(h_snapshot, &entry) != FALSE;
}

bool get_next_process_record(
    HANDLE h_snapshot,
    PROCESSENTRY32W& entry) noexcept {
  entry.dwSize = static_cast<DWORD>(sizeof(PROCESSENTRY32W));
  return ::Process32NextW(h_snapshot, &entry) != FALSE;
}

SIZE_T get_process_working_set_bytes(DWORD pid) noexcept {
  if (pid == 0) {
    return 0;
  }

  // PROCESS_QUERY_LIMITED_INFORMATION works across protected/system processes
  // without requiring unnecessary full VM read privileges.
  const HANDLE h_process = ::OpenProcess(
      PROCESS_QUERY_LIMITED_INFORMATION,
      FALSE,
      pid);
  if (h_process == nullptr || h_process == INVALID_HANDLE_VALUE) {
    return 0;
  }

  SIZE_T working_set_bytes = 0;
  PROCESS_MEMORY_COUNTERS pmc{};
  pmc.cb = static_cast<DWORD>(sizeof(PROCESS_MEMORY_COUNTERS));
  if (::GetProcessMemoryInfo(
          h_process,
          &pmc,
          static_cast<DWORD>(sizeof(pmc))) != FALSE) {
    working_set_bytes = pmc.WorkingSetSize;
  }

  ::CloseHandle(h_process);
  return working_set_bytes;
}

std::wstring get_windows_session_name(DWORD session_id) {
  LPWSTR p_session_name = nullptr;
  DWORD bytes_returned = 0;
  std::wstring result;

  if (::WTSQuerySessionInformationW(
          WTS_CURRENT_SERVER_HANDLE,
          session_id,
          WTSWinStationName,
          &p_session_name,
          &bytes_returned) != FALSE) {
    if (p_session_name != nullptr && p_session_name[0] != L'\0') {
      result.assign(p_session_name);
    }
    if (p_session_name != nullptr) {
      ::WTSFreeMemory(p_session_name);
      p_session_name = nullptr;
    }
  }

  if (result.empty()) {
    result = (session_id == 0) ? L"Services" : L"Console";
  }
  return result;
}

std::wstring format_bytes_to_kb_string(SIZE_T byte_size) {
  const SIZE_T mem_kb = byte_size / 1024U;
  std::wstring s = std::to_wstring(mem_kb);
  for (int i = static_cast<int>(s.size()) - 3; i > 0; i -= 3) {
    s.insert(static_cast<std::size_t>(i), L",");
  }
  return s + L" K";
}

std::wstring truncate_process_name(
    const wchar_t* raw_name,
    std::size_t max_width) {
  std::wstring original_name(raw_name != nullptr ? raw_name : L"");
  if (max_width > 3 && original_name.size() > max_width) {
    return original_name.substr(0, max_width - 3) + L"...";
  }
  return original_name;
}

void print_tasklist_header() {
  std::wcout
      << std::left << std::setw(kColNameWidth) << L"Image Name"
      << std::right << std::setw(kColPidWidth) << L"PID "
      << std::left << std::setw(kColSessionNameWidth) << L"  Session Name"
      << std::right << std::setw(kColSessionIdWidth) << L"Session#"
      << std::right << std::setw(kColMemWidth) << L"  Mem Usage\n"
      << L"========================= ======= ================ ========== ============\n";
}

void print_process_row_data(
    const std::wstring& name,
    DWORD pid,
    const std::wstring& session_name,
    DWORD session_id,
    const std::wstring& memory_str) {
  std::wcout
      << std::left << std::setw(kColNameWidth) << name
      << std::right << std::setw(kColPidWidth) << pid << L" "
      << std::left << std::setw(kColSessionNameWidth) << session_name
      << std::right << std::setw(kColSessionIdWidth) << session_id
      << std::right << std::setw(kColMemWidth) << memory_str << L"\n";
}

void process_single_record(const PROCESSENTRY32W& process_entry) {
  const DWORD pid = process_entry.th32ProcessID;

  DWORD session_id = 0;
  if (::ProcessIdToSessionId(pid, &session_id) == FALSE) {
    session_id = 0;
  }
  const std::wstring session_name = get_windows_session_name(session_id);

  const SIZE_T memory_bytes = get_process_working_set_bytes(pid);
  const std::wstring formatted_mem = format_bytes_to_kb_string(memory_bytes);
  const std::wstring clean_name = truncate_process_name(
      process_entry.szExeFile,
      static_cast<std::size_t>(kColNameWidth));

  print_process_row_data(clean_name, pid, session_name, session_id, formatted_mem);
}

int execute_process_sieve() {
  const HANDLE h_snapshot = create_system_snapshot();
  if (h_snapshot == INVALID_HANDLE_VALUE || h_snapshot == nullptr) {
    const DWORD err = ::GetLastError();
    std::wcerr << L"Error: Failed to create process snapshot. Win32=" << err << L"\n";
    return (err != ERROR_SUCCESS) ? static_cast<int>(err) : static_cast<int>(ERROR_ACCESS_DENIED);
  }

  PROCESSENTRY32W process_entry{};
  if (get_first_process_record(h_snapshot, process_entry)) {
    do {
      process_single_record(process_entry);
    } while (get_next_process_record(h_snapshot, process_entry));
  } else {
    const DWORD err = ::GetLastError();
    std::wcerr << L"Error: Failed to read first process record. Win32=" << err << L"\n";
  }

  const DWORD end_err = ::GetLastError();
  ::CloseHandle(h_snapshot);

  if (end_err != ERROR_NO_MORE_FILES && end_err != ERROR_SUCCESS) {
    return static_cast<int>(end_err);
  }
  return 0;
}

}  // namespace

int wmain() {
  _setmode(_fileno(stdout), _O_U16TEXT);
  _setmode(_fileno(stderr), _O_U16TEXT);

  print_tasklist_header();
  return execute_process_sieve();
}
