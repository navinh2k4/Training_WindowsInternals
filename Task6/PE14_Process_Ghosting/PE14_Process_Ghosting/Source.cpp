
#include <windows.h>
#include <tlhelp32.h>

#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <iostream>

namespace {

using NTSTATUS = LONG;

using NtQueryInformationProcessFn = NTSTATUS(WINAPI*)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

struct process_basic_info_raw final {
  NTSTATUS exit_status;
  PVOID peb_base_address;
  ULONG_PTR affinity_mask;
  LONG base_priority;
  ULONG_PTR unique_process_id;
  ULONG_PTR inherited_from_unique_process_id;
};

struct process_telemetry_summary final {
  DWORD pid = 0;
  DWORD parent_pid = 0;
  DWORD thread_count = 0;
  PVOID peb_address = nullptr;
  bool found = false;
};

process_telemetry_summary inspect_target_process(const wchar_t* process_name) noexcept {
  process_telemetry_summary summary{};
  if (process_name == nullptr || process_name[0] == L'\0') {
    return summary;
  }

  const HANDLE h_snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (h_snapshot == INVALID_HANDLE_VALUE || h_snapshot == nullptr) {
    return summary;
  }

  PROCESSENTRY32W entry{};
  entry.dwSize = static_cast<DWORD>(sizeof(PROCESSENTRY32W));

  if (::Process32FirstW(h_snapshot, &entry) != FALSE) {
    do {
      if (::_wcsicmp(process_name, entry.szExeFile) == 0) {
        summary.pid = entry.th32ProcessID;
        summary.parent_pid = entry.th32ParentProcessID;
        summary.thread_count = entry.cntThreads;
        summary.found = true;
        break;
      }
      entry = {};
      entry.dwSize = static_cast<DWORD>(sizeof(PROCESSENTRY32W));
    } while (::Process32NextW(h_snapshot, &entry) != FALSE);
  }

  ::CloseHandle(h_snapshot);
  if (!summary.found) {
    return summary;
  }

  const HANDLE h_process = ::OpenProcess(
      PROCESS_QUERY_LIMITED_INFORMATION,
      FALSE,
      summary.pid);
  if (h_process != nullptr && h_process != INVALID_HANDLE_VALUE) {
    const HMODULE h_ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (h_ntdll != nullptr) {
      const FARPROC raw_proc = ::GetProcAddress(h_ntdll, "NtQueryInformationProcess");
      if (raw_proc != nullptr) {
        auto query_fn = reinterpret_cast<NtQueryInformationProcessFn>(raw_proc);
        process_basic_info_raw pbi{};
        ULONG ret_len = 0;
        constexpr DWORD kProcessBasicInformation = 0;
        if (query_fn(
                h_process,
                kProcessBasicInformation,
                &pbi,
                static_cast<ULONG>(sizeof(pbi)),
                &ret_len) == 0) {
          summary.peb_address = pbi.peb_base_address;
        }
      }
    }
    ::CloseHandle(h_process);
  }

  return summary;
}

}  // namespace

int wmain() {
  constexpr wchar_t kTargetProcess[] = L"notepad.exe";

  std::wcout
      << L"====================================================\n"
      << L"[*] PE 14: PROCESS & IMAGE TELEMETRY AUDIT STUDY\n"
      << L"====================================================\n";

  const process_telemetry_summary info = inspect_target_process(kTargetProcess);
  if (!info.found) {
    std::wcout << L"[-] Target process not running: " << kTargetProcess << L"\n";
    return 1;
  }

  std::wcout
      << L"[+] Process: " << kTargetProcess
      << L" | PID=" << info.pid
      << L" | PPID=" << info.parent_pid
      << L" | Threads=" << info.thread_count
      << L" | PEB=0x" << std::hex << reinterpret_cast<std::uintptr_t>(info.peb_address)
      << std::dec << L"\n";

  return 0;
}
