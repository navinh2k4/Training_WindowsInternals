
#include <windows.h>
#include <tlhelp32.h>

#include <cstdint>
#include <cwchar>
#include <iostream>

namespace {

struct module_audit_result final {
  DWORD process_id = 0;
  std::uintptr_t module_base = 0;
  DWORD module_size = 0;
  bool found = false;
};

DWORD find_process_id_by_name(const wchar_t* process_name) noexcept {
  if (process_name == nullptr || process_name[0] == L'\0') {
    return 0;
  }

  const HANDLE h_snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (h_snapshot == INVALID_HANDLE_VALUE || h_snapshot == nullptr) {
    return 0;
  }

  DWORD matched_pid = 0;
  PROCESSENTRY32W entry{};
  entry.dwSize = static_cast<DWORD>(sizeof(PROCESSENTRY32W));

  if (::Process32FirstW(h_snapshot, &entry) != FALSE) {
    do {
      if (::_wcsicmp(process_name, entry.szExeFile) == 0) {
        matched_pid = entry.th32ProcessID;
        break;
      }
      entry = {};
      entry.dwSize = static_cast<DWORD>(sizeof(PROCESSENTRY32W));
    } while (::Process32NextW(h_snapshot, &entry) != FALSE);
  }

  ::CloseHandle(h_snapshot);
  return matched_pid;
}

module_audit_result query_loaded_module_info(
    DWORD pid,
    const wchar_t* module_name) noexcept {
  module_audit_result result{};
  result.process_id = pid;

  if (pid == 0 || module_name == nullptr || module_name[0] == L'\0') {
    return result;
  }

  const HANDLE h_snapshot = ::CreateToolhelp32Snapshot(
      TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
      pid);
  if (h_snapshot == INVALID_HANDLE_VALUE || h_snapshot == nullptr) {
    return result;
  }

  MODULEENTRY32W mod{};
  mod.dwSize = static_cast<DWORD>(sizeof(MODULEENTRY32W));

  if (::Module32FirstW(h_snapshot, &mod) != FALSE) {
    do {
      if (::_wcsicmp(module_name, mod.szModule) == 0) {
        result.module_base = reinterpret_cast<std::uintptr_t>(mod.modBaseAddr);
        result.module_size = mod.modBaseSize;
        result.found = true;
        break;
      }
      mod = {};
      mod.dwSize = static_cast<DWORD>(sizeof(MODULEENTRY32W));
    } while (::Module32NextW(h_snapshot, &mod) != FALSE);
  }

  ::CloseHandle(h_snapshot);
  return result;
}

}  // namespace

int wmain() {
  constexpr wchar_t kTargetProcess[] = L"notepad.exe";
  constexpr wchar_t kInspectedModule[] = L"ntdll.dll";

  std::wcout
      << L"====================================================\n"
      << L"[*] PE 16: LOADED MODULE & SECTION TELEMETRY STUDY\n"
      << L"====================================================\n";

  const DWORD pid = find_process_id_by_name(kTargetProcess);
  if (pid == 0) {
    std::wcout << L"[-] Target process not running: " << kTargetProcess << L"\n";
    return 1;
  }

  const HANDLE h_process = ::OpenProcess(
      PROCESS_QUERY_LIMITED_INFORMATION,
      FALSE,
      pid);
  if (h_process == nullptr || h_process == INVALID_HANDLE_VALUE) {
    std::wcerr << L"[-] OpenProcess failed. Win32=" << ::GetLastError() << L"\n";
    return 1;
  }

  const module_audit_result mod_info = query_loaded_module_info(pid, kInspectedModule);
  if (mod_info.found) {
    std::wcout
        << L"[+] Module '" << kInspectedModule
        << L"' in PID=" << mod_info.process_id
        << L": Base=0x" << std::hex << mod_info.module_base
        << L", Size=0x" << mod_info.module_size
        << std::dec << L"\n";
  } else {
    std::wcout << L"[-] Module '" << kInspectedModule
               << L"' not found in PID=" << pid << L".\n";
  }

  ::CloseHandle(h_process);
  return 0;
}
