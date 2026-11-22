
#include <windows.h>
#include <tlhelp32.h>

#include <cwchar>
#include <iostream>

namespace {

using GetProcAddressFn = FARPROC(WINAPI*)(HMODULE, LPCSTR);

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

}  // namespace

int wmain() {
  constexpr wchar_t kTargetProcess[] = L"notepad.exe";
  char k32_name[] = {'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', '\0'};
  char query_name[] = {
      'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', '\0'};

  std::wcout
      << L"====================================================\n"
      << L"[*] PE 03: DYNAMIC SYMBOL RESOLUTION & DEFENSE STUDY\n"
      << L"====================================================\n";

  const DWORD pid = find_process_id_by_name(kTargetProcess);
  if (pid == 0) {
    std::wcout << L"[-] Target process not running: " << kTargetProcess << L"\n";
  } else {
    std::wcout << L"[+] Target process observed: PID=" << pid << L"\n";
  }

  const HMODULE h_kernel32 = ::GetModuleHandleA(k32_name);
  if (h_kernel32 == nullptr) {
    std::wcerr << L"[-] Failed to resolve module handle.\n";
    return 1;
  }

  const FARPROC raw_proc = ::GetProcAddress(h_kernel32, query_name);
  if (raw_proc == nullptr) {
    std::wcerr << L"[-] Failed to resolve exported symbol.\n";
    return 1;
  }

  auto fn_get_current_process = reinterpret_cast<HANDLE(WINAPI*)()>(raw_proc);
  const HANDLE h_self = fn_get_current_process();
  std::wcout << L"[+] Resolved symbol dynamically; pseudo-handle=" << h_self << L"\n";
  return 0;
}
