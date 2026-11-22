
#include <windows.h>
#include <tlhelp32.h>

#include <cwchar>
#include <iostream>
#include <string>

namespace {

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

std::wstring resolve_module_candidate_path(const wchar_t* module_name) {
  if (module_name == nullptr || module_name[0] == L'\0') {
    return L"";
  }

  wchar_t full_path[MAX_PATH]{};
  const DWORD written = ::GetFullPathNameW(module_name, MAX_PATH, full_path, nullptr);
  if (written > 0 && written < MAX_PATH) {
    return std::wstring(full_path, static_cast<std::size_t>(written));
  }
  return std::wstring(module_name);
}

bool verify_target_module_exists(const std::wstring& candidate_path) noexcept {
  if (candidate_path.empty()) {
    return false;
  }
  const DWORD attrs = ::GetFileAttributesW(candidate_path.c_str());
  return attrs != INVALID_FILE_ATTRIBUTES &&
      (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

}  // namespace

int wmain() {
  constexpr wchar_t kTargetProcess[] = L"notepad.exe";
  constexpr wchar_t kModuleName[] = L"SampleModule.dll";

  std::wcout
      << L"====================================================\n"
      << L"[*] PE 05: MODULE LOADING & PROCESS AUDIT STUDY\n"
      << L"====================================================\n";

  const std::wstring module_path = resolve_module_candidate_path(kModuleName);
  std::wcout << L"[*] Candidate module path: " << module_path << L"\n";
  std::wcout << L"[*] Module file present on disk: "
             << (verify_target_module_exists(module_path) ? L"Yes" : L"No") << L"\n";

  const DWORD pid = find_process_id_by_name(kTargetProcess);
  if (pid == 0) {
    std::wcout << L"[-] Target process not running: " << kTargetProcess << L"\n";
    return 1;
  }

  std::wcout << L"[+] Target process found (PID=" << pid << L").\n";

  const HANDLE h_process = ::OpenProcess(
      PROCESS_QUERY_LIMITED_INFORMATION,
      FALSE,
      pid);
  if (h_process == nullptr || h_process == INVALID_HANDLE_VALUE) {
    std::wcerr << L"[-] OpenProcess failed. Win32=" << ::GetLastError() << L"\n";
    return 1;
  }

  const HMODULE h_kernel32 = ::GetModuleHandleW(L"kernel32.dll");
  const FARPROC load_lib_proc = (h_kernel32 != nullptr)
      ? ::GetProcAddress(h_kernel32, "LoadLibraryW")
      : nullptr;

  std::wcout << L"[+] LoadLibraryW address in current process: 0x"
             << std::hex << reinterpret_cast<ULONG_PTR>(load_lib_proc)
             << std::dec << L"\n";

  ::CloseHandle(h_process);
  return 0;
}
