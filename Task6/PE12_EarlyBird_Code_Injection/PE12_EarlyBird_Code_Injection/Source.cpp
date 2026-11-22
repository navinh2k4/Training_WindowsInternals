
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

namespace {

struct early_stage_audit final {
  DWORD pid = 0;
  DWORD tid = 0;
  DWORD apc_status = 0;
};

std::wstring build_system_target_path(const wchar_t* exe_name) {
  if (exe_name == nullptr || exe_name[0] == L'\0') {
    return L"";
  }

  const UINT needed = ::GetSystemDirectoryW(nullptr, 0);
  if (needed == 0) {
    return L"";
  }

  wchar_t* dir_buf = static_cast<wchar_t*>(
      ::HeapAlloc(
          ::GetProcessHeap(),
          HEAP_ZERO_MEMORY,
          static_cast<std::size_t>(needed) * sizeof(wchar_t)));
  if (dir_buf == nullptr) {
    return L"";
  }

  std::wstring full_path;
  const UINT written = ::GetSystemDirectoryW(dir_buf, needed);
  if (written > 0 && written < needed) {
    full_path.assign(dir_buf, static_cast<std::size_t>(written));
    full_path.push_back(L'\\');
    full_path.append(exe_name);
  }

  ::HeapFree(::GetProcessHeap(), 0, dir_buf);
  return full_path;
}

VOID CALLBACK early_stage_apc_probe(ULONG_PTR parameter) noexcept {
  auto* audit = reinterpret_cast<early_stage_audit*>(parameter);
  if (audit != nullptr) {
    audit->apc_status = ERROR_SUCCESS;
  }
}

}  // namespace

int wmain() {
  constexpr wchar_t kTargetExe[] = L"notepad.exe";

  std::wcout
      << L"====================================================\n"
      << L"[*] PE 12: EARLY PROCESS INITIALIZATION & APC STUDY\n"
      << L"====================================================\n";

  const std::wstring target_path = build_system_target_path(kTargetExe);
  if (target_path.empty()) {
    std::wcerr << L"[-] Failed to resolve target system executable path.\n";
    return 1;
  }

  std::wcout << L"[+] Resolved target path: " << target_path << L"\n";

  std::wstring cmd_line = L"\"" + target_path + L"\"";
  STARTUPINFOW si{};
  si.cb = static_cast<DWORD>(sizeof(STARTUPINFOW));
  PROCESS_INFORMATION pi{};

  if (::CreateProcessW(
          target_path.c_str(),
          cmd_line.data(),
          nullptr,
          nullptr,
          FALSE,
          CREATE_SUSPENDED,
          nullptr,
          nullptr,
          &si,
          &pi) == FALSE) {
    std::wcerr << L"[-] CreateProcessW(CREATE_SUSPENDED) failed. Win32="
               << ::GetLastError() << L"\n";
    return 1;
  }

  early_stage_audit audit{};
  audit.pid = pi.dwProcessId;
  audit.tid = pi.dwThreadId;

  const DWORD queued = ::QueueUserAPC(
      &early_stage_apc_probe,
      pi.hThread,
      reinterpret_cast<ULONG_PTR>(&audit));
  if (queued == 0) {
    std::wcerr << L"[-] QueueUserAPC failed. Win32=" << ::GetLastError() << L"\n";
    ::TerminateProcess(pi.hProcess, 0);
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);
    return 1;
  }

  std::wcout
      << L"[+] Queued early-stage APC on suspended process (PID=" << pi.dwProcessId
      << L", TID=" << pi.dwThreadId << L").\n";

  ::TerminateProcess(pi.hProcess, 0);
  ::CloseHandle(pi.hThread);
  ::CloseHandle(pi.hProcess);
  return 0;
}
