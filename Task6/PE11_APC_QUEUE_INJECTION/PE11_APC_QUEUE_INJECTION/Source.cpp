
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

namespace {

struct apc_audit_context final {
  DWORD process_id = 0;
  DWORD thread_id = 0;
  DWORD queued_result = 0;
};

std::wstring build_system_binary_path(const wchar_t* exe_name) {
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

VOID CALLBACK diagnostic_apc_callback(ULONG_PTR parameter) noexcept {
  auto* ctx = reinterpret_cast<apc_audit_context*>(parameter);
  if (ctx != nullptr) {
    ctx->queued_result = ERROR_SUCCESS;
  }
}

}  // namespace

int wmain() {
  constexpr wchar_t kTargetExe[] = L"notepad.exe";

  std::wcout
      << L"====================================================\n"
      << L"[*] PE 11: APC QUEUE & THREAD LIFECYCLE AUDIT STUDY\n"
      << L"====================================================\n";

  const std::wstring target_path = build_system_binary_path(kTargetExe);
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

  apc_audit_context ctx{};
  ctx.process_id = pi.dwProcessId;
  ctx.thread_id = pi.dwThreadId;

  const DWORD queued = ::QueueUserAPC(
      &diagnostic_apc_callback,
      pi.hThread,
      reinterpret_cast<ULONG_PTR>(&ctx));
  if (queued == 0) {
    std::wcerr << L"[-] QueueUserAPC failed. Win32=" << ::GetLastError() << L"\n";
    ::TerminateProcess(pi.hProcess, 0);
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);
    return 1;
  }

  std::wcout
      << L"[+] Queued APC entry on suspended process (PID=" << pi.dwProcessId
      << L", TID=" << pi.dwThreadId << L").\n";

  ::TerminateProcess(pi.hProcess, 0);
  ::CloseHandle(pi.hThread);
  ::CloseHandle(pi.hProcess);
  return 0;
}
