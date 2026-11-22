
#include <windows.h>
#include <tlhelp32.h>

#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <iostream>

namespace {

struct inspection_context final {
  DWORD target_pid = 0;
  std::size_t sample_span_bytes = 0;
  DWORD status_code = ERROR_SUCCESS;
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

DWORD WINAPI worker_thread_routine(LPVOID lp_param) noexcept {
  auto* ctx = static_cast<inspection_context*>(lp_param);
  if (ctx == nullptr) {
    return ERROR_INVALID_PARAMETER;
  }
  ctx->status_code = ERROR_SUCCESS;
  return ERROR_SUCCESS;
}

DWORD WINAPI worker_thread_end_marker() noexcept {
  return 0;
}

std::size_t compute_bounded_span() noexcept {
  const auto start_addr = reinterpret_cast<std::uintptr_t>(&worker_thread_routine);
  const auto end_addr = reinterpret_cast<std::uintptr_t>(&worker_thread_end_marker);
  if (end_addr > start_addr) {
    const std::size_t diff = static_cast<std::size_t>(end_addr - start_addr);
    if (diff > 0 && diff <= 4096U) {
      return diff;
    }
  }
  return 256U;
}

}  // namespace

int wmain() {
  constexpr wchar_t kTargetProcess[] = L"notepad.exe";

  std::wcout
      << L"====================================================\n"
      << L"[*] PE 09: LOCAL WORKER THREAD & MEMORY LAYOUT STUDY\n"
      << L"====================================================\n";

  const DWORD observed_pid = find_process_id_by_name(kTargetProcess);
  if (observed_pid == 0) {
    std::wcout << L"[*] Process '" << kTargetProcess << L"' is not currently running.\n";
  } else {
    std::wcout << L"[+] Observed target process '" << kTargetProcess
               << L"' (PID=" << observed_pid << L").\n";
  }

  inspection_context ctx{};
  ctx.target_pid = observed_pid;
  ctx.sample_span_bytes = compute_bounded_span();

  const HANDLE h_thread = ::CreateThread(
      nullptr,
      0,
      &worker_thread_routine,
      &ctx,
      0,
      nullptr);
  if (h_thread == nullptr) {
    std::wcerr << L"[-] CreateThread failed. Win32=" << ::GetLastError() << L"\n";
    return 1;
  }

  ::WaitForSingleObject(h_thread, INFINITE);
  ::CloseHandle(h_thread);

  std::wcout
      << L"[+] Worker thread completed (status=" << ctx.status_code
      << L", measured_span=" << ctx.sample_span_bytes << L" bytes).\n";
  return 0;
}
