
#include <windows.h>

#include <cstddef>
#include <iostream>

#pragma comment(lib, "user32.lib")

namespace {

struct thread_context_params final {
  std::size_t region_size = 0;
  DWORD exit_status = 0;
};

DWORD WINAPI inspect_worker_routine(LPVOID lp_param) noexcept {
  auto* params = static_cast<thread_context_params*>(lp_param);
  if (params == nullptr) {
    return ERROR_INVALID_PARAMETER;
  }
  params->exit_status = ERROR_SUCCESS;
  return ERROR_SUCCESS;
}

}  // namespace

int wmain() {
  constexpr std::size_t kRegionSize = 4096U;

  std::wcout << L"====================================================\n"
             << L"[*] PE 01: LOCAL MEMORY & THREAD INSPECTION STUDY\n"
             << L"====================================================\n";

  // Allocate read-write memory first, then transition to read-execute (W^X).
  LPVOID local_code_buf = ::VirtualAlloc(
      nullptr,
      kRegionSize,
      MEM_COMMIT | MEM_RESERVE,
      PAGE_READWRITE);
  if (local_code_buf == nullptr) {
    std::wcerr << L"[-] VirtualAlloc (RW) failed. Win32=" << ::GetLastError() << L"\n";
    return 1;
  }

  DWORD old_protect = 0;
  if (::VirtualProtect(local_code_buf, kRegionSize, PAGE_EXECUTE_READ, &old_protect) == FALSE) {
    std::wcerr << L"[-] VirtualProtect (RX) failed. Win32=" << ::GetLastError() << L"\n";
    ::VirtualFree(local_code_buf, 0, MEM_RELEASE);
    return 1;
  }

  thread_context_params params{kRegionSize, ERROR_SUCCESS};
  const HANDLE h_thread = ::CreateThread(
      nullptr,
      0,
      &inspect_worker_routine,
      &params,
      0,
      nullptr);
  if (h_thread == nullptr) {
    std::wcerr << L"[-] CreateThread failed. Win32=" << ::GetLastError() << L"\n";
    ::VirtualFree(local_code_buf, 0, MEM_RELEASE);
    return 1;
  }

  ::WaitForSingleObject(h_thread, INFINITE);

  ::MessageBoxA(
      nullptr,
      "[+] PAUSE: Inspect private memory region and active threads now.",
      "Defensive Analysis",
      MB_OK | MB_ICONINFORMATION);

  ::CloseHandle(h_thread);
  ::VirtualFree(local_code_buf, 0, MEM_RELEASE);

  std::wcout << L"[+] Memory and thread resources released cleanly.\n";
  return 0;
}
