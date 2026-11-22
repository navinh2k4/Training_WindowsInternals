
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <iostream>

namespace {

struct fiber_execution_audit final {
  LPVOID master_fiber = nullptr;
  LPVOID worker_fiber = nullptr;
  DWORD main_thread_id = 0;
  DWORD callback_thread_id = 0;
  bool worker_executed = false;
};

VOID CALLBACK fiber_diagnostic_routine(LPVOID lp_param) noexcept {
  auto* audit = static_cast<fiber_execution_audit*>(lp_param);
  if (audit == nullptr) {
    return;
  }

  audit->callback_thread_id = ::GetCurrentThreadId();
  audit->worker_executed = true;

  if (audit->master_fiber != nullptr) {
    ::SwitchToFiber(audit->master_fiber);
  }
}

}  // namespace

int wmain() {
  std::wcout
      << L"====================================================\n"
      << L"[*] PE 22: WIN32 FIBERS & COOPERATIVE CONTEXT STUDY\n"
      << L"====================================================\n";

  fiber_execution_audit audit{};
  audit.main_thread_id = ::GetCurrentThreadId();

  audit.master_fiber = ::ConvertThreadToFiberEx(&audit, FIBER_FLAG_FLOAT_SWITCH);
  if (audit.master_fiber == nullptr) {
    std::wcerr << L"[-] ConvertThreadToFiberEx failed. Win32="
               << ::GetLastError() << L"\n";
    return 1;
  }

  audit.worker_fiber = ::CreateFiberEx(
      0,
      0,
      FIBER_FLAG_FLOAT_SWITCH,
      &fiber_diagnostic_routine,
      &audit);
  if (audit.worker_fiber == nullptr) {
    std::wcerr << L"[-] CreateFiberEx failed. Win32=" << ::GetLastError() << L"\n";
    ::ConvertFiberToThread();
    return 1;
  }

  ::SwitchToFiber(audit.worker_fiber);

  std::wcout
      << L"[+] Fiber switch completed: MainTID=" << audit.main_thread_id
      << L", CallbackTID=" << audit.callback_thread_id
      << L", WorkerExecuted=" << (audit.worker_executed ? L"Yes" : L"No") << L"\n";

  ::DeleteFiber(audit.worker_fiber);
  audit.worker_fiber = nullptr;

  if (::ConvertFiberToThread() == FALSE) {
    std::wcerr << L"[-] ConvertFiberToThread failed. Win32="
               << ::GetLastError() << L"\n";
  }

  return 0;
}
