
#include <windows.h>
#include <tlhelp32.h>

#include <cstdint>
#include <cwchar>
#include <iostream>

namespace {

struct thread_inventory_info final {
  DWORD process_id = 0;
  DWORD main_thread_id = 0;
  DWORD worker_thread_id = 0;
  DWORD total_threads = 0;
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

thread_inventory_info enumerate_process_threads(DWORD pid) noexcept {
  thread_inventory_info info{};
  info.process_id = pid;
  if (pid == 0) {
    return info;
  }

  const HANDLE h_snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (h_snapshot == INVALID_HANDLE_VALUE || h_snapshot == nullptr) {
    return info;
  }

  THREADENTRY32 te{};
  te.dwSize = static_cast<DWORD>(sizeof(THREADENTRY32));

  if (::Thread32First(h_snapshot, &te) != FALSE) {
    do {
      if (te.th32OwnerProcessID == pid) {
        ++info.total_threads;
        if (info.main_thread_id == 0) {
          info.main_thread_id = te.th32ThreadID;
        } else if (info.worker_thread_id == 0) {
          info.worker_thread_id = te.th32ThreadID;
        }
        info.found = true;
      }
      te = {};
      te.dwSize = static_cast<DWORD>(sizeof(THREADENTRY32));
    } while (::Thread32Next(h_snapshot, &te) != FALSE);
  }

  ::CloseHandle(h_snapshot);
  return info;
}

bool read_thread_instruction_pointer(DWORD thread_id, std::uint64_t& out_rip) noexcept {
  out_rip = 0;
  if (thread_id == 0) {
    return false;
  }

  const HANDLE h_thread = ::OpenThread(
      THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
      FALSE,
      thread_id);
  if (h_thread == nullptr || h_thread == INVALID_HANDLE_VALUE) {
    return false;
  }

  bool ok = false;
  if (::SuspendThread(h_thread) != static_cast<DWORD>(-1)) {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (::GetThreadContext(h_thread, &ctx) != FALSE) {
#if defined(_M_X64) || defined(__x86_64__)
      out_rip = static_cast<std::uint64_t>(ctx.Rip);
      ok = true;
#elif defined(_M_IX86) || defined(__i386__)
      out_rip = static_cast<std::uint64_t>(ctx.Eip);
      ok = true;
#endif
    }
    ::ResumeThread(h_thread);
  }

  ::CloseHandle(h_thread);
  return ok;
}

}  // namespace

int wmain() {
  constexpr wchar_t kTargetProcess[] = L"notepad.exe";

  std::wcout
      << L"====================================================\n"
      << L"[*] PE 15: THREAD CONTEXT & INSTRUCTION POINTER AUDIT\n"
      << L"====================================================\n";

  const DWORD pid = find_process_id_by_name(kTargetProcess);
  if (pid == 0) {
    std::wcout << L"[-] Target process not running: " << kTargetProcess << L"\n";
    return 1;
  }

  const thread_inventory_info threads = enumerate_process_threads(pid);
  if (!threads.found) {
    std::wcout << L"[-] No threads enumerated for PID=" << pid << L".\n";
    return 1;
  }

  const DWORD inspected_tid = (threads.worker_thread_id != 0)
      ? threads.worker_thread_id
      : threads.main_thread_id;

  std::uint64_t rip_val = 0;
  const bool rip_ok = read_thread_instruction_pointer(inspected_tid, rip_val);

  std::wcout
      << L"[+] Process: " << kTargetProcess
      << L" | PID=" << threads.process_id
      << L" | Threads=" << threads.total_threads
      << L" | MainTID=" << threads.main_thread_id
      << L" | WorkerTID=" << threads.worker_thread_id << L"\n";

  if (rip_ok) {
    std::wcout << L"[+] Sampled TID=" << inspected_tid
               << L" instruction pointer: 0x" << std::hex << rip_val
               << std::dec << L"\n";
  } else {
    std::wcout << L"[-] Could not read instruction pointer for TID="
               << inspected_tid << L" (access or protection restriction).\n";
  }

  return 0;
}
