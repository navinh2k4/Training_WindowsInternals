
#include <windows.h>
#include <tlhelp32.h>

#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <iostream>

namespace {

using NTSTATUS = LONG;

using NtQueryVirtualMemoryFn = NTSTATUS(NTAPI*)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    DWORD MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength);

struct native_memory_probe final {
  DWORD pid = 0;
  std::uintptr_t base_address = 0;
  SIZE_T region_size = 0;
  DWORD state = 0;
  DWORD protect = 0;
  DWORD type = 0;
  bool found_process = false;
  bool queried_region = false;
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

native_memory_probe query_first_committed_region(const wchar_t* process_name) noexcept {
  native_memory_probe probe{};
  probe.pid = find_process_id_by_name(process_name);
  if (probe.pid == 0) {
    return probe;
  }
  probe.found_process = true;

  const HMODULE h_ntdll = ::GetModuleHandleW(L"ntdll.dll");
  if (h_ntdll == nullptr) {
    return probe;
  }

  const FARPROC raw_proc = ::GetProcAddress(h_ntdll, "NtQueryVirtualMemory");
  if (raw_proc == nullptr) {
    return probe;
  }

  auto fn_query_vm = reinterpret_cast<NtQueryVirtualMemoryFn>(raw_proc);

  const HANDLE h_process = ::OpenProcess(
      PROCESS_QUERY_LIMITED_INFORMATION,
      FALSE,
      probe.pid);
  if (h_process == nullptr || h_process == INVALID_HANDLE_VALUE) {
    return probe;
  }

  MEMORY_BASIC_INFORMATION mbi{};
  SIZE_T return_len = 0;
  constexpr DWORD kMemoryBasicInformation = 0;
  std::uintptr_t cursor = 0x10000ULL;

  while (cursor < 0x7FFFFFFFFFFFULL) {
    const NTSTATUS status = fn_query_vm(
        h_process,
        reinterpret_cast<PVOID>(cursor),
        kMemoryBasicInformation,
        &mbi,
        sizeof(mbi),
        &return_len);
    if (status != 0) {
      break;
    }

    if (mbi.State == MEM_COMMIT && mbi.RegionSize > 0) {
      probe.base_address = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
      probe.region_size = mbi.RegionSize;
      probe.state = mbi.State;
      probe.protect = mbi.Protect;
      probe.type = mbi.Type;
      probe.queried_region = true;
      break;
    }

    const std::uintptr_t next_addr =
        reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) +
        static_cast<std::uintptr_t>(mbi.RegionSize);
    if (next_addr <= cursor) {
      break;
    }
    cursor = next_addr;
  }

  ::CloseHandle(h_process);
  return probe;
}

}  // namespace

int wmain() {
  constexpr wchar_t kTargetProcess[] = L"notepad.exe";

  std::wcout
      << L"====================================================\n"
      << L"[*] PE 23: NTDLL NATIVE API & MEMORY TELEMETRY STUDY\n"
      << L"====================================================\n";

  const native_memory_probe probe = query_first_committed_region(kTargetProcess);
  if (!probe.found_process) {
    std::wcout << L"[-] Target process not running: " << kTargetProcess << L"\n";
    return 1;
  }

  std::wcout << L"[+] Target process '" << kTargetProcess
             << L"' active (PID=" << probe.pid << L").\n";

  if (probe.queried_region) {
    std::wcout
        << L"[+] Sample committed region via NtQueryVirtualMemory: Base=0x"
        << std::hex << probe.base_address
        << L", Size=0x" << probe.region_size
        << L", Protect=0x" << probe.protect
        << L", Type=0x" << probe.type
        << std::dec << L"\n";
  } else {
    std::wcout << L"[-] Could not query virtual memory region via NtQueryVirtualMemory.\n";
  }

  return 0;
}
