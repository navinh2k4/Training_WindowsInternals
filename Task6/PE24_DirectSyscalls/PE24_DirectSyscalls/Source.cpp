
#include <windows.h>
#include <tlhelp32.h>

#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <iostream>

extern "C" LONG nt_query_virtual_memory_stub(
    HANDLE process_handle,
    PVOID base_address,
    DWORD memory_information_class,
    PVOID memory_information,
    SIZE_T memory_information_length,
    PSIZE_T return_length);

namespace {

struct syscall_telemetry_audit final {
  DWORD pid = 0;
  std::uintptr_t region_base = 0;
  SIZE_T region_bytes = 0;
  DWORD protect = 0;
  DWORD type = 0;
  LONG nt_status = 0;
  bool found_process = false;
  bool sampled_region = false;
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

syscall_telemetry_audit inspect_target_memory_via_stub(const wchar_t* process_name) noexcept {
  syscall_telemetry_audit audit{};
  audit.pid = find_process_id_by_name(process_name);
  if (audit.pid == 0) {
    return audit;
  }
  audit.found_process = true;

  const HANDLE h_process = ::OpenProcess(
      PROCESS_QUERY_LIMITED_INFORMATION,
      FALSE,
      audit.pid);
  if (h_process == nullptr || h_process == INVALID_HANDLE_VALUE) {
    return audit;
  }

  MEMORY_BASIC_INFORMATION mbi{};
  SIZE_T return_len = 0;
  constexpr DWORD kMemoryBasicInformation = 0;
  std::uintptr_t cursor = 0x10000ULL;

  while (cursor < 0x7FFFFFFFFFFFULL) {
    const LONG status = nt_query_virtual_memory_stub(
        h_process,
        reinterpret_cast<PVOID>(cursor),
        kMemoryBasicInformation,
        &mbi,
        sizeof(mbi),
        &return_len);
    audit.nt_status = status;
    if (status != 0) {
      break;
    }

    if (mbi.State == MEM_COMMIT && mbi.RegionSize > 0) {
      audit.region_base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
      audit.region_bytes = mbi.RegionSize;
      audit.protect = mbi.Protect;
      audit.type = mbi.Type;
      audit.sampled_region = true;
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
  return audit;
}

}  // namespace

int wmain() {
  constexpr wchar_t kTargetProcess[] = L"notepad.exe";

  std::wcout
      << L"====================================================\n"
      << L"[*] PE 24: X64 SYSCALL MECHANICS & TELEMETRY STUDY\n"
      << L"====================================================\n";

  const syscall_telemetry_audit audit = inspect_target_memory_via_stub(kTargetProcess);
  if (!audit.found_process) {
    std::wcout << L"[-] Target process not running: " << kTargetProcess << L"\n";
    return 1;
  }

  std::wcout << L"[+] Target '" << kTargetProcess << L"' active (PID=" << audit.pid << L")\n";

  if (audit.sampled_region) {
    std::wcout
        << L"[+] Sampled committed region: Base=0x" << std::hex << audit.region_base
        << L", Size=0x" << audit.region_bytes
        << L", Protect=0x" << audit.protect
        << L", Type=0x" << audit.type
        << std::dec << L"\n";
  } else {
    std::wcout
        << L"[*] Stub query returned NTSTATUS=0x" << std::hex << audit.nt_status
        << std::dec << L" (SSN depends on host Windows build).\n";
  }

  return 0;
}
