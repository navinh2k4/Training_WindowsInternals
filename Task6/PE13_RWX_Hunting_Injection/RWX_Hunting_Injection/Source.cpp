
\#include <windows.h>
#include <tlhelp32.h>

#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <iostream>

namespace {

struct memory_region_audit final {
  std::uintptr_t base_address = 0;
  SIZE_T region_size = 0;
  DWORD state = 0;
  DWORD protect = 0;
  DWORD type = 0;
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

memory_region_audit scan_virtual_memory_regions(
    HANDLE h_process,
    SIZE_T minimum_bytes) noexcept {
  memory_region_audit summary{};
  if (h_process == nullptr || h_process == INVALID_HANDLE_VALUE) {
    return summary;
  }

  MEMORY_BASIC_INFORMATION mbi{};
  std::uintptr_t cursor = 0x1000000ULL;

  while (::VirtualQueryEx(
             h_process,
             reinterpret_cast<LPCVOID>(cursor),
             &mbi,
             sizeof(mbi)) != 0) {
    if (mbi.State == MEM_COMMIT &&
        mbi.Type == MEM_PRIVATE &&
        mbi.Protect == PAGE_READWRITE &&
        mbi.RegionSize >= minimum_bytes &&
        !summary.found) {
      summary.base_address = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
      summary.region_size = mbi.RegionSize;
      summary.state = mbi.State;
      summary.protect = mbi.Protect;
      summary.type = mbi.Type;
      summary.found = true;
    }

    const std::uintptr_t next_addr =
        reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) +
        static_cast<std::uintptr_t>(mbi.RegionSize);
    if (next_addr <= cursor) {
      break;
    }
    cursor = next_addr;
  }

  return summary;
}

}  // namespace

int wmain() {
  constexpr wchar_t kTargetProcess[] = L"notepad.exe";
  constexpr SIZE_T kProbeSize = 4096U;

  std::wcout
      << L"====================================================\n"
      << L"[*] PE 13: VIRTUAL MEMORY TOPOLOGY & AUDIT STUDY\n"
      << L"====================================================\n";

  const DWORD pid = find_process_id_by_name(kTargetProcess);
  if (pid == 0) {
    std::wcout << L"[-] Target process not running: " << kTargetProcess << L"\n";
    return 1;
  }

  const HANDLE h_process = ::OpenProcess(
      PROCESS_QUERY_LIMITED_INFORMATION,
      FALSE,
      pid);
  if (h_process == nullptr || h_process == INVALID_HANDLE_VALUE) {
    std::wcerr << L"[-] OpenProcess failed. Win32=" << ::GetLastError() << L"\n";
    return 1;
  }

  const memory_region_audit audit = scan_virtual_memory_regions(h_process, kProbeSize);
  if (audit.found) {
    std::wcout
        << L"[+] Sample private RW region: base=0x" << std::hex << audit.base_address
        << L", size=" << std::dec << audit.region_size
        << L" bytes, protect=0x" << std::hex << audit.protect << std::dec << L"\n";
  } else {
    std::wcout << L"[-] No matching private RW region found.\n";
  }

  ::CloseHandle(h_process);
  return 0;
}
