#include <windows.h>
#include <tlhelp32.h>

#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <iostream>

extern "C" ULONG_PTR g_nt_query_syscall_addr = 0;

extern "C" LONG nt_query_virtual_memory_indirect(
    HANDLE process_handle,
    PVOID base_address,
    DWORD memory_information_class,
    PVOID memory_information,
    SIZE_T memory_information_length,
    PSIZE_T return_length);

namespace {

struct indirect_stub_audit final {
  DWORD pid = 0;
  std::uintptr_t syscall_insn_va = 0;
  std::uintptr_t region_base = 0;
  SIZE_T region_bytes = 0;
  LONG nt_status = 0;
  bool found_process = false;
  bool located_syscall_bytes = false;
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

std::uintptr_t locate_ntdll_syscall_opcode(const char* export_name) noexcept {
  if (export_name == nullptr || export_name[0] == '\0') {
    return 0;
  }

  const HMODULE h_ntdll = ::GetModuleHandleW(L"ntdll.dll");
  if (h_ntdll == nullptr) {
    return 0;
  }

  const FARPROC raw_proc = ::GetProcAddress(h_ntdll, export_name);
  if (raw_proc == nullptr) {
    return 0;
  }

  const auto* stub_bytes = reinterpret_cast<const std::uint8_t*>(raw_proc);
  // Scan a short window for the x64 `syscall` instruction bytes (0x0F, 0x05).
  for (std::size_t i = 0; i + 1 < 32U; ++i) {
    if (stub_bytes[i] == 0x0FU && stub_bytes[i + 1] == 0x05U) {
      return reinterpret_cast<std::uintptr_t>(stub_bytes + i);
    }
  }

  return 0;
}

indirect_stub_audit run_indirect_memory_probe(const wchar_t* process_name) noexcept {
  indirect_stub_audit audit{};
  audit.pid = find_process_id_by_name(process_name);
  if (audit.pid == 0) {
    return audit;
  }
  audit.found_process = true;

  audit.syscall_insn_va = locate_ntdll_syscall_opcode("NtQueryVirtualMemory");
  g_nt_query_syscall_addr = static_cast<ULONG_PTR>(audit.syscall_insn_va);
  if (g_nt_query_syscall_addr == 0) {
    return audit;
  }
  audit.located_syscall_bytes = true;

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
    const LONG status = nt_query_virtual_memory_indirect(
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
      << L"[*] PE 25: CALL STACK & SYSCALL PROVENANCE STUDY\n"
      << L"====================================================\n";

  const indirect_stub_audit audit = run_indirect_memory_probe(kTargetProcess);
  if (!audit.found_process) {
    std::wcout << L"[-] Target process not running: " << kTargetProcess << L"\n";
    return 1;
  }

  std::wcout << L"[+] Target '" << kTargetProcess << L"' active (PID=" << audit.pid << L")\n";

  if (audit.located_syscall_bytes) {
    std::wcout << L"[+] Located ntdll syscall opcode at VA=0x"
               << std::hex << audit.syscall_insn_va << std::dec << L"\n";
  }

  if (audit.sampled_region) {
    std::wcout << L"[+] Sampled committed region: Base=0x" << std::hex << audit.region_base
               << L", Size=0x" << audit.region_bytes << std::dec << L"\n";
  } else {
    std::wcout << L"[*] Probe returned NTSTATUS=0x" << std::hex << audit.nt_status
               << std::dec << L"\n";
  }

  return 0;
}
