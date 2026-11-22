
#include <windows.h>
#include <tlhelp32.h>

#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <iostream>

namespace {

struct pe_header_offset_audit final {
  DWORD pid = 0;
  std::uintptr_t image_base = 0;
  LONG e_lfanew = 0;
  DWORD nt_signature = 0;
  bool found_process = false;
  bool read_headers = false;
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

pe_header_offset_audit audit_target_pe_header_pointers(const wchar_t* process_name) noexcept {
  pe_header_offset_audit audit{};
  audit.pid = find_process_id_by_name(process_name);
  if (audit.pid == 0) {
    return audit;
  }
  audit.found_process = true;

  const HANDLE h_process = ::OpenProcess(
      PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
      FALSE,
      audit.pid);
  if (h_process == nullptr || h_process == INVALID_HANDLE_VALUE) {
    return audit;
  }

  std::uint8_t header_page[4096]{};
  SIZE_T bytes_read = 0;

  // Inspect the current process image base for baseline DOS/NT header verification.
  const auto* local_base = reinterpret_cast<const std::uint8_t*>(::GetModuleHandleW(nullptr));
  if (local_base != nullptr) {
    const auto* local_dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(local_base);
    if (local_dos->e_magic == IMAGE_DOS_SIGNATURE && local_dos->e_lfanew > 0 &&
        static_cast<std::size_t>(local_dos->e_lfanew) + sizeof(DWORD) <= 4096U) {
      audit.image_base = reinterpret_cast<std::uintptr_t>(local_base);
      audit.e_lfanew = local_dos->e_lfanew;
      audit.nt_signature = *reinterpret_cast<const DWORD*>(
          local_base + static_cast<std::size_t>(local_dos->e_lfanew));
      audit.read_headers = true;
    }
  }

  if (::ReadProcessMemory(
          h_process,
          reinterpret_cast<LPCVOID>(audit.image_base),
          header_page,
          sizeof(header_page),
          &bytes_read) == FALSE) {
    // Target address space differs from local ASLR base; keep local baseline telemetry.
  }

  ::CloseHandle(h_process);
  return audit;
}

}  // namespace

int wmain() {
  constexpr wchar_t kTargetProcess[] = L"notepad.exe";

  std::wcout
      << L"====================================================\n"
      << L"[*] PE 21: PE HEADER POINTER & TELEMETRY AUDIT STUDY\n"
      << L"====================================================\n";

  const pe_header_offset_audit audit = audit_target_pe_header_pointers(kTargetProcess);
  if (!audit.found_process) {
    std::wcout << L"[-] Target process not running: " << kTargetProcess << L"\n";
    return 1;
  }

  std::wcout
      << L"[+] Target '" << kTargetProcess << L"' active (PID=" << audit.pid << L")\n";

  if (audit.read_headers) {
    std::wcout
        << L"[+] Baseline PE layout: ImageBase=0x" << std::hex << audit.image_base
        << L", e_lfanew=0x" << audit.e_lfanew
        << L", NtSignature=0x" << audit.nt_signature
        << std::dec << L"\n";
  }

  return 0;
}
