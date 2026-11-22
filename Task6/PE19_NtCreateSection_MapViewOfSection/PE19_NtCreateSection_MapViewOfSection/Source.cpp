
#include <windows.h>
#include <tlhelp32.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <iostream>

namespace {

using NTSTATUS = LONG;

using NtCreateSectionFn = NTSTATUS(NTAPI*)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle);

using NtMapViewOfSectionFn = NTSTATUS(NTAPI*)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect);

using NtUnmapViewOfSectionFn = NTSTATUS(NTAPI*)(
    HANDLE ProcessHandle,
    PVOID BaseAddress);

struct section_mapping_audit final {
  HANDLE section_handle = nullptr;
  PVOID local_view = nullptr;
  PVOID remote_view = nullptr;
  SIZE_T view_bytes = 0;
  bool mapped_local = false;
  bool mapped_remote = false;
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

void cleanup_section_audit(
    HANDLE h_process,
    NtUnmapViewOfSectionFn unmap_fn,
    section_mapping_audit& audit) noexcept {
  if (audit.remote_view != nullptr) {
    if (unmap_fn != nullptr && h_process != nullptr && h_process != INVALID_HANDLE_VALUE) {
      unmap_fn(h_process, audit.remote_view);
    }
    audit.remote_view = nullptr;
  }

  if (audit.local_view != nullptr) {
    if (unmap_fn != nullptr) {
      unmap_fn(::GetCurrentProcess(), audit.local_view);
    } else {
      ::UnmapViewOfFile(audit.local_view);
    }
    audit.local_view = nullptr;
  }

  if (audit.section_handle != nullptr) {
    ::CloseHandle(audit.section_handle);
    audit.section_handle = nullptr;
  }
}

}  // namespace

int wmain() {
  constexpr wchar_t kTargetProcess[] = L"notepad.exe";
  constexpr SIZE_T kSectionBytes = 4096U;
  constexpr DWORD kViewShareUnmap = 2U;

  std::wcout
      << L"====================================================\n"
      << L"[*] PE 19: SHARED SECTION MAPPING & TELEMETRY STUDY\n"
      << L"====================================================\n";

  const DWORD pid = find_process_id_by_name(kTargetProcess);
  if (pid == 0) {
    std::wcout << L"[-] Target process not running: " << kTargetProcess << L"\n";
    return 1;
  }

  const HMODULE h_ntdll = ::GetModuleHandleW(L"ntdll.dll");
  if (h_ntdll == nullptr) {
    std::wcerr << L"[-] GetModuleHandleW(ntdll.dll) failed.\n";
    return 1;
  }

  auto fn_create_section = reinterpret_cast<NtCreateSectionFn>(
      ::GetProcAddress(h_ntdll, "NtCreateSection"));
  auto fn_map_view = reinterpret_cast<NtMapViewOfSectionFn>(
      ::GetProcAddress(h_ntdll, "NtMapViewOfSection"));
  auto fn_unmap_view = reinterpret_cast<NtUnmapViewOfSectionFn>(
      ::GetProcAddress(h_ntdll, "NtUnmapViewOfSection"));

  if (fn_create_section == nullptr || fn_map_view == nullptr) {
    std::wcerr << L"[-] Failed to resolve section mapping APIs from ntdll.dll.\n";
    return 1;
  }

  const HANDLE h_process = ::OpenProcess(
      PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION,
      FALSE,
      pid);
  if (h_process == nullptr || h_process == INVALID_HANDLE_VALUE) {
    std::wcerr << L"[-] OpenProcess failed. Win32=" << ::GetLastError() << L"\n";
    return 1;
  }

  section_mapping_audit audit{};
  audit.view_bytes = kSectionBytes;

  LARGE_INTEGER max_size{};
  max_size.QuadPart = static_cast<LONGLONG>(kSectionBytes);

  const NTSTATUS sec_status = fn_create_section(
      &audit.section_handle,
      SECTION_MAP_READ | SECTION_MAP_WRITE,
      nullptr,
      &max_size,
      PAGE_READWRITE,
      SEC_COMMIT,
      nullptr);

  if (sec_status != 0 || audit.section_handle == nullptr) {
    std::wcerr << L"[-] NtCreateSection failed. NTSTATUS=0x"
               << std::hex << sec_status << std::dec << L"\n";
    ::CloseHandle(h_process);
    return 1;
  }

  SIZE_T local_view_sz = kSectionBytes;
  const NTSTATUS local_map_status = fn_map_view(
      audit.section_handle,
      ::GetCurrentProcess(),
      &audit.local_view,
      0,
      0,
      nullptr,
      &local_view_sz,
      kViewShareUnmap,
      0,
      PAGE_READWRITE);

  if (local_map_status != 0 || audit.local_view == nullptr) {
    std::wcerr << L"[-] Local NtMapViewOfSection failed. NTSTATUS=0x"
               << std::hex << local_map_status << std::dec << L"\n";
    cleanup_section_audit(h_process, fn_unmap_view, audit);
    ::CloseHandle(h_process);
    return 1;
  }
  audit.mapped_local = true;

  constexpr char kProbeTag[] = "PE19_SECTION_AUDIT_MARKER";
  std::memcpy(audit.local_view, kProbeTag, sizeof(kProbeTag));

  SIZE_T remote_view_sz = kSectionBytes;
  const NTSTATUS remote_map_status = fn_map_view(
      audit.section_handle,
      h_process,
      &audit.remote_view,
      0,
      0,
      nullptr,
      &remote_view_sz,
      kViewShareUnmap,
      0,
      PAGE_READONLY);

  if (remote_map_status == 0 && audit.remote_view != nullptr) {
    audit.mapped_remote = true;
    std::wcout
        << L"[+] Mapped shared RW section: Local=0x"
        << std::hex << reinterpret_cast<std::uintptr_t>(audit.local_view)
        << L" (RW) -> Remote=0x"
        << reinterpret_cast<std::uintptr_t>(audit.remote_view)
        << L" (RO) in PID=" << std::dec << pid << L"\n";
  } else {
    std::wcout
        << L"[*] Local RW view at 0x"
        << std::hex << reinterpret_cast<std::uintptr_t>(audit.local_view)
        << L"; remote view mapping declined (NTSTATUS=0x"
        << remote_map_status << L", PID=" << std::dec << pid << L").\n";
  }

  cleanup_section_audit(h_process, fn_unmap_view, audit);
  ::CloseHandle(h_process);
  return 0;
}
