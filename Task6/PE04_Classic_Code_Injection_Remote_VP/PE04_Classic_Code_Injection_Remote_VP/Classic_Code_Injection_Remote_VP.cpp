
#include <windows.h>
#include <tlhelp32.h>

#include <cwchar>
#include <iostream>

namespace {

struct remote_page_pair final {
  LPVOID primary_page = nullptr;
  LPVOID secondary_page = nullptr;
  SIZE_T page_bytes = 0;
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

void release_remote_pages(HANDLE h_process, remote_page_pair& pages) noexcept {
  if (h_process != nullptr && h_process != INVALID_HANDLE_VALUE) {
    if (pages.primary_page != nullptr) {
      ::VirtualFreeEx(h_process, pages.primary_page, 0, MEM_RELEASE);
      pages.primary_page = nullptr;
    }
    if (pages.secondary_page != nullptr) {
      ::VirtualFreeEx(h_process, pages.secondary_page, 0, MEM_RELEASE);
      pages.secondary_page = nullptr;
    }
  }
}

bool allocate_rw_pages(
    HANDLE h_process,
    SIZE_T page_bytes,
    remote_page_pair& out_pages) noexcept {
  out_pages = {};

  LPVOID first = ::VirtualAllocEx(
      h_process,
      nullptr,
      page_bytes,
      MEM_COMMIT | MEM_RESERVE,
      PAGE_READWRITE);
  if (first == nullptr) {
    return false;
  }

  LPVOID second = ::VirtualAllocEx(
      h_process,
      nullptr,
      page_bytes,
      MEM_COMMIT | MEM_RESERVE,
      PAGE_READWRITE);
  if (second == nullptr) {
    ::VirtualFreeEx(h_process, first, 0, MEM_RELEASE);
    return false;
  }

  out_pages.primary_page = first;
  out_pages.secondary_page = second;
  out_pages.page_bytes = page_bytes;
  return true;
}

}  // namespace

int wmain() {
  constexpr wchar_t kTargetProcess[] = L"notepad.exe";
  constexpr SIZE_T kPageSize = 4096U;

  std::wcout
      << L"====================================================\n"
      << L"[*] PE 04: PAGE PROTECTION TRANSITION STUDY (RW -> RX)\n"
      << L"====================================================\n";

  const DWORD pid = find_process_id_by_name(kTargetProcess);
  if (pid == 0) {
    ::MessageBoxW(
        nullptr,
        L"[-] Target process not found. Open notepad.exe first.",
        L"Info",
        MB_OK | MB_ICONINFORMATION);
    return 1;
  }

  std::wcout << L"[+] Target process PID: " << pid << L"\n";

  const HANDLE h_process = ::OpenProcess(
      PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION,
      FALSE,
      pid);
  if (h_process == nullptr || h_process == INVALID_HANDLE_VALUE) {
    std::wcerr << L"[-] OpenProcess failed. Win32=" << ::GetLastError() << L"\n";
    return 1;
  }

  remote_page_pair pages{};
  if (!allocate_rw_pages(h_process, kPageSize, pages)) {
    std::wcerr << L"[-] VirtualAllocEx (RW) failed. Win32=" << ::GetLastError() << L"\n";
    ::CloseHandle(h_process);
    return 1;
  }

  DWORD prev_protect = 0;
  if (::VirtualProtectEx(
          h_process,
          pages.primary_page,
          pages.page_bytes,
          PAGE_EXECUTE_READ,
          &prev_protect) == FALSE) {
    std::wcerr << L"[-] VirtualProtectEx (RX) failed. Win32=" << ::GetLastError() << L"\n";
    release_remote_pages(h_process, pages);
    ::CloseHandle(h_process);
    return 1;
  }

  std::wcout
      << L"[+] Transitioned primary page to RX (previous=0x"
      << std::hex << prev_protect << L") at 0x" << pages.primary_page
      << std::dec << L"\n";

  ::MessageBoxW(
      nullptr,
      L"[+] PAUSE: Inspect page protections in target process now.",
      L"Defensive Analysis",
      MB_OK | MB_ICONINFORMATION);

  release_remote_pages(h_process, pages);
  ::CloseHandle(h_process);

  std::wcout << L"[+] Cleanup completed.\n";
  return 0;
}
