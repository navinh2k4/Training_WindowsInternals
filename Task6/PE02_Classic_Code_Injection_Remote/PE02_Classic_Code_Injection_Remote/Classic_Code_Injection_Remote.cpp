
#include <windows.h>
#include <tlhelp32.h>

#include <cstddef>
#include <cwchar>
#include <iostream>
#include <string>

#pragma comment(lib, "user32.lib")

namespace {

struct remote_region_info final {
  LPVOID code_addr = nullptr;
  LPVOID data_addr = nullptr;
  SIZE_T code_size = 0;
  SIZE_T data_size = 0;
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

void release_remote_regions(
    HANDLE h_process,
    remote_region_info& regions) noexcept {
  if (h_process != nullptr && h_process != INVALID_HANDLE_VALUE) {
    if (regions.code_addr != nullptr) {
      ::VirtualFreeEx(h_process, regions.code_addr, 0, MEM_RELEASE);
      regions.code_addr = nullptr;
    }
    if (regions.data_addr != nullptr) {
      ::VirtualFreeEx(h_process, regions.data_addr, 0, MEM_RELEASE);
      regions.data_addr = nullptr;
    }
  }
}

bool prepare_remote_regions(
    HANDLE h_process,
    SIZE_T code_bytes,
    SIZE_T data_bytes,
    remote_region_info& out_regions) noexcept {
  out_regions = {};

  LPVOID code_buf = ::VirtualAllocEx(
      h_process,
      nullptr,
      code_bytes,
      MEM_COMMIT | MEM_RESERVE,
      PAGE_READWRITE);
  if (code_buf == nullptr) {
    return false;
  }

  LPVOID data_buf = ::VirtualAllocEx(
      h_process,
      nullptr,
      data_bytes,
      MEM_COMMIT | MEM_RESERVE,
      PAGE_READWRITE);
  if (data_buf == nullptr) {
    ::VirtualFreeEx(h_process, code_buf, 0, MEM_RELEASE);
    return false;
  }

  out_regions.code_addr = code_buf;
  out_regions.data_addr = data_buf;
  out_regions.code_size = code_bytes;
  out_regions.data_size = data_bytes;
  return true;
}

}  // namespace

int wmain() {
  constexpr wchar_t kTargetProcess[] = L"notepad.exe";
  constexpr SIZE_T kCodeRegionBytes = 4096U;
  constexpr SIZE_T kDataRegionBytes = 4096U;

  std::wcout
      << L"====================================================\n"
      << L"[*] PE 02: CROSS-PROCESS MEMORY & HANDLE AUDIT\n"
      << L"====================================================\n";

  const DWORD pid = find_process_id_by_name(kTargetProcess);
  if (pid == 0) {
    ::MessageBoxW(
        nullptr,
        L"[-] Target process not found. Start notepad.exe before running this study.",
        L"Info",
        MB_OK | MB_ICONINFORMATION);
    return 1;
  }

  std::wcout << L"[+] Target process located (PID=" << pid << L").\n";

  const HANDLE h_process = ::OpenProcess(
      PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION,
      FALSE,
      pid);
  if (h_process == nullptr || h_process == INVALID_HANDLE_VALUE) {
    std::wcerr << L"[-] OpenProcess failed. Win32=" << ::GetLastError() << L"\n";
    return 1;
  }

  remote_region_info regions{};
  if (!prepare_remote_regions(h_process, kCodeRegionBytes, kDataRegionBytes, regions)) {
    std::wcerr << L"[-] VirtualAllocEx failed. Win32=" << ::GetLastError() << L"\n";
    ::CloseHandle(h_process);
    return 1;
  }

  DWORD old_protect = 0;
  if (::VirtualProtectEx(
          h_process,
          regions.code_addr,
          regions.code_size,
          PAGE_READONLY,
          &old_protect) == FALSE) {
    std::wcerr << L"[-] VirtualProtectEx failed. Win32=" << ::GetLastError() << L"\n";
    release_remote_regions(h_process, regions);
    ::CloseHandle(h_process);
    return 1;
  }

  std::wcout
      << L"[+] Remote regions allocated and locked (Read-Only)."
      << L" Code=0x" << std::hex << regions.code_addr
      << L", Data=0x" << regions.data_addr << std::dec << L"\n";

  ::MessageBoxW(
      nullptr,
      L"[+] PAUSE: Inspect target process memory map and open handles now.",
      L"Defensive Analysis",
      MB_OK | MB_ICONINFORMATION);

  release_remote_regions(h_process, regions);
  ::CloseHandle(h_process);

  std::wcout << L"[+] Remote virtual regions and handles released cleanly.\n";
  return 0;
}
