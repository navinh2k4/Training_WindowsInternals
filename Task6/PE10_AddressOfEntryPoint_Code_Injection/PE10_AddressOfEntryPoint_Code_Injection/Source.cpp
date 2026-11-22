
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

namespace {

std::wstring resolve_system_binary_path(const wchar_t* exe_name) {
  if (exe_name == nullptr || exe_name[0] == L'\0') {
    return L"";
  }

  const UINT needed = ::GetSystemDirectoryW(nullptr, 0);
  if (needed == 0) {
    return L"";
  }

  wchar_t* dir_buf = static_cast<wchar_t*>(
      ::HeapAlloc(
          ::GetProcessHeap(),
          HEAP_ZERO_MEMORY,
          static_cast<std::size_t>(needed) * sizeof(wchar_t)));
  if (dir_buf == nullptr) {
    return L"";
  }

  std::wstring full_path;
  const UINT written = ::GetSystemDirectoryW(dir_buf, needed);
  if (written > 0 && written < needed) {
    full_path.assign(dir_buf, static_cast<std::size_t>(written));
    full_path.push_back(L'\\');
    full_path.append(exe_name);
  }

  ::HeapFree(::GetProcessHeap(), 0, dir_buf);
  return full_path;
}

bool read_remote_entry_point(
    HANDLE h_process,
    HANDLE h_thread,
    std::uintptr_t& out_image_base,
    DWORD& out_entry_rva) noexcept {
  out_image_base = 0;
  out_entry_rva = 0;

  if (h_process == nullptr || h_thread == nullptr) {
    return false;
  }

  CONTEXT ctx{};
  ctx.ContextFlags = CONTEXT_INTEGER;
  if (::GetThreadContext(h_thread, &ctx) == FALSE) {
    return false;
  }

  // On x64 Windows, Rdx points to the PEB; offset +0x10 holds ImageBaseAddress.
  PVOID remote_base = nullptr;
  SIZE_T bytes_read = 0;
  const std::uintptr_t peb_base_slot = static_cast<std::uintptr_t>(ctx.Rdx) + 0x10ULL;
  if (::ReadProcessMemory(
          h_process,
          reinterpret_cast<LPCVOID>(peb_base_slot),
          &remote_base,
          sizeof(remote_base),
          &bytes_read) == FALSE ||
      remote_base == nullptr) {
    return false;
  }

  std::uint8_t header_buf[4096]{};
  if (::ReadProcessMemory(
          h_process,
          remote_base,
          header_buf,
          sizeof(header_buf),
          &bytes_read) == FALSE ||
      bytes_read < sizeof(IMAGE_DOS_HEADER)) {
    return false;
  }

  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(header_buf);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) {
    return false;
  }

  const std::size_t nt_off = static_cast<std::size_t>(dos->e_lfanew);
  if (nt_off + sizeof(IMAGE_NT_HEADERS64) > bytes_read) {
    return false;
  }

  const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(header_buf + nt_off);
  if (nt->Signature != IMAGE_NT_SIGNATURE ||
      nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    return false;
  }

  out_image_base = reinterpret_cast<std::uintptr_t>(remote_base);
  out_entry_rva = nt->OptionalHeader.AddressOfEntryPoint;
  return true;
}

}  // namespace

int wmain() {
  constexpr wchar_t kTargetExe[] = L"conhost.exe";

  std::wcout
      << L"====================================================\n"
      << L"[*] PE 10: ENTRYPOINT METADATA & THREAD AUDIT STUDY\n"
      << L"====================================================\n";

  const std::wstring target_path = resolve_system_binary_path(kTargetExe);
  if (target_path.empty()) {
    std::wcerr << L"[-] Failed to resolve target system executable path.\n";
    return 1;
  }

  std::wcout << L"[+] Resolved target path: " << target_path << L"\n";

  std::wstring cmd_line = L"\"" + target_path + L"\"";
  STARTUPINFOW si{};
  si.cb = static_cast<DWORD>(sizeof(STARTUPINFOW));
  PROCESS_INFORMATION pi{};

  if (::CreateProcessW(
          target_path.c_str(),
          cmd_line.data(),
          nullptr,
          nullptr,
          FALSE,
          CREATE_SUSPENDED,
          nullptr,
          nullptr,
          &si,
          &pi) == FALSE) {
    std::wcerr << L"[-] CreateProcessW(CREATE_SUSPENDED) failed. Win32="
               << ::GetLastError() << L"\n";
    return 1;
  }

  std::uintptr_t image_base = 0;
  DWORD entry_rva = 0;
  if (read_remote_entry_point(pi.hProcess, pi.hThread, image_base, entry_rva)) {
    std::wcout
        << L"[+] Suspended PID=" << pi.dwProcessId
        << L", ImageBase=0x" << std::hex << image_base
        << L", EntryPoint=0x" << (image_base + entry_rva)
        << std::dec << L"\n";
  } else {
    std::wcout << L"[-] Unable to inspect remote entry point metadata (PID="
               << pi.dwProcessId << L").\n";
  }

  ::TerminateProcess(pi.hProcess, 0);
  ::CloseHandle(pi.hThread);
  ::CloseHandle(pi.hProcess);
  return 0;
}
