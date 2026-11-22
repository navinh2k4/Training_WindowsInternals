
#include "data.h"

#include <windows.h>
#include <tlhelp32.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <iostream>
#include <string>

namespace {

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

DWORD rva_to_file_offset(
    const IMAGE_NT_HEADERS64* nt_headers,
    DWORD rva,
    std::size_t buffer_size) noexcept {
  if (nt_headers == nullptr || buffer_size < sizeof(IMAGE_NT_HEADERS64)) {
    return 0;
  }

  const WORD section_count = nt_headers->FileHeader.NumberOfSections;
  const auto* first_section = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
      reinterpret_cast<const std::uint8_t*>(&nt_headers->OptionalHeader) +
      nt_headers->FileHeader.SizeOfOptionalHeader);

  for (WORD i = 0; i < section_count; ++i) {
    const IMAGE_SECTION_HEADER& sec = first_section[i];
    const DWORD sec_span = (sec.Misc.VirtualSize > sec.SizeOfRawData)
        ? sec.Misc.VirtualSize
        : sec.SizeOfRawData;
    if (rva >= sec.VirtualAddress && rva < (sec.VirtualAddress + sec_span)) {
      const DWORD raw_offset = (rva - sec.VirtualAddress) + sec.PointerToRawData;
      if (static_cast<std::size_t>(raw_offset) < buffer_size) {
        return raw_offset;
      }
    }
  }
  return 0;
}

bool inspect_pe64_layout(
    const std::uint8_t* raw_bytes,
    std::size_t raw_size,
    DWORD& out_image_size,
    ULONGLONG& out_preferred_base,
    DWORD& out_export_rva,
    WORD& out_sections) noexcept {
  out_image_size = 0;
  out_preferred_base = 0;
  out_export_rva = 0;
  out_sections = 0;

  if (raw_bytes == nullptr || raw_size < sizeof(IMAGE_DOS_HEADER)) {
    return false;
  }

  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw_bytes);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) {
    return false;
  }

  const std::size_t nt_offset = static_cast<std::size_t>(dos->e_lfanew);
  if (nt_offset + sizeof(IMAGE_NT_HEADERS64) > raw_size) {
    return false;
  }

  const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(raw_bytes + nt_offset);
  if (nt->Signature != IMAGE_NT_SIGNATURE ||
      nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    return false;
  }

  out_image_size = nt->OptionalHeader.SizeOfImage;
  out_preferred_base = nt->OptionalHeader.ImageBase;
  out_sections = nt->FileHeader.NumberOfSections;

  const DWORD exp_rva =
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  const DWORD exp_size =
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

  if (exp_rva != 0 && exp_size >= sizeof(IMAGE_EXPORT_DIRECTORY)) {
    const DWORD exp_raw = rva_to_file_offset(nt, exp_rva, raw_size);
    if (exp_raw != 0 &&
        static_cast<std::size_t>(exp_raw) + sizeof(IMAGE_EXPORT_DIRECTORY) <= raw_size) {
      const auto* exp_dir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(raw_bytes + exp_raw);
      const DWORD names_raw = rva_to_file_offset(nt, exp_dir->AddressOfNames, raw_size);
      const DWORD funcs_raw = rva_to_file_offset(nt, exp_dir->AddressOfFunctions, raw_size);
      const DWORD ords_raw = rva_to_file_offset(nt, exp_dir->AddressOfNameOrdinals, raw_size);

      if (names_raw != 0 && funcs_raw != 0 && ords_raw != 0) {
        const auto* names_rva = reinterpret_cast<const DWORD*>(raw_bytes + names_raw);
        const auto* funcs_rva = reinterpret_cast<const DWORD*>(raw_bytes + funcs_raw);
        const auto* name_ords = reinterpret_cast<const WORD*>(raw_bytes + ords_raw);

        for (DWORD i = 0; i < exp_dir->NumberOfNames; ++i) {
          const DWORD fn_raw = rva_to_file_offset(nt, names_rva[i], raw_size);
          if (fn_raw != 0) {
            const char* fn_name = reinterpret_cast<const char*>(raw_bytes + fn_raw);
            if (std::strcmp(fn_name, "Go") == 0) {
              const WORD ord_idx = name_ords[i];
              if (ord_idx < exp_dir->NumberOfFunctions) {
                out_export_rva = funcs_rva[ord_idx];
              }
              break;
            }
          }
        }
      }
    }
  }

  return true;
}

bool read_file_bytes_heap(
    const wchar_t* file_path,
    std::uint8_t*& out_buf,
    std::size_t& out_size) noexcept {
  out_buf = nullptr;
  out_size = 0;

  if (file_path == nullptr || file_path[0] == L'\0') {
    return false;
  }

  const HANDLE h_file = ::CreateFileW(
      file_path,
      GENERIC_READ,
      FILE_SHARE_READ,
      nullptr,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      nullptr);
  if (h_file == INVALID_HANDLE_VALUE || h_file == nullptr) {
    return false;
  }

  LARGE_INTEGER file_sz{};
  if (::GetFileSizeEx(h_file, &file_sz) == FALSE ||
      file_sz.QuadPart <= 0 ||
      file_sz.QuadPart > static_cast<LONGLONG>(64ULL * 1024ULL * 1024ULL)) {
    ::CloseHandle(h_file);
    return false;
  }

  const std::size_t byte_len = static_cast<std::size_t>(file_sz.QuadPart);
  std::uint8_t* buf = static_cast<std::uint8_t*>(
      ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, byte_len));
  if (buf == nullptr) {
    ::CloseHandle(h_file);
    return false;
  }

  std::size_t total_read = 0;
  while (total_read < byte_len) {
    const DWORD chunk = static_cast<DWORD>(
        (byte_len - total_read) > 65536ULL ? 65536ULL : (byte_len - total_read));
    DWORD bytes_read = 0;
    if (::ReadFile(h_file, buf + total_read, chunk, &bytes_read, nullptr) == FALSE ||
        bytes_read == 0) {
      ::HeapFree(::GetProcessHeap(), 0, buf);
      ::CloseHandle(h_file);
      return false;
    }
    total_read += static_cast<std::size_t>(bytes_read);
  }

  ::CloseHandle(h_file);
  out_buf = buf;
  out_size = total_read;
  return true;
}

}  // namespace

int wmain() {
  constexpr wchar_t kCandidateDll[] = L"SampleModule.dll";
  constexpr wchar_t kTargetProcess[] = L"notepad.exe";

  std::wcout
      << L"====================================================\n"
      << L"[*] PE 06: PE64 STRUCTURE & REMOTE AUDIT STUDY\n"
      << L"====================================================\n";

  std::uint8_t* pe_buf = nullptr;
  std::size_t pe_size = 0;
  if (!read_file_bytes_heap(kCandidateDll, pe_buf, pe_size)) {
    std::wcout << L"[-] Optional PE sample '" << kCandidateDll
               << L"' not found or unreadable; skipping static PE header inspection.\n";
  } else {
    DWORD image_size = 0;
    ULONGLONG preferred_base = 0;
    DWORD export_rva = 0;
    WORD section_count = 0;

    if (inspect_pe64_layout(
            pe_buf,
            pe_size,
            image_size,
            preferred_base,
            export_rva,
            section_count)) {
      std::wcout << L"[+] Parsed PE64 header: SizeOfImage=" << image_size
                 << L" bytes, Sections=" << section_count
                 << L", PreferredBase=0x" << std::hex << preferred_base
                 << L", ExportRVA=0x" << export_rva << std::dec << L"\n";
    } else {
      std::wcout << L"[-] File is not a valid PE32+ (64-bit) image.\n";
    }

    ::HeapFree(::GetProcessHeap(), 0, pe_buf);
    pe_buf = nullptr;
  }

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

  std::wcout << L"[+] Opened target process handle (PID=" << pid
             << L") with limited query rights.\n";
  ::CloseHandle(h_process);
  return 0;
}
