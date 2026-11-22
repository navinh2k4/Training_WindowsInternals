
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>

namespace {

bool inspect_ntdll_text_section(
    DWORD& out_rva,
    DWORD& out_raw_offset,
    DWORD& out_size) noexcept {
  out_rva = 0;
  out_raw_offset = 0;
  out_size = 0;

  constexpr wchar_t kNtdllPath[] = L"C:\\Windows\\System32\\ntdll.dll";
  const HMODULE h_ntdll = ::GetModuleHandleW(L"ntdll.dll");
  if (h_ntdll == nullptr) {
    return false;
  }

  const HANDLE h_file = ::CreateFileW(
      kNtdllPath,
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
      file_sz.QuadPart <= static_cast<LONGLONG>(sizeof(IMAGE_DOS_HEADER)) ||
      file_sz.QuadPart > static_cast<LONGLONG>(64ULL * 1024ULL * 1024ULL)) {
    ::CloseHandle(h_file);
    return false;
  }

  const HANDLE h_map = ::CreateFileMappingW(
      h_file,
      nullptr,
      PAGE_READONLY,
      0,
      0,
      nullptr);
  if (h_map == nullptr) {
    ::CloseHandle(h_file);
    return false;
  }

  const LPVOID view_ptr = ::MapViewOfFile(h_map, FILE_MAP_READ, 0, 0, 0);
  if (view_ptr == nullptr) {
    ::CloseHandle(h_map);
    ::CloseHandle(h_file);
    return false;
  }

  const std::size_t mapped_bytes = static_cast<std::size_t>(file_sz.QuadPart);
  const auto* base_bytes = static_cast<const std::uint8_t*>(view_ptr);
  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base_bytes);

  bool found_text = false;
  if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew > 0) {
    const std::size_t nt_off = static_cast<std::size_t>(dos->e_lfanew);
    if (nt_off + sizeof(IMAGE_NT_HEADERS64) <= mapped_bytes) {
      const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base_bytes + nt_off);
      if (nt->Signature == IMAGE_NT_SIGNATURE &&
          nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const WORD sec_count = nt->FileHeader.NumberOfSections;
        const auto* sec_table = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            reinterpret_cast<const std::uint8_t*>(&nt->OptionalHeader) +
            nt->FileHeader.SizeOfOptionalHeader);
        const std::size_t table_off =
            reinterpret_cast<const std::uint8_t*>(sec_table) - base_bytes;

        if (table_off + static_cast<std::size_t>(sec_count) * sizeof(IMAGE_SECTION_HEADER) <= mapped_bytes) {
          for (WORD i = 0; i < sec_count; ++i) {
            const IMAGE_SECTION_HEADER& sec = sec_table[i];
            if (std::strncmp(reinterpret_cast<const char*>(sec.Name), ".text", 5) == 0 &&
                sec.Name[5] == '\0') {
              out_rva = sec.VirtualAddress;
              out_raw_offset = sec.PointerToRawData;
              out_size = sec.Misc.VirtualSize;
              found_text = true;
              break;
            }
          }
        }
      }
    }
  }

  ::UnmapViewOfFile(view_ptr);
  ::CloseHandle(h_map);
  ::CloseHandle(h_file);
  return found_text;
}

}  // namespace

int wmain() {
  std::wcout
      << L"====================================================\n"
      << L"[*] PE 07: NTDLL IMAGE & SECTION INTEGRITY STUDY\n"
      << L"====================================================\n";

  const HMODULE h_ntdll = ::GetModuleHandleW(L"ntdll.dll");
  if (h_ntdll == nullptr) {
    std::wcerr << L"[-] GetModuleHandleW(ntdll.dll) failed. Win32=" << ::GetLastError() << L"\n";
    return 1;
  }

  DWORD text_rva = 0;
  DWORD text_raw = 0;
  DWORD text_size = 0;
  if (!inspect_ntdll_text_section(text_rva, text_raw, text_size)) {
    std::wcerr << L"[-] Failed to inspect ntdll.dll .text section.\n";
    return 1;
  }

  const auto* mapped_text_ptr = reinterpret_cast<const std::uint8_t*>(
      reinterpret_cast<std::uintptr_t>(h_ntdll) + text_rva);

  std::wcout
      << L"[+] ntdll.dll base=0x" << std::hex << reinterpret_cast<std::uintptr_t>(h_ntdll)
      << L", .text RVA=0x" << text_rva
      << L", Raw=0x" << text_raw
      << L", VirtualSize=0x" << text_size
      << L", Mapped .text=0x" << reinterpret_cast<std::uintptr_t>(mapped_text_ptr)
      << std::dec << L"\n";

  return 0;
}
