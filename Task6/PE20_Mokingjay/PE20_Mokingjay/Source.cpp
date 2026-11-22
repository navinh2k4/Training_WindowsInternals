
#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")

namespace {

struct section_characteristics_audit final {
  std::uintptr_t module_base = 0;
  DWORD module_size = 0;
  DWORD target_rva = 0;
  DWORD target_size = 0;
  DWORD characteristics = 0;
  bool has_rwx_section = false;
  bool found_section = false;
};

section_characteristics_audit audit_loaded_module_sections(
    const wchar_t* module_name) noexcept {
  section_characteristics_audit audit{};
  if (module_name == nullptr || module_name[0] == L'\0') {
    return audit;
  }

  const HMODULE h_mod = ::LoadLibraryExW(
      module_name,
      nullptr,
      LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (h_mod == nullptr) {
    return audit;
  }

  MODULEINFO mod_info{};
  if (::GetModuleInformation(
          ::GetCurrentProcess(),
          h_mod,
          &mod_info,
          static_cast<DWORD>(sizeof(mod_info))) != FALSE) {
    audit.module_base = reinterpret_cast<std::uintptr_t>(mod_info.lpBaseOfDll);
    audit.module_size = mod_info.SizeOfImage;
  }

  IMAGE_NT_HEADERS* nt_hdr = ::ImageNtHeader(h_mod);
  if (nt_hdr != nullptr) {
    const IMAGE_SECTION_HEADER* sec_table = IMAGE_FIRST_SECTION(nt_hdr);
    const WORD sec_count = nt_hdr->FileHeader.NumberOfSections;

    for (WORD i = 0; i < sec_count; ++i) {
      const IMAGE_SECTION_HEADER& sec = sec_table[i];
      const bool exec_flag = (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
      const bool write_flag = (sec.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
      const bool read_flag = (sec.Characteristics & IMAGE_SCN_MEM_READ) != 0;

      if (exec_flag && write_flag && read_flag) {
        audit.has_rwx_section = true;
        audit.found_section = true;
        audit.target_rva = sec.VirtualAddress;
        audit.target_size = sec.Misc.VirtualSize;
        audit.characteristics = sec.Characteristics;
        break;
      }
    }

    if (!audit.found_section) {
      for (WORD i = 0; i < sec_count; ++i) {
        const IMAGE_SECTION_HEADER& sec = sec_table[i];
        if (std::strncmp(reinterpret_cast<const char*>(sec.Name), ".data", 5) == 0 &&
            sec.Name[5] == '\0') {
          audit.found_section = true;
          audit.target_rva = sec.VirtualAddress;
          audit.target_size = sec.Misc.VirtualSize;
          audit.characteristics = sec.Characteristics;
          break;
        }
      }
    }
  }

  ::FreeLibrary(h_mod);
  return audit;
}

}  // namespace

int wmain() {
  constexpr wchar_t kSystemDll[] = L"version.dll";

  std::wcout
      << L"====================================================\n"
      << L"[*] PE 20: IMAGE SECTION & RWX ATTRIBUTE AUDIT STUDY\n"
      << L"====================================================\n";

  const section_characteristics_audit audit = audit_loaded_module_sections(kSystemDll);
  if (audit.module_base == 0) {
    std::wcerr << L"[-] Failed to load or query system module: " << kSystemDll << L"\n";
    return 1;
  }

  std::wcout
      << L"[+] Module: " << kSystemDll
      << L" | Base=0x" << std::hex << audit.module_base
      << L" | ImageSize=0x" << audit.module_size
      << L" | NativeRWX=" << (audit.has_rwx_section ? L"Yes" : L"No") << L"\n";

  if (audit.found_section) {
    std::wcout
        << L"[+] Inspected Section VA=0x" << (audit.module_base + audit.target_rva)
        << L" (RVA=0x" << audit.target_rva
        << L", VirtualSize=0x" << audit.target_size
        << L", Characteristics=0x" << audit.characteristics << L")\n";
  }

  std::wcout << std::dec;
  return 0;
}
