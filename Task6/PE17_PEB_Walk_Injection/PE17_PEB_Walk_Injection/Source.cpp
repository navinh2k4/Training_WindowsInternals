
#include <windows.h>
#include <tlhelp32.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <iostream>

namespace {

struct peb_ldr_data_raw final {
  ULONG length;
  BOOLEAN initialized;
  HANDLE ss_handle;
  LIST_ENTRY in_load_order_module_list;
  LIST_ENTRY in_memory_order_module_list;
  LIST_ENTRY in_initialization_order_module_list;
};

struct unicode_string_raw final {
  USHORT length;
  USHORT maximum_length;
  PWSTR buffer;
};

struct ldr_data_table_entry_raw final {
  LIST_ENTRY in_load_order_links;
  LIST_ENTRY in_memory_order_links;
  LIST_ENTRY in_initialization_order_links;
  PVOID dll_base;
  PVOID entry_point;
  ULONG size_of_image;
  unicode_string_raw full_dll_name;
  unicode_string_raw base_dll_name;
};

struct peb_raw final {
  BOOLEAN inherited_address_space;
  BOOLEAN read_image_file_exec_options;
  BOOLEAN being_debugged;
  BOOLEAN spare_bool;
  HANDLE mutant;
  PVOID image_base_address;
  peb_ldr_data_raw* ldr;
};

struct module_lookup_result final {
  HMODULE base_handle = nullptr;
  ULONG image_size = 0;
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

module_lookup_result walk_peb_modules_x64(const wchar_t* target_module_name) noexcept {
  module_lookup_result result{};
  if (target_module_name == nullptr || target_module_name[0] == L'\0') {
    return result;
  }

#if defined(_M_X64) || defined(__x86_64__)
  const auto* peb = reinterpret_cast<const peb_raw*>(::__readgsqword(0x60U));
  if (peb == nullptr || peb->ldr == nullptr) {
    return result;
  }

  const LIST_ENTRY* list_head = &peb->ldr->in_load_order_module_list;
  const LIST_ENTRY* current = list_head->Flink;
  int guard = 0;

  while (current != nullptr && current != list_head && guard < 1024) {
    const auto* entry = CONTAINING_RECORD(
        current,
        ldr_data_table_entry_raw,
        in_load_order_links);

    if (entry != nullptr && entry->base_dll_name.buffer != nullptr &&
        entry->base_dll_name.length > 0) {
      const std::size_t wchar_len =
          static_cast<std::size_t>(entry->base_dll_name.length) / sizeof(wchar_t);
      if (wchar_len > 0 && wchar_len < 260U) {
        wchar_t candidate[260]{};
        std::wcsncpy(candidate, entry->base_dll_name.buffer, wchar_len);
        candidate[wchar_len] = L'\0';
        if (::_wcsicmp(candidate, target_module_name) == 0) {
          result.base_handle = static_cast<HMODULE>(entry->dll_base);
          result.image_size = entry->size_of_image;
          result.found = (result.base_handle != nullptr);
          break;
        }
      }
    }

    current = current->Flink;
    ++guard;
  }
#endif

  return result;
}

std::uintptr_t resolve_export_rva64(HMODULE h_module, const char* export_name) noexcept {
  if (h_module == nullptr || export_name == nullptr || export_name[0] == '\0') {
    return 0;
  }

  const auto* base = reinterpret_cast<const std::uint8_t*>(h_module);
  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) {
    return 0;
  }

  const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
      base + static_cast<std::size_t>(dos->e_lfanew));
  if (nt->Signature != IMAGE_NT_SIGNATURE ||
      nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    return 0;
  }

  const DWORD exp_rva =
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  const DWORD exp_size =
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
  if (exp_rva == 0 || exp_size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
    return 0;
  }

  const auto* exp_dir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + exp_rva);
  const auto* func_rvas = reinterpret_cast<const DWORD*>(base + exp_dir->AddressOfFunctions);
  const auto* name_rvas = reinterpret_cast<const DWORD*>(base + exp_dir->AddressOfNames);
  const auto* name_ordinals =
      reinterpret_cast<const WORD*>(base + exp_dir->AddressOfNameOrdinals);

  for (DWORD i = 0; i < exp_dir->NumberOfNames; ++i) {
    const char* fn_name = reinterpret_cast<const char*>(base + name_rvas[i]);
    if (fn_name != nullptr && std::strcmp(fn_name, export_name) == 0) {
      const WORD ord_idx = name_ordinals[i];
      if (ord_idx < exp_dir->NumberOfFunctions) {
        return reinterpret_cast<std::uintptr_t>(base + func_rvas[ord_idx]);
      }
      break;
    }
  }

  return 0;
}

}  // namespace

int wmain() {
  constexpr wchar_t kTargetProcess[] = L"notepad.exe";
  constexpr wchar_t kModuleName[] = L"kernel32.dll";
  constexpr char kExportSymbol[] = "GetCurrentProcessId";

  std::wcout
      << L"====================================================\n"
      << L"[*] PE 17: PEB LOADER WALK & EXPORT AUDIT STUDY\n"
      << L"====================================================\n";

  const DWORD target_pid = find_process_id_by_name(kTargetProcess);
  if (target_pid == 0) {
    std::wcout << L"[*] Target process not running: " << kTargetProcess << L"\n";
  } else {
    std::wcout << L"[+] Observed target process '" << kTargetProcess
               << L"' (PID=" << target_pid << L").\n";
  }

  const module_lookup_result mod = walk_peb_modules_x64(kModuleName);
  if (!mod.found) {
    std::wcerr << L"[-] Failed to locate module via PEB walk: " << kModuleName << L"\n";
    return 1;
  }

  const std::uintptr_t symbol_va = resolve_export_rva64(mod.base_handle, kExportSymbol);
  std::wcout
      << L"[+] PEB module '" << kModuleName
      << L"': Base=0x" << std::hex << reinterpret_cast<std::uintptr_t>(mod.base_handle)
      << L", Size=0x" << mod.image_size
      << L", SymbolVA=0x" << symbol_va
      << std::dec << L"\n";

  return 0;
}
