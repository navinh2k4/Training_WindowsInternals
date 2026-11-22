
#include "PEFILE_CUSTOM_STRUCTS.h"
#include "PEParserEngine.hpp"
#include "winntdef.h"

#include <windows.h>
#include <objbase.h>
#include <shlguid.h>
#include <shobjidl.h>

#include <fcntl.h>
#include <io.h>

#include <cstdio>
#include <cwctype>
#include <string>

#pragma comment(lib, "ole32.lib")

namespace {

bool ends_with_lnk_ignore_case(const std::wstring& path) noexcept {
  if (path.size() < 4) {
    return false;
  }
  const std::size_t off = path.size() - 4;
  return ::_wcsnicmp(path.c_str() + off, L".lnk", 4) == 0;
}

std::wstring resolve_shortcut_if_lnk(const std::wstring& input_path) {
  if (!ends_with_lnk_ignore_case(input_path)) {
    return input_path;
  }

  const HRESULT init_hr = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  const bool should_uninit = SUCCEEDED(init_hr);

  std::wstring resolved_path = input_path;
  IShellLinkW* p_shell_link = nullptr;
  const HRESULT hr = ::CoCreateInstance(
      CLSID_ShellLink,
      nullptr,
      CLSCTX_INPROC_SERVER,
      IID_IShellLinkW,
      reinterpret_cast<void**>(&p_shell_link));

  if (SUCCEEDED(hr) && p_shell_link != nullptr) {
    IPersistFile* p_persist_file = nullptr;
    if (SUCCEEDED(p_shell_link->QueryInterface(
            IID_IPersistFile,
            reinterpret_cast<void**>(&p_persist_file))) &&
        p_persist_file != nullptr) {
      if (SUCCEEDED(p_persist_file->Load(input_path.c_str(), STGM_READ))) {
        p_shell_link->Resolve(nullptr, SLR_NO_UI | SLR_ANY_MATCH);
        wchar_t target_path[MAX_PATH]{};
        if (SUCCEEDED(p_shell_link->GetPath(target_path, MAX_PATH, nullptr, SLGP_RAWPATH)) &&
            target_path[0] != L'\0') {
          resolved_path.assign(target_path);
        }
      }
      p_persist_file->Release();
    }
    p_shell_link->Release();
  }

  if (should_uninit) {
    ::CoUninitialize();
  }

  return resolved_path;
}

bool wide_to_utf8_narrow(const std::wstring& wide, std::string& out_narrow) {
  out_narrow.clear();
  if (wide.empty()) {
    return false;
  }
  const int needed = ::WideCharToMultiByte(
      CP_UTF8,
      0,
      wide.c_str(),
      static_cast<int>(wide.size()),
      nullptr,
      0,
      nullptr,
      nullptr);
  if (needed <= 0) {
    return false;
  }
  out_narrow.resize(static_cast<std::size_t>(needed));
  ::WideCharToMultiByte(
      CP_UTF8,
      0,
      wide.c_str(),
      static_cast<int>(wide.size()),
      out_narrow.data(),
      needed,
      nullptr,
      nullptr);
  return true;
}

}  // namespace

int wmain(int argc, wchar_t* argv[]) {
  _setmode(_fileno(stderr), _O_U16TEXT);

  if (argc != 2 || argv == nullptr || argv[1] == nullptr || argv[1][0] == L'\0') {
    std::printf("Usage: pe_parser.exe <path to executable or .lnk shortcut>\n");
    return 1;
  }

  const std::wstring raw_wstr(argv[1]);
  const std::wstring target_wstr = resolve_shortcut_if_lnk(raw_wstr);

  std::string target_narrow;
  if (!wide_to_utf8_narrow(target_wstr, target_narrow)) {
    std::printf("Error: Unable to convert target path.\n");
    return 1;
  }

  FILE* pe_file = nullptr;
  if (::fopen_s(&pe_file, target_narrow.c_str(), "rb") != 0 || pe_file == nullptr) {
    std::printf("Can't open file: %s\n", target_narrow.c_str());
    return 1;
  }

  IMAGE_DOS_HEADER dos_hdr{};
  if (std::fseek(pe_file, 0, SEEK_SET) != 0 ||
      std::fread(&dos_hdr, sizeof(IMAGE_DOS_HEADER), 1, pe_file) != 1 ||
      dos_hdr.e_magic != IMAGE_DOS_SIGNATURE ||
      dos_hdr.e_lfanew <= 0) {
    std::printf("Error: Not a valid PE file format.\n");
    std::fclose(pe_file);
    return 1;
  }

  WORD magic_optional = 0;
  const long offset_magic = dos_hdr.e_lfanew +
      static_cast<long>(sizeof(DWORD)) +
      static_cast<long>(sizeof(IMAGE_FILE_HEADER));

  if (std::fseek(pe_file, offset_magic, SEEK_SET) != 0 ||
      std::fread(&magic_optional, sizeof(WORD), 1, pe_file) != 1) {
    std::printf("Error: Unable to read Optional Header magic.\n");
    std::fclose(pe_file);
    return 1;
  }

  if (magic_optional == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    std::printf(" Binary mode PE32 (32-bit) detected.\n");
    PEParserEngine<IMAGE_NT_HEADERS32, ilt_entry_32> engine32(target_narrow.c_str(), pe_file);
    if (engine32.is_valid()) {
      engine32.print_info();
    } else {
      std::printf("Error: Failed to parse PE32 structure.\n");
    }
  } else if (magic_optional == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    std::printf(" Binary mode PE32+ (64-bit) detected.\n");
    PEParserEngine<IMAGE_NT_HEADERS64, ilt_entry_64> engine64(target_narrow.c_str(), pe_file);
    if (engine64.is_valid()) {
      engine64.print_info();
    } else {
      std::printf("Error: Failed to parse PE32+ structure.\n");
    }
  } else {
    std::printf("Error: Unknown Optional Header Magic structure (0x%X).\n", magic_optional);
  }

  std::fclose(pe_file);
  return 0;
}
