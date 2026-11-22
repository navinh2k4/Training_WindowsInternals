
#pragma once

#include "PEFILE_CUSTOM_STRUCTS.h"
#include "winntdef.h"

#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

template <typename NtHeadersType, typename IltEntryType>
class PEParserEngine final {
 public:
  PEParserEngine(const char* file_name, FILE* pe_file) noexcept
      : file_name_(file_name),
        pe_file_(pe_file),
        import_directory_count_(0),
        basereloc_directory_count_(0),
        dos_header_{},
        nt_headers_{},
        rich_header_info_{},
        rich_header_{},
        section_headers_(nullptr),
        import_table_(nullptr),
        basereloc_table_(nullptr),
        parse_ok_(false) {
    parse_file();
  }

  ~PEParserEngine() noexcept {
    release_resources();
  }

  PEParserEngine(const PEParserEngine&) = delete;
  PEParserEngine& operator=(const PEParserEngine&) = delete;

  bool is_valid() const noexcept {
    return parse_ok_;
  }

  void print_info() const noexcept {
    const char* display_name = (file_name_ != nullptr && file_name_[0] != '\0')
        ? file_name_
        : "<unknown>";

    std::printf(" FILE: %s\n", display_name);
    if constexpr (sizeof(NtHeadersType) == sizeof(IMAGE_NT_HEADERS64)) {
      std::printf(
          " TYPE: 0x%X (PE32+ / 64-bit)\n",
          nt_headers_.OptionalHeader.Magic);
    } else {
      std::printf(
          " TYPE: 0x%X (PE32 / 32-bit)\n",
          nt_headers_.OptionalHeader.Magic);
    }
    std::printf(" ----------------------------------\n");

    std::printf(" DOS HEADER:\n -----------\n\n");
    std::printf("  Magic: 0x%X\n", dos_header_.e_magic);
    std::printf("  File address of new exe header: 0x%lX\n", dos_header_.e_lfanew);
    std::printf(" ----------------------------------\n");

    if (rich_header_info_.entries > 0 && rich_header_.entries != nullptr) {
      std::printf(" RICH HEADER:\n ------------\n\n");
      for (int i = 0; i < rich_header_info_.entries; ++i) {
        const rich_header_entry& item = rich_header_.entries[i];
        std::printf(
            "  0x%X 0x%X 0x%lX: %u.%u.%lu\n",
            item.build_id,
            item.prod_id,
            item.use_count,
            static_cast<unsigned int>(item.build_id),
            static_cast<unsigned int>(item.prod_id),
            item.use_count);
      }
      std::printf(" ----------------------------------\n");
    }

    std::printf(" NT HEADERS:\n -----------\n\n");
    std::printf("  PE Signature: 0x%lX\n", nt_headers_.Signature);
    std::printf("\n  File Header:\n\n");
    std::printf("    Machine: 0x%X\n", nt_headers_.FileHeader.Machine);
    std::printf("    Number of sections: 0x%X\n", nt_headers_.FileHeader.NumberOfSections);
    std::printf("    Size of optional header: 0x%X\n", nt_headers_.FileHeader.SizeOfOptionalHeader);

    std::printf("\n  Optional Header:\n\n");
    std::printf("    Magic: 0x%X\n", nt_headers_.OptionalHeader.Magic);
    std::printf("    Size of code section: 0x%lX\n", nt_headers_.OptionalHeader.SizeOfCode);
    std::printf("    Size of initialized data: 0x%lX\n", nt_headers_.OptionalHeader.SizeOfInitializedData);
    std::printf("    Size of uninitialized data: 0x%lX\n", nt_headers_.OptionalHeader.SizeOfUninitializedData);
    std::printf("    Address of entry point: 0x%lX\n", nt_headers_.OptionalHeader.AddressOfEntryPoint);
    std::printf("    RVA of start of code section: 0x%lX\n", nt_headers_.OptionalHeader.BaseOfCode);

    if constexpr (sizeof(NtHeadersType) == sizeof(IMAGE_NT_HEADERS32)) {
      std::printf("    Base of Data: 0x%lX\n", nt_headers_.OptionalHeader.BaseOfData);
      std::printf("    Desired image base: 0x%lX\n", nt_headers_.OptionalHeader.ImageBase);
    } else {
      std::printf(
          "    Desired image base: 0x%llX\n",
          static_cast<unsigned long long>(nt_headers_.OptionalHeader.ImageBase));
    }

    std::printf("    Section alignment: 0x%lX\n", nt_headers_.OptionalHeader.SectionAlignment);
    std::printf("    File alignment: 0x%lX\n", nt_headers_.OptionalHeader.FileAlignment);
    std::printf("    Size of image: 0x%lX\n", nt_headers_.OptionalHeader.SizeOfImage);
    std::printf("    Size of headers: 0x%lX\n", nt_headers_.OptionalHeader.SizeOfHeaders);

    std::printf("\n  Data Directories:\n");
    std::printf(
        "    * Import Directory: RVA: 0x%lX | Size: 0x%lX\n",
        nt_headers_.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
        nt_headers_.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
    std::printf(
        "    * Base Relocation Table: RVA: 0x%lX | Size: 0x%lX\n",
        nt_headers_.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,
        nt_headers_.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
    std::printf(" ----------------------------------\n");

    std::printf(" SECTION HEADERS:\n ----------------\n\n");
    if (section_headers_ != nullptr) {
      for (int i = 0; i < static_cast<int>(nt_headers_.FileHeader.NumberOfSections); ++i) {
        const IMAGE_SECTION_HEADER& sec = section_headers_[i];
        std::printf("    * %.8s:\n", sec.Name);
        std::printf("         VirtualAddress: 0x%lX\n", sec.VirtualAddress);
        std::printf("         VirtualSize: 0x%lX\n", sec.Misc.VirtualSize);
        std::printf("         PointerToRawData: 0x%lX\n", sec.PointerToRawData);
        std::printf("         SizeOfRawData: 0x%lX\n", sec.SizeOfRawData);
        std::printf("         Characteristics: 0x%lX\n\n", sec.Characteristics);
      }
    }
    std::printf(" ----------------------------------\n");

    if (pe_file_ != nullptr && import_directory_count_ > 0 && import_table_ != nullptr) {
      std::printf(" IMPORT TABLE:\n ----------------\n\n");
      for (int i = 0; i < import_directory_count_; ++i) {
        const IMAGE_IMPORT_DESCRIPTOR& imp = import_table_[i];
        const int name_loc = locate_section(imp.Name);
        const DWORD name_addr = resolve_rva_to_raw(imp.Name, name_loc);
        char* dll_name = read_c_string_at_raw(name_addr);

        std::printf("   * %s:\n", (dll_name != nullptr) ? dll_name : "<unknown>");
        if (dll_name != nullptr) {
          ::HeapFree(::GetProcessHeap(), 0, dll_name);
        }

        std::printf("       ILT RVA: 0x%lX\n", imp.OriginalFirstThunk);
        std::printf("       IAT RVA: 0x%lX\n\n", imp.FirstThunk);

        const DWORD thunk_rva = (imp.OriginalFirstThunk != 0)
            ? imp.OriginalFirstThunk
            : imp.FirstThunk;
        const int ilt_loc = locate_section(thunk_rva);
        const DWORD ilt_addr = resolve_rva_to_raw(thunk_rva, ilt_loc);

        if (ilt_addr != 0) {
          int entry_counter = 0;
          while (entry_counter < 65536) {
            IltEntryType entry{};
            const long entry_offset = static_cast<long>(
                ilt_addr + static_cast<DWORD>(entry_counter) * static_cast<DWORD>(sizeof(entry)));
            if (std::fseek(pe_file_, entry_offset, SEEK_SET) != 0) {
              break;
            }
            if (std::fread(&entry, sizeof(entry), 1, pe_file_) != 1) {
              break;
            }
            if (entry == 0) {
              break;
            }

            bool is_ordinal = false;
            DWORD hint_rva = 0;
            WORD ordinal = 0;

            if constexpr (sizeof(IltEntryType) == sizeof(ilt_entry_32)) {
              if ((static_cast<std::uint32_t>(entry) & kBearOrdinalFlag32) != 0U) {
                is_ordinal = true;
                ordinal = static_cast<WORD>(static_cast<std::uint32_t>(entry) & kBearOrdinalMask);
              } else {
                hint_rva = static_cast<DWORD>(entry);
              }
            } else {
              if ((static_cast<std::uint64_t>(entry) & kBearOrdinalFlag64) != 0ULL) {
                is_ordinal = true;
                ordinal = static_cast<WORD>(static_cast<std::uint64_t>(entry) & kBearOrdinalMask);
              } else {
                hint_rva = static_cast<DWORD>(static_cast<std::uint64_t>(entry) & 0xFFFFFFFFULL);
              }
            }

            std::printf("\n       Entry:\n");
            if (!is_ordinal) {
              const int hint_loc = locate_section(hint_rva);
              const DWORD hint_addr = resolve_rva_to_raw(hint_rva, hint_loc);

              WORD function_hint = 0;
              if (hint_addr != 0 &&
                  std::fseek(pe_file_, static_cast<long>(hint_addr), SEEK_SET) == 0 &&
                  std::fread(&function_hint, sizeof(WORD), 1, pe_file_) == 1) {
                char* func_name = read_c_string_at_raw(hint_addr + static_cast<DWORD>(sizeof(WORD)));
                std::printf("         Name: %s\n", (func_name != nullptr) ? func_name : "<invalid>");
                std::printf("         Hint RVA: 0x%lX\n", hint_rva);
                std::printf("         Hint: 0x%X\n", function_hint);
                if (func_name != nullptr) {
                  ::HeapFree(::GetProcessHeap(), 0, func_name);
                }
              }
            } else {
              std::printf("         Ordinal: 0x%X\n", ordinal);
            }

            ++entry_counter;
          }
        }
        std::printf("\n   ----------------------\n\n");
      }
      std::printf(" ----------------------------------\n");
    }

    if (pe_file_ != nullptr && basereloc_directory_count_ > 0 && basereloc_table_ != nullptr) {
      std::printf(" BASE RELOCATIONS TABLE:\n -----------------------\n");
      const DWORD reloc_rva =
          nt_headers_.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
      const int reloc_loc = locate_section(reloc_rva);
      const DWORD base_reloc_addr = resolve_rva_to_raw(reloc_rva, reloc_loc);

      DWORD block_offset = 0;
      for (int i = 0; i < basereloc_directory_count_; ++i) {
        const IMAGE_BASE_RELOCATION& blk = basereloc_table_[i];
        if (blk.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) {
          break;
        }
        const int entries = static_cast<int>(
            (blk.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD));

        std::printf("\n   Block 0x%X: \n", i);
        std::printf("     Page RVA: 0x%lX\n", blk.VirtualAddress);
        std::printf("     Block size: 0x%lX\n", blk.SizeOfBlock);
        std::printf("     Number of entries: 0x%X\n\n     Entries:\n", entries);

        for (int j = 0; j < entries; ++j) {
          WORD raw_word = 0;
          const long entry_pos = static_cast<long>(
              base_reloc_addr + block_offset +
              static_cast<DWORD>(sizeof(IMAGE_BASE_RELOCATION)) +
              static_cast<DWORD>(j) * static_cast<DWORD>(sizeof(WORD)));
          if (std::fseek(pe_file_, entry_pos, SEEK_SET) != 0 ||
              std::fread(&raw_word, sizeof(WORD), 1, pe_file_) != 1) {
            break;
          }

          base_reloc_entry entry{};
          std::memcpy(&entry, &raw_word, sizeof(WORD));

          std::printf("\n       * Value: 0x%X\n", raw_word);
          std::printf("         Relocation Type: 0x%X\n", static_cast<unsigned int>(entry.type));
          std::printf("         Offset: 0x%X\n", static_cast<unsigned int>(entry.offset));
        }

        std::printf("\n   ----------------------\n\n");
        block_offset += blk.SizeOfBlock;
      }
      std::printf(" ----------------------------------\n");
    }
  }

 private:
  const char* file_name_;
  FILE* pe_file_;
  int import_directory_count_;
  int basereloc_directory_count_;

  IMAGE_DOS_HEADER dos_header_;
  NtHeadersType nt_headers_;
  rich_header_info rich_header_info_;
  rich_header rich_header_;
  PIMAGE_SECTION_HEADER section_headers_;
  PIMAGE_IMPORT_DESCRIPTOR import_table_;
  PIMAGE_BASE_RELOCATION basereloc_table_;
  bool parse_ok_;

  void release_resources() noexcept {
    if (section_headers_ != nullptr) {
      ::HeapFree(::GetProcessHeap(), 0, section_headers_);
      section_headers_ = nullptr;
    }
    if (import_table_ != nullptr) {
      ::HeapFree(::GetProcessHeap(), 0, import_table_);
      import_table_ = nullptr;
    }
    if (basereloc_table_ != nullptr) {
      ::HeapFree(::GetProcessHeap(), 0, basereloc_table_);
      basereloc_table_ = nullptr;
    }
    if (rich_header_.entries != nullptr) {
      ::HeapFree(::GetProcessHeap(), 0, rich_header_.entries);
      rich_header_.entries = nullptr;
    }
    if (rich_header_info_.ptr_to_buffer != nullptr) {
      ::HeapFree(::GetProcessHeap(), 0, rich_header_info_.ptr_to_buffer);
      rich_header_info_.ptr_to_buffer = nullptr;
    }
  }

  int locate_section(DWORD rva) const noexcept {
    if (section_headers_ == nullptr) {
      return -1;
    }
    const int count = static_cast<int>(nt_headers_.FileHeader.NumberOfSections);
    for (int i = 0; i < count; ++i) {
      const DWORD start_rva = section_headers_[i].VirtualAddress;
      const DWORD span = (section_headers_[i].Misc.VirtualSize > section_headers_[i].SizeOfRawData)
          ? section_headers_[i].Misc.VirtualSize
          : section_headers_[i].SizeOfRawData;
      if (rva >= start_rva && rva < (start_rva + span)) {
        return i;
      }
    }
    return -1;
  }

  DWORD resolve_rva_to_raw(DWORD rva, int section_index) const noexcept {
    if (section_index < 0 || section_headers_ == nullptr) {
      return 0;
    }
    return (rva - section_headers_[section_index].VirtualAddress) +
        section_headers_[section_index].PointerToRawData;
  }

  char* read_c_string_at_raw(DWORD raw_offset) const noexcept {
    if (pe_file_ == nullptr || raw_offset == 0) {
      return nullptr;
    }

    constexpr int kMaxNameBytes = 1024;
    char probe[kMaxNameBytes]{};
    if (std::fseek(pe_file_, static_cast<long>(raw_offset), SEEK_SET) != 0) {
      return nullptr;
    }
    const std::size_t n_read = std::fread(probe, 1, static_cast<std::size_t>(kMaxNameBytes - 1), pe_file_);
    if (n_read == 0) {
      return nullptr;
    }

    std::size_t len = 0;
    while (len < n_read && probe[len] != '\0') {
      ++len;
    }

    char* out_buf = static_cast<char*>(
        ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, len + 1U));
    if (out_buf == nullptr) {
      return nullptr;
    }
    if (len > 0) {
      std::memcpy(out_buf, probe, len);
    }
    out_buf[len] = '\0';
    return out_buf;
  }

  void parse_rich_header() noexcept {
    rich_header_info_.size = 0;
    rich_header_info_.entries = 0;
    rich_header_info_.ptr_to_buffer = nullptr;
    rich_header_.entries = nullptr;

    if (dos_header_.e_lfanew <= 0 || dos_header_.e_lfanew > 0x100000L) {
      return;
    }

    const std::size_t stub_size = static_cast<std::size_t>(dos_header_.e_lfanew);
    char* stub_buf = static_cast<char*>(
        ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, stub_size));
    if (stub_buf == nullptr) {
      return;
    }

    if (std::fseek(pe_file_, 0, SEEK_SET) != 0 ||
        std::fread(stub_buf, 1, stub_size, pe_file_) != stub_size) {
      ::HeapFree(::GetProcessHeap(), 0, stub_buf);
      return;
    }

    int rich_pos = -1;
    for (std::size_t i = 0; i + 4 <= stub_size; ++i) {
      // "Rich" ASCII = 0x52, 0x69, 0x63, 0x68
      if (static_cast<unsigned char>(stub_buf[i]) == 0x52U &&
          static_cast<unsigned char>(stub_buf[i + 1]) == 0x69U) {
        rich_pos = static_cast<int>(i);
        break;
      }
    }

    if (rich_pos > 16 && static_cast<std::size_t>(rich_pos) + 8 <= stub_size) {
      unsigned char key[4]{};
      std::memcpy(key, stub_buf + rich_pos + 4, 4);

      int scan_pos = rich_pos - 4;
      int rich_bytes = 0;
      while (scan_pos >= 0) {
        unsigned char decoded[4]{};
        std::memcpy(decoded, stub_buf + scan_pos, 4);
        for (int k = 0; k < 4; ++k) {
          decoded[k] = static_cast<unsigned char>(decoded[k] ^ key[k]);
        }
        rich_bytes += 4;
        // "DanS" little-endian check (decoded[0] == 'D' = 0x44, decoded[1] == 'a' = 0x61)
        if (decoded[0] == 0x44U && decoded[1] == 0x61U) {
          break;
        }
        scan_pos -= 4;
      }

      if (rich_bytes >= 24 && (rich_pos - rich_bytes) >= 0) {
        char* decoded_rich = static_cast<char*>(
            ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, static_cast<std::size_t>(rich_bytes)));
        if (decoded_rich != nullptr) {
          std::memcpy(decoded_rich, stub_buf + (rich_pos - rich_bytes), static_cast<std::size_t>(rich_bytes));
          for (int idx = 0; idx < rich_bytes; idx += 4) {
            for (int k = 0; k < 4; ++k) {
              decoded_rich[idx + k] = static_cast<char>(
                  static_cast<unsigned char>(decoded_rich[idx + k]) ^ key[k]);
            }
          }

          const int entry_count = (rich_bytes - 16) / 8;
          if (entry_count > 0) {
            rich_header_entry* entries_arr = static_cast<rich_header_entry*>(
                ::HeapAlloc(
                    ::GetProcessHeap(),
                    HEAP_ZERO_MEMORY,
                    static_cast<std::size_t>(entry_count) * sizeof(rich_header_entry)));
            if (entries_arr != nullptr) {
              for (int i = 16; i + 8 <= rich_bytes; i += 8) {
                const auto u = reinterpret_cast<const unsigned char*>(decoded_rich + i);
                const WORD prod_id = static_cast<WORD>(
                    (static_cast<std::uint16_t>(u[3]) << 8) | static_cast<std::uint16_t>(u[2]));
                const WORD build_id = static_cast<WORD>(
                    (static_cast<std::uint16_t>(u[1]) << 8) | static_cast<std::uint16_t>(u[0]));
                const DWORD use_count =
                    (static_cast<std::uint32_t>(u[7]) << 24) |
                    (static_cast<std::uint32_t>(u[6]) << 16) |
                    (static_cast<std::uint32_t>(u[5]) << 8) |
                    static_cast<std::uint32_t>(u[4]);

                const int slot = (i / 8) - 2;
                if (slot >= 0 && slot < entry_count) {
                  entries_arr[slot] = rich_header_entry{prod_id, build_id, use_count};
                }
              }
              rich_header_info_.size = rich_bytes;
              rich_header_info_.entries = entry_count;
              rich_header_info_.ptr_to_buffer = decoded_rich;
              rich_header_.entries = entries_arr;
              decoded_rich = nullptr;
            }
          }
          if (decoded_rich != nullptr) {
            ::HeapFree(::GetProcessHeap(), 0, decoded_rich);
          }
        }
      }
    }

    ::HeapFree(::GetProcessHeap(), 0, stub_buf);
  }

  void parse_file() noexcept {
    if (pe_file_ == nullptr) {
      return;
    }

    if (std::fseek(pe_file_, 0, SEEK_SET) != 0 ||
        std::fread(&dos_header_, sizeof(IMAGE_DOS_HEADER), 1, pe_file_) != 1) {
      return;
    }

    if (dos_header_.e_magic != IMAGE_DOS_SIGNATURE || dos_header_.e_lfanew <= 0) {
      return;
    }

    parse_rich_header();

    if (std::fseek(pe_file_, dos_header_.e_lfanew, SEEK_SET) != 0 ||
        std::fread(&nt_headers_, sizeof(NtHeadersType), 1, pe_file_) != 1) {
      return;
    }

    if (nt_headers_.Signature != IMAGE_NT_SIGNATURE) {
      return;
    }

    const int num_sections = static_cast<int>(nt_headers_.FileHeader.NumberOfSections);
    if (num_sections <= 0 || num_sections > 96) {
      return;
    }

    section_headers_ = static_cast<PIMAGE_SECTION_HEADER>(
        ::HeapAlloc(
            ::GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            static_cast<std::size_t>(num_sections) * sizeof(IMAGE_SECTION_HEADER)));
    if (section_headers_ == nullptr) {
      return;
    }

    const long sect_offset = dos_header_.e_lfanew +
        static_cast<long>(sizeof(DWORD)) +
        static_cast<long>(sizeof(IMAGE_FILE_HEADER)) +
        static_cast<long>(nt_headers_.FileHeader.SizeOfOptionalHeader);

    if (std::fseek(pe_file_, sect_offset, SEEK_SET) != 0 ||
        std::fread(
            section_headers_,
            sizeof(IMAGE_SECTION_HEADER),
            static_cast<std::size_t>(num_sections),
            pe_file_) != static_cast<std::size_t>(num_sections)) {
      return;
    }

    const DWORD imp_rva =
        nt_headers_.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    const int imp_loc = locate_section(imp_rva);
    if (imp_loc >= 0) {
      const DWORD imp_raw = resolve_rva_to_raw(imp_rva, imp_loc);
      int count = 0;
      while (count < 4096) {
        IMAGE_IMPORT_DESCRIPTOR tmp{};
        const long pos = static_cast<long>(
            imp_raw + static_cast<DWORD>(count) * static_cast<DWORD>(sizeof(IMAGE_IMPORT_DESCRIPTOR)));
        if (std::fseek(pe_file_, pos, SEEK_SET) != 0 ||
            std::fread(&tmp, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, pe_file_) != 1) {
          break;
        }
        if (tmp.Name == 0 && tmp.FirstThunk == 0) {
          break;
        }
        ++count;
      }

      if (count > 0) {
        import_table_ = static_cast<PIMAGE_IMPORT_DESCRIPTOR>(
            ::HeapAlloc(
                ::GetProcessHeap(),
                HEAP_ZERO_MEMORY,
                static_cast<std::size_t>(count) * sizeof(IMAGE_IMPORT_DESCRIPTOR)));
        if (import_table_ != nullptr &&
            std::fseek(pe_file_, static_cast<long>(imp_raw), SEEK_SET) == 0 &&
            std::fread(
                import_table_,
                sizeof(IMAGE_IMPORT_DESCRIPTOR),
                static_cast<std::size_t>(count),
                pe_file_) == static_cast<std::size_t>(count)) {
          import_directory_count_ = count;
        }
      }
    }

    const DWORD reloc_rva =
        nt_headers_.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    const DWORD reloc_dir_size =
        nt_headers_.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    const int reloc_loc = locate_section(reloc_rva);

    if (reloc_loc >= 0 && reloc_dir_size >= sizeof(IMAGE_BASE_RELOCATION)) {
      const DWORD reloc_raw = resolve_rva_to_raw(reloc_rva, reloc_loc);
      DWORD scanned = 0;
      int blk_count = 0;

      while (scanned + sizeof(IMAGE_BASE_RELOCATION) <= reloc_dir_size && blk_count < 65536) {
        IMAGE_BASE_RELOCATION tmp{};
        if (std::fseek(pe_file_, static_cast<long>(reloc_raw + scanned), SEEK_SET) != 0 ||
            std::fread(&tmp, sizeof(IMAGE_BASE_RELOCATION), 1, pe_file_) != 1) {
          break;
        }
        if (tmp.VirtualAddress == 0 && tmp.SizeOfBlock == 0) {
          break;
        }
        if (tmp.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
            scanned + tmp.SizeOfBlock > reloc_dir_size) {
          break;
        }
        ++blk_count;
        scanned += tmp.SizeOfBlock;
      }

      if (blk_count > 0) {
        basereloc_table_ = static_cast<PIMAGE_BASE_RELOCATION>(
            ::HeapAlloc(
                ::GetProcessHeap(),
                HEAP_ZERO_MEMORY,
                static_cast<std::size_t>(blk_count) * sizeof(IMAGE_BASE_RELOCATION)));
        if (basereloc_table_ != nullptr) {
          DWORD copy_pos = 0;
          int copied = 0;
          while (copied < blk_count) {
            if (std::fseek(pe_file_, static_cast<long>(reloc_raw + copy_pos), SEEK_SET) != 0 ||
                std::fread(&basereloc_table_[copied], sizeof(IMAGE_BASE_RELOCATION), 1, pe_file_) != 1) {
              break;
            }
            copy_pos += basereloc_table_[copied].SizeOfBlock;
            ++copied;
          }
          basereloc_directory_count_ = copied;
        }
      }
    }

    parse_ok_ = true;
  }
};
