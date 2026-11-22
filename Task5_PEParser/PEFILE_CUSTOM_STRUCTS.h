
#pragma once

#include <windows.h>

#include <cstdint>

struct rich_header_info final {
  int size = 0;
  char* ptr_to_buffer = nullptr;
  int entries = 0;
};

struct rich_header_entry final {
  WORD prod_id = 0;
  WORD build_id = 0;
  DWORD use_count = 0;
};

struct rich_header final {
  rich_header_entry* entries = nullptr;
};

using ilt_entry_32 = DWORD;
using ilt_entry_64 = ULONGLONG;

constexpr std::uint64_t kBearOrdinalFlag64 = 0x8000000000000000ULL;
constexpr std::uint32_t kBearOrdinalFlag32 = 0x80000000U;
constexpr WORD kBearOrdinalMask = 0xFFFFU;

struct base_reloc_entry final {
  WORD offset : 12;
  WORD type : 4;
};
