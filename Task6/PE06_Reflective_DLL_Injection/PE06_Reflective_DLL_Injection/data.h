
#pragma once

#include <windows.h>

#include <cstdint>

struct base_relocation_block final {
  DWORD page_address = 0;
  DWORD block_size = 0;
};

struct base_relocation_entry final {
  std::uint16_t offset : 12;
  std::uint16_t type : 4;
};
