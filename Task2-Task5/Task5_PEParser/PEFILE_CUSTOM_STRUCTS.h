#pragma once
#include <windows.h>

// 1. Cấu trúc quản lý bộ đệm thông tin Rich Header trong quá trình bóc tách dữ liệu thô
typedef struct __RICH_HEADER_INFO {
    int size;
    char* ptrToBuffer;
    int entries;
} RICH_HEADER_INFO, * PRICH_HEADER_INFO;

// 2. Cấu trúc đại diện cho một bản ghi (Entry) giải mã từ Rich Header
typedef struct __RICH_HEADER_ENTRY {
    WORD  prodID;
    WORD  buildID;
    DWORD useCount;
} RICH_HEADER_ENTRY, * PRICH_HEADER_ENTRY;

// 3. Cấu trúc mảng quản lý danh sách Rich Header
typedef struct __RICH_HEADER {
    PRICH_HEADER_ENTRY entries;
} RICH_HEADER, * PRICH_HEADER;

// 4. Định nghĩa kiểu dữ liệu Thunk nguyên thủy dạng Scaler cho ILT Table
typedef DWORD     ILT_ENTRY_32;
typedef ULONGLONG ILT_ENTRY_64;

// Định nghĩa các hằng số mặt nạ Bit hệ thống để bóc tách bit cao nhất (Ordinal Flag)
#define BEAR_ORDINAL_FLAG64 0x8000000000000000ULL
#define BEAR_ORDINAL_FLAG32 0x80000000
#define BEAR_ORDINAL_MASK   0xFFFF

// 5. Cấu trúc phân rã ranh giới 16-bit của một bản ghi Base Relocation
typedef struct __BASE_RELOC_ENTRY {
    WORD OFFSET : 12; // 12 bit thấp lưu vị trí lệch trong trang bộ nhớ 4KB
    WORD TYPE : 4;    // 4 bit cao lưu phân loại kiểu Relocation
} BASE_RELOC_ENTRY, * PBASE_RELOC_ENTRY;