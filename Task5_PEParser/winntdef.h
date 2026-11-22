
#pragma once

#include <windows.h>

#include <cstdint>

using QWORD = std::uint64_t;

constexpr WORD kPeOptionalHdr32Magic = 0x10b;
constexpr WORD kPeOptionalHdr64Magic = 0x20b;
constexpr DWORD kPeNumberOfDirectoryEntries = 16U;
constexpr WORD kPeDosSignature = 0x5A4D;

constexpr DWORD kPeDirEntryExport = 0U;
constexpr DWORD kPeDirEntryImport = 1U;
constexpr DWORD kPeDirEntryResource = 2U;
constexpr DWORD kPeDirEntryException = 3U;
constexpr DWORD kPeDirEntrySecurity = 4U;
constexpr DWORD kPeDirEntryBaseReloc = 5U;
constexpr DWORD kPeDirEntryDebug = 6U;
constexpr DWORD kPeDirEntryArchitecture = 7U;
constexpr DWORD kPeDirEntryGlobalPtr = 8U;
constexpr DWORD kPeDirEntryTls = 9U;
constexpr DWORD kPeDirEntryLoadConfig = 10U;
constexpr DWORD kPeDirEntryBoundImport = 11U;
constexpr DWORD kPeDirEntryIat = 12U;
constexpr DWORD kPeDirEntryDelayImport = 13U;
constexpr DWORD kPeDirEntryComDescriptor = 14U;

constexpr DWORD kPeSizeofShortName = 8U;
constexpr DWORD kPeSizeofSectionHeader = 40U;
