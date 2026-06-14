#pragma once
#include <cstdio>
#include <cstring>
#include <windows.h>
#include "winntdef.h"
#include "PEFILE_CUSTOM_STRUCTS.h"

template <typename NT_HEADERS_TYPE, typename ILT_ENTRY_TYPE>
class PEParserEngine
{
public:
    PEParserEngine(char* _NAME, FILE* _Ppefile) {
        NAME = _NAME;
        Ppefile = _Ppefile;
        PEFILE_SECTION_HEADERS = nullptr;
        PEFILE_IMPORT_TABLE = nullptr;
        PEFILE_BASERELOC_TABLE = nullptr;
        PEFILE_RICH_HEADER.entries = nullptr;

        ParseFile();
    }

    ~PEParserEngine() {
        if (PEFILE_SECTION_HEADERS) delete[] PEFILE_SECTION_HEADERS;
        if (PEFILE_IMPORT_TABLE) delete[] PEFILE_IMPORT_TABLE;
        if (PEFILE_BASERELOC_TABLE) delete[] PEFILE_BASERELOC_TABLE;
        if (PEFILE_RICH_HEADER.entries) delete[] PEFILE_RICH_HEADER.entries;
    }

    void PrintInfo() {
        // --- 1. FILE & TYPE INFO ---
        printf(" FILE: %s\n", NAME);
        if constexpr (sizeof(NT_HEADERS_TYPE) == sizeof(IMAGE_NT_HEADERS64)) {
            printf(" TYPE: 0x%X (PE32+ / 64-bit)\n", PEFILE_NT_HEADERS.OptionalHeader.Magic);
        }
        else {
            printf(" TYPE: 0x%X (PE32 / 32-bit)\n", PEFILE_NT_HEADERS.OptionalHeader.Magic);
        }
        printf(" ----------------------------------\n");

        // --- 2. DOS HEADER INFO ---
        printf(" DOS HEADER:\n -----------\n\n");
        printf("  Magic: 0x%X\n", PEFILE_DOS_HEADER.e_magic);
        printf("  File address of new exe header: 0x%X\n", PEFILE_DOS_HEADER.e_lfanew);
        printf(" ----------------------------------\n");

        // --- 3. RICH HEADER INFO ---
        if (PEFILE_RICH_HEADER_INFO.entries > 0) {
            printf(" RICH HEADER:\n ------------\n\n");
            for (int i = 0; i < PEFILE_RICH_HEADER_INFO.entries; i++) {
                printf("  0x%X 0x%X 0x%X: %d.%d.%d\n",
                    PEFILE_RICH_HEADER.entries[i].buildID, PEFILE_RICH_HEADER.entries[i].prodID, PEFILE_RICH_HEADER.entries[i].useCount,
                    PEFILE_RICH_HEADER.entries[i].buildID, PEFILE_RICH_HEADER.entries[i].prodID, PEFILE_RICH_HEADER.entries[i].useCount);
            }
            printf(" ----------------------------------\n");
        }

        // --- 4. NT HEADERS INFO ---
        printf(" NT HEADERS:\n -----------\n\n");
        printf("  PE Signature: 0x%X\n", PEFILE_NT_HEADERS.Signature);
        printf("\n  File Header:\n\n");
        printf("    Machine: 0x%X\n", PEFILE_NT_HEADERS.FileHeader.Machine);
        printf("    Number of sections: 0x%X\n", PEFILE_NT_HEADERS.FileHeader.NumberOfSections);
        printf("    Size of optional header: 0x%X\n", PEFILE_NT_HEADERS.FileHeader.SizeOfOptionalHeader);

        printf("\n  Optional Header:\n\n");
        printf("    Magic: 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.Magic);
        printf("    Size of code section: 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.SizeOfCode);
        printf("    Size of initialized data: 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.SizeOfInitializedData);
        printf("    Size of uninitialized data: 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.SizeOfUninitializedData);
        printf("    Address of entry point: 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint);
        printf("    RVA of start of code section: 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.BaseOfCode);

        if constexpr (sizeof(NT_HEADERS_TYPE) == sizeof(IMAGE_NT_HEADERS32)) {
            printf("    Base of Data: 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.BaseOfData);
            printf("    Desired image base: 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.ImageBase);
        }
        else {
            printf("    Desired image base: 0x%llX\n", PEFILE_NT_HEADERS.OptionalHeader.ImageBase);
        }

        printf("    Section alignment: 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.SectionAlignment);
        printf("    File alignment: 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.FileAlignment);
        printf("    Size of image: 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.SizeOfImage);
        printf("    Size of headers: 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.SizeOfHeaders);

        printf("\n  Data Directories:\n");
        printf("    * Import Directory: RVA: 0x%X | Size: 0x%X\n",
            PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
            PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
        printf("    * Base Relocation Table: RVA: 0x%X | Size: 0x%X\n",
            PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,
            PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
        printf(" ----------------------------------\n");

        // --- 5. SECTION HEADERS INFO ---
        printf(" SECTION HEADERS:\n ----------------\n\n");
        for (int i = 0; i < (int)PEFILE_NT_HEADERS.FileHeader.NumberOfSections; i++) {
            printf("    * %.8s:\n", PEFILE_SECTION_HEADERS[i].Name);
            printf("         VirtualAddress: 0x%X\n", PEFILE_SECTION_HEADERS[i].VirtualAddress);
            printf("         VirtualSize: 0x%X\n", PEFILE_SECTION_HEADERS[i].Misc.VirtualSize);
            printf("         PointerToRawData: 0x%X\n", PEFILE_SECTION_HEADERS[i].PointerToRawData);
            printf("         SizeOfRawData: 0x%X\n", PEFILE_SECTION_HEADERS[i].SizeOfRawData);
            printf("         Characteristics: 0x%X\n\n", PEFILE_SECTION_HEADERS[i].Characteristics);
        }
        printf(" ----------------------------------\n");

        // --- 6. IMPORT TABLE INFO ---
        if (_import_directory_count > 0) {
            printf(" IMPORT TABLE:\n ----------------\n\n");
            for (int i = 0; i < _import_directory_count; i++) {
                int nameLoc = locate(PEFILE_IMPORT_TABLE[i].Name);
                DWORD NameAddr = resolve(PEFILE_IMPORT_TABLE[i].Name, nameLoc);
                int NameSize = 0;
                while (true) {
                    char tmp;
                    fseek(Ppefile, (NameAddr + NameSize), SEEK_SET);
                    fread(&tmp, sizeof(char), 1, Ppefile);
                    if (tmp == 0x00) break;
                    NameSize++;
                }
                char* Name = new char[NameSize + 2];
                fseek(Ppefile, NameAddr, SEEK_SET);
                fread(Name, (NameSize * sizeof(char)) + 1, 1, Ppefile);
                printf("   * %s:\n", Name);
                delete[] Name;

                printf("       ILT RVA: 0x%X\n", PEFILE_IMPORT_TABLE[i].OriginalFirstThunk);
                printf("       IAT RVA: 0x%X\n", PEFILE_IMPORT_TABLE[i].FirstThunk);
                printf("\n");

                DWORD thunkRva = PEFILE_IMPORT_TABLE[i].OriginalFirstThunk ? PEFILE_IMPORT_TABLE[i].OriginalFirstThunk : PEFILE_IMPORT_TABLE[i].FirstThunk;
                int iltLoc = locate(thunkRva);
                DWORD ILTAddr = resolve(thunkRva, iltLoc);
                int entrycounter = 0;

                while (true) {
                    ILT_ENTRY_TYPE entry;
                    fseek(Ppefile, (ILTAddr + (entrycounter * sizeof(entry))), SEEK_SET);
                    fread(&entry, sizeof(entry), 1, Ppefile);

                    if (entry == 0) break; // End of table

                    BYTE flag = 0;
                    DWORD HintRVA = 0;
                    WORD ordinal = 0;

                    // Sử dụng toán tử Bitwise thuần túy kịch trần để tránh lỗi C2228 hệ thống
                    if constexpr (sizeof(ILT_ENTRY_TYPE) == sizeof(ILT_ENTRY_32)) {
                        if (entry & BEAR_ORDINAL_FLAG32) {
                            flag = 1;
                            ordinal = (WORD)(entry & BEAR_ORDINAL_MASK);
                        }
                        else {
                            flag = 0;
                            HintRVA = (DWORD)entry;
                        }
                    }
                    else {
                        if (entry & BEAR_ORDINAL_FLAG64) {
                            flag = 1;
                            ordinal = (WORD)(entry & BEAR_ORDINAL_MASK);
                        }
                        else {
                            flag = 0;
                            HintRVA = (DWORD)(entry & 0xFFFFFFFF);
                        }
                    }

                    printf("\n       Entry:\n");
                    if (flag == 0) {
                        int hintLoc = locate(HintRVA);
                        DWORD HintAddr = resolve(HintRVA, hintLoc);

                        // 1. Đọc trường Hint (2 bytes đầu tiên của cấu trúc)
                        WORD functionHint = 0;
                        fseek(Ppefile, HintAddr, SEEK_SET);
                        fread(&functionHint, sizeof(WORD), 1, Ppefile);

                        // 2. Thuật toán cào chuỗi ký thô adaptive tính độ dài chuỗi tên hàm dưới đĩa
                        int funcNameSize = 0;
                        while (true) {
                            char ch;
                            fseek(Ppefile, HintAddr + sizeof(WORD) + funcNameSize, SEEK_SET);
                            fread(&ch, sizeof(char), 1, Ppefile);
                            if (ch == 0x00) break; // Gặp ký tự Null-terminator thì dừng toán thức
                            funcNameSize++;
                        }

                        // 3. Cấp phát vùng đệm động vừa khít đến từng byte chống rò rỉ bộ nhớ
                        char* pFuncNameBuf = new char[funcNameSize + 1];
                        fseek(Ppefile, HintAddr + sizeof(WORD), SEEK_SET);
                        fread(pFuncNameBuf, sizeof(char), funcNameSize, Ppefile);
                        pFuncNameBuf[funcNameSize] = '\0'; // Ép chặt ký tự kết thúc chuỗi an toàn

                        // 4. In ấn thô nguyên mẫu ra màn hình CLI
                        printf("         Name: %s\n", pFuncNameBuf);
                        printf("         Hint RVA: 0x%X\n", HintRVA);
                        printf("         Hint: 0x%X\n", functionHint);

                        delete[] pFuncNameBuf; // Giải phóng triệt để vùng đệm RAM kịch trần
                    }
                    else {
                        printf("         Ordinal: 0x%X\n", ordinal);
                    }
                    entrycounter++;
                }
                printf("\n   ----------------------\n\n");
            }
            printf(" ----------------------------------\n");
        }

        // --- 7. BASE RELOCATIONS INFO ---
        if (_basreloc_directory_count > 0) {
            printf(" BASE RELOCATIONS TABLE:\n -----------------------\n");
            int szCounter = sizeof(IMAGE_BASE_RELOCATION);
            for (int i = 0; i < _basreloc_directory_count; i++) {
                int relocLoc = locate(PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
                DWORD BASE_RELOC_ADDR = resolve(PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, relocLoc);
                DWORD PAGERVA = PEFILE_BASERELOC_TABLE[i].VirtualAddress;
                DWORD BLOCKSIZE = PEFILE_BASERELOC_TABLE[i].SizeOfBlock;
                int ENTRIES = (BLOCKSIZE - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

                printf("\n   Block 0x%X: \n", i);
                printf("     Page RVA: 0x%X\n", PAGERVA);
                printf("     Block size: 0x%X\n", BLOCKSIZE);
                printf("     Number of entries: 0x%X\n", ENTRIES);
                printf("\n     Entries:\n");

                for (int j = 0; j < ENTRIES; j++) {
                    BASE_RELOC_ENTRY entry;
                    int offset = (BASE_RELOC_ADDR + szCounter + (j * sizeof(WORD)));
                    fseek(Ppefile, offset, SEEK_SET);
                    fread(&entry, sizeof(WORD), 1, Ppefile);

                    WORD rawValue = *(WORD*)&entry;
                    printf("\n       * Value: 0x%X\n", rawValue);
                    printf("         Relocation Type: 0x%X\n", entry.TYPE);
                    printf("         Offset: 0x%X\n", entry.OFFSET);
                }
                printf("\n   ----------------------\n\n");
                szCounter += BLOCKSIZE;
            }
            printf(" ----------------------------------\n");
        }
    }

private:
    char* NAME;
    FILE* Ppefile;
    int _import_directory_count = 0;
    int _import_directory_size = 0;
    int _basreloc_directory_count = 0;

    IMAGE_DOS_HEADER      PEFILE_DOS_HEADER;
    NT_HEADERS_TYPE       PEFILE_NT_HEADERS;
    RICH_HEADER_INFO      PEFILE_RICH_HEADER_INFO;
    RICH_HEADER           PEFILE_RICH_HEADER;
    PIMAGE_SECTION_HEADER PEFILE_SECTION_HEADERS;
    PIMAGE_IMPORT_DESCRIPTOR PEFILE_IMPORT_TABLE;
    PIMAGE_BASE_RELOCATION   PEFILE_BASERELOC_TABLE;

    int locate(DWORD VA) {
        for (int i = 0; i < (int)PEFILE_NT_HEADERS.FileHeader.NumberOfSections; i++) {
            if (VA >= PEFILE_SECTION_HEADERS[i].VirtualAddress &&
                VA < (PEFILE_SECTION_HEADERS[i].VirtualAddress + PEFILE_SECTION_HEADERS[i].Misc.VirtualSize)) {
                return i;
            }
        }
        return -1;
    }

    DWORD resolve(DWORD VA, int index) {
        if (index == -1) return 0;
        return (VA - PEFILE_SECTION_HEADERS[index].VirtualAddress) + PEFILE_SECTION_HEADERS[index].PointerToRawData;
    }

    void ParseFile() {
        fseek(Ppefile, 0, SEEK_SET);
        fread(&PEFILE_DOS_HEADER, sizeof(IMAGE_DOS_HEADER), 1, Ppefile);

        char* dataPtr = new char[PEFILE_DOS_HEADER.e_lfanew];
        fseek(Ppefile, 0, SEEK_SET);
        fread(dataPtr, PEFILE_DOS_HEADER.e_lfanew, 1, Ppefile);
        int index_ = 0;
        for (int i = 0; i <= (int)PEFILE_DOS_HEADER.e_lfanew - 4; i++) {
            if (dataPtr[i] == 0x52 && dataPtr[i + 1] == 0x69) { index_ = i; break; }
        }
        if (index_ == 0) {
            PEFILE_RICH_HEADER_INFO.entries = 0;
        }
        else {
            char key[4]; memcpy(key, dataPtr + (index_ + 4), 4);
            int indexpointer = index_ - 4; int RichHeaderSize = 0;
            while (indexpointer > 0) {
                char tmpchar[4]; memcpy(tmpchar, dataPtr + indexpointer, 4);
                for (int i = 0; i < 4; i++) tmpchar[i] = tmpchar[i] ^ key[i];
                indexpointer -= 4; RichHeaderSize += 4;
                if (tmpchar[1] == 0x61 && tmpchar[0] == 0x44) break;
            }
            char* RichHeaderPtr = new char[RichHeaderSize];
            memcpy(RichHeaderPtr, dataPtr + (index_ - RichHeaderSize), RichHeaderSize);
            for (int i = 0; i < RichHeaderSize; i += 4) {
                for (int x = 0; x < 4; x++) RichHeaderPtr[i + x] = RichHeaderPtr[i + x] ^ key[x];
            }
            PEFILE_RICH_HEADER_INFO.size = RichHeaderSize;
            PEFILE_RICH_HEADER_INFO.entries = (RichHeaderSize - 16) / 8;
            PEFILE_RICH_HEADER.entries = new RICH_HEADER_ENTRY[PEFILE_RICH_HEADER_INFO.entries];
            for (int i = 16; i < RichHeaderSize; i += 8) {
                WORD PRODID = (uint16_t)((unsigned char)RichHeaderPtr[i + 3] << 8) | (unsigned char)RichHeaderPtr[i + 2];
                WORD BUILDID = (uint16_t)((unsigned char)RichHeaderPtr[i + 1] << 8) | (unsigned char)RichHeaderPtr[i];
                DWORD USECOUNT = (uint32_t)((unsigned char)RichHeaderPtr[i + 7] << 24) | (unsigned char)RichHeaderPtr[i + 6] << 16 | (unsigned char)RichHeaderPtr[i + 5] << 8 | (unsigned char)RichHeaderPtr[i + 4];
                PEFILE_RICH_HEADER.entries[(i / 8) - 2] = { PRODID, BUILDID, USECOUNT };
            }
            delete[] RichHeaderPtr;
        }
        delete[] dataPtr;

        fseek(Ppefile, PEFILE_DOS_HEADER.e_lfanew, SEEK_SET);
        fread(&PEFILE_NT_HEADERS, sizeof(NT_HEADERS_TYPE), 1, Ppefile);

        PEFILE_SECTION_HEADERS = new IMAGE_SECTION_HEADER[PEFILE_NT_HEADERS.FileHeader.NumberOfSections];
        int sectOffset = PEFILE_DOS_HEADER.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + PEFILE_NT_HEADERS.FileHeader.SizeOfOptionalHeader;
        fseek(Ppefile, sectOffset, SEEK_SET);
        fread(PEFILE_SECTION_HEADERS, sizeof(IMAGE_SECTION_HEADER), PEFILE_NT_HEADERS.FileHeader.NumberOfSections, Ppefile);

        DWORD impRVA = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        int impLoc = locate(impRVA);
        if (impLoc == -1) { _import_directory_count = 0; }
        else {
            DWORD impRAW = resolve(impRVA, impLoc);
            while (true) {
                IMAGE_IMPORT_DESCRIPTOR tmp;
                fseek(Ppefile, impRAW + (_import_directory_count * sizeof(IMAGE_IMPORT_DESCRIPTOR)), SEEK_SET);
                fread(&tmp, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, Ppefile);
                if (tmp.Name == 0 && tmp.FirstThunk == 0) break;
                _import_directory_count++;
            }
            if (_import_directory_count > 0) {
                PEFILE_IMPORT_TABLE = new IMAGE_IMPORT_DESCRIPTOR[_import_directory_count];
                fseek(Ppefile, impRAW, SEEK_SET);
                fread(PEFILE_IMPORT_TABLE, sizeof(IMAGE_IMPORT_DESCRIPTOR), _import_directory_count, Ppefile);
            }
        }

        DWORD relocRVA = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        int relocLoc = locate(relocRVA);
        if (relocLoc == -1) { _basreloc_directory_count = 0; }
        else {
            DWORD relocRAW = resolve(relocRVA, relocLoc);
            int sizeCounter = 0;
            while (sizeCounter < (int)PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
                IMAGE_BASE_RELOCATION tmp;
                fseek(Ppefile, relocRAW + sizeCounter, SEEK_SET);
                fread(&tmp, sizeof(IMAGE_BASE_RELOCATION), 1, Ppefile);
                if (tmp.VirtualAddress == 0 && tmp.SizeOfBlock == 0) break;
                _basreloc_directory_count++;
                sizeCounter += tmp.SizeOfBlock;
            }
            if (_basreloc_directory_count > 0) {
                PEFILE_BASERELOC_TABLE = new IMAGE_BASE_RELOCATION[_basreloc_directory_count];
                sizeCounter = 0;
                for (int i = 0; i < _basreloc_directory_count; i++) {
                    fseek(Ppefile, relocRAW + sizeCounter, SEEK_SET);
                    fread(&PEFILE_BASERELOC_TABLE[i], sizeof(IMAGE_BASE_RELOCATION), 1, Ppefile);
                    sizeCounter += PEFILE_BASERELOC_TABLE[i].SizeOfBlock;
                }
            }
        }
    }
};