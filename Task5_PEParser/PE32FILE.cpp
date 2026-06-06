#include "PE32FILE.h"
#include <iostream>
#include <cstring>

using namespace std;

PE32FILE::PE32FILE(char* _NAME, FILE* _Ppefile) {
    NAME = _NAME;
    Ppefile = _Ppefile;
    PEFILE_SECTION_HEADERS = nullptr;
    PEFILE_IMPORT_TABLE = nullptr;
    PEFILE_BASERELOC_TABLE = nullptr;
    PEFILE_RICH_HEADER.entries = nullptr;

    ParseFile();
}

PE32FILE::~PE32FILE() {
    if (PEFILE_SECTION_HEADERS) delete[] PEFILE_SECTION_HEADERS;
    if (PEFILE_IMPORT_TABLE) delete[] PEFILE_IMPORT_TABLE;
    if (PEFILE_BASERELOC_TABLE) delete[] PEFILE_BASERELOC_TABLE;
    if (PEFILE_RICH_HEADER.entries) delete[] PEFILE_RICH_HEADER.entries;
}

void PE32FILE::ParseFile() {
    ParseDOSHeader();
    ParseRichHeader();
    ParseNTHeaders();
    ParseSectionHeaders();
    ParseImportDirectory();
    ParseBaseReloc();
}

int PE32FILE::locate(DWORD VA) {
    int index = -1;
    for (int i = 0; i < (int)PEFILE_NT_HEADERS_FILE_HEADER_NUMBER0F_SECTIONS; i++) {
        if (VA >= PEFILE_SECTION_HEADERS[i].VirtualAddress
            && VA < (PEFILE_SECTION_HEADERS[i].VirtualAddress + PEFILE_SECTION_HEADERS[i].Misc.VirtualSize)) {
            index = i;
            break;
        }
    }
    return index;
}

DWORD PE32FILE::resolve(DWORD VA, int index) {
    if (index == -1) return 0;
    return (VA - PEFILE_SECTION_HEADERS[index].VirtualAddress) + PEFILE_SECTION_HEADERS[index].PointerToRawData;
}

void PE32FILE::ParseDOSHeader() {
    fseek(Ppefile, 0, SEEK_SET);
    fread(&PEFILE_DOS_HEADER, sizeof(IMAGE_DOS_HEADER), 1, Ppefile);
    PEFILE_DOS_HEADER_EMAGIC = PEFILE_DOS_HEADER.e_magic;
    PEFILE_DOS_HEADER_LFANEW = PEFILE_DOS_HEADER.e_lfanew;
}

void PE32FILE::ParseRichHeader() {
    char* dataPtr = new char[PEFILE_DOS_HEADER_LFANEW];
    fseek(Ppefile, 0, SEEK_SET);
    fread(dataPtr, PEFILE_DOS_HEADER_LFANEW, 1, Ppefile);

    int index_ = 0;
    for (int i = 0; i <= (int)PEFILE_DOS_HEADER_LFANEW - 4; i++) {
        if (dataPtr[i] == 0x52 && dataPtr[i + 1] == 0x69) {
            index_ = i;
            break;
        }
    }

    if (index_ == 0) {
        PEFILE_RICH_HEADER_INFO.entries = 0;
        delete[] dataPtr;
        return;
    }

    char key[4];
    memcpy(key, dataPtr + (index_ + 4), 4);

    int indexpointer = index_ - 4;
    int RichHeaderSize = 0;

    while (indexpointer > 0) {
        char tmpchar[4];
        memcpy(tmpchar, dataPtr + indexpointer, 4);
        for (int i = 0; i < 4; i++) tmpchar[i] = tmpchar[i] ^ key[i];
        indexpointer -= 4;
        RichHeaderSize += 4;
        if (tmpchar[1] == 0x61 && tmpchar[0] == 0x44) break;
    }

    char* RichHeaderPtr = new char[RichHeaderSize];
    memcpy(RichHeaderPtr, dataPtr + (index_ - RichHeaderSize), RichHeaderSize);

    for (int i = 0; i < RichHeaderSize; i += 4) {
        for (int x = 0; x < 4; x++) RichHeaderPtr[i + x] = RichHeaderPtr[i + x] ^ key[x];
    }

    PEFILE_RICH_HEADER_INFO.size = RichHeaderSize;
    PEFILE_RICH_HEADER_INFO.ptrToBuffer = RichHeaderPtr;
    PEFILE_RICH_HEADER_INFO.entries = (RichHeaderSize - 16) / 8;
    delete[] dataPtr;

    PEFILE_RICH_HEADER.entries = new RICH_HEADER_ENTRY[PEFILE_RICH_HEADER_INFO.entries];
    for (int i = 16; i < RichHeaderSize; i += 8) {
        WORD PRODID = (uint16_t)((unsigned char)RichHeaderPtr[i + 3] << 8) | (unsigned char)RichHeaderPtr[i + 2];
        WORD BUILDID = (uint16_t)((unsigned char)RichHeaderPtr[i + 1] << 8) | (unsigned char)RichHeaderPtr[i];
        DWORD USECOUNT = (uint32_t)((unsigned char)RichHeaderPtr[i + 7] << 24) | (unsigned char)RichHeaderPtr[i + 6] << 16 | (unsigned char)RichHeaderPtr[i + 5] << 8 | (unsigned char)RichHeaderPtr[i + 4];

        PEFILE_RICH_HEADER.entries[(i / 8) - 2] = { PRODID, BUILDID, USECOUNT };
        if (i + 8 >= RichHeaderSize) {
            PEFILE_RICH_HEADER.entries[(i / 8) - 1] = { 0x0000, 0x0000, 0x00000000 };
        }
    }
    delete[] RichHeaderPtr;
}

void PE32FILE::ParseNTHeaders() {
    fseek(Ppefile, PEFILE_DOS_HEADER_LFANEW, SEEK_SET);
    fread(&PEFILE_NT_HEADERS, sizeof(PEFILE_NT_HEADERS), 1, Ppefile);

    PEFILE_NT_HEADERS_SIGNATURE = PEFILE_NT_HEADERS.Signature;
    PEFILE_NT_HEADERS_FILE_HEADER_MACHINE = PEFILE_NT_HEADERS.FileHeader.Machine;
    PEFILE_NT_HEADERS_FILE_HEADER_NUMBER0F_SECTIONS = PEFILE_NT_HEADERS.FileHeader.NumberOfSections;
    PEFILE_NT_HEADERS_FILE_HEADER_SIZEOF_OPTIONAL_HEADER = PEFILE_NT_HEADERS.FileHeader.SizeOfOptionalHeader;

    PEFILE_NT_HEADERS_OPTIONAL_HEADER_MAGIC = PEFILE_NT_HEADERS.OptionalHeader.Magic;
    PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_CODE = PEFILE_NT_HEADERS.OptionalHeader.SizeOfCode;
    PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_INITIALIZED_DATA = PEFILE_NT_HEADERS.OptionalHeader.SizeOfInitializedData;
    PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_UNINITIALIZED_DATA = PEFILE_NT_HEADERS.OptionalHeader.SizeOfUninitializedData;
    PEFILE_NT_HEADERS_OPTIONAL_HEADER_ADDRESSOF_ENTRYPOINT = PEFILE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint;
    PEFILE_NT_HEADERS_OPTIONAL_HEADER_BASEOF_CODE = PEFILE_NT_HEADERS.OptionalHeader.BaseOfCode;
    PEFILE_NT_HEADERS_OPTIONAL_HEADER_BASEOF_DATA = PEFILE_NT_HEADERS.OptionalHeader.BaseOfData;
    PEFILE_NT_HEADERS_OPTIONAL_HEADER_IMAGEBASE = PEFILE_NT_HEADERS.OptionalHeader.ImageBase;
    PEFILE_NT_HEADERS_OPTIONAL_HEADER_SECTION_ALIGNMENT = PEFILE_NT_HEADERS.OptionalHeader.SectionAlignment;
    PEFILE_NT_HEADERS_OPTIONAL_HEADER_FILE_ALIGNMENT = PEFILE_NT_HEADERS.OptionalHeader.FileAlignment;
    PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_IMAGE = PEFILE_NT_HEADERS.OptionalHeader.SizeOfImage;
    PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_HEADERS = PEFILE_NT_HEADERS.OptionalHeader.SizeOfHeaders;

    PEFILE_EXPORT_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PEFILE_IMPORT_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PEFILE_RESOURCE_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    PEFILE_EXCEPTION_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    PEFILE_SECURITY_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    PEFILE_BASERELOC_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    PEFILE_DEBUG_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    PEFILE_ARCHITECTURE_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE];
    PEFILE_GLOBALPTR_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR];
    PEFILE_TLS_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    PEFILE_LOAD_CONFIG_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    PEFILE_BOUND_IMPORT_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
    PEFILE_IAT_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    PEFILE_DELAY_IMPORT_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    PEFILE_COM_DESCRIPTOR_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
}

void PE32FILE::ParseSectionHeaders() {
    PEFILE_SECTION_HEADERS = new IMAGE_SECTION_HEADER[PEFILE_NT_HEADERS_FILE_HEADER_NUMBER0F_SECTIONS];
    for (int i = 0; i < (int)PEFILE_NT_HEADERS_FILE_HEADER_NUMBER0F_SECTIONS; i++) {
        int offset = (PEFILE_DOS_HEADER_LFANEW + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + PEFILE_NT_HEADERS_FILE_HEADER_SIZEOF_OPTIONAL_HEADER) + (i * sizeof(IMAGE_SECTION_HEADER));
        fseek(Ppefile, offset, SEEK_SET);
        fread(&PEFILE_SECTION_HEADERS[i], sizeof(IMAGE_SECTION_HEADER), 1, Ppefile);
    }
}

void PE32FILE::ParseImportDirectory() {
    int loc = locate(PEFILE_IMPORT_DIRECTORY.VirtualAddress);
    if (loc == -1) { _import_directory_count = 0; return; }
    DWORD _import_directory_address = resolve(PEFILE_IMPORT_DIRECTORY.VirtualAddress, loc);
    _import_directory_count = 0;

    while (true) {
        IMAGE_IMPORT_DESCRIPTOR tmp;
        int offset = (_import_directory_count * sizeof(IMAGE_IMPORT_DESCRIPTOR)) + _import_directory_address;
        fseek(Ppefile, offset, SEEK_SET);
        fread(&tmp, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, Ppefile);
        if (tmp.Name == 0x00000000 && tmp.FirstThunk == 0x00000000) {
            _import_directory_size = _import_directory_count * sizeof(IMAGE_IMPORT_DESCRIPTOR);
            break;
        }
        _import_directory_count++;
    }

    if (_import_directory_count > 0) {
        PEFILE_IMPORT_TABLE = new IMAGE_IMPORT_DESCRIPTOR[_import_directory_count];
        for (int i = 0; i < _import_directory_count; i++) {
            int offset = (i * sizeof(IMAGE_IMPORT_DESCRIPTOR)) + _import_directory_address;
            fseek(Ppefile, offset, SEEK_SET);
            fread(&PEFILE_IMPORT_TABLE[i], sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, Ppefile);
        }
    }
}

void PE32FILE::ParseBaseReloc() {
    int loc = locate(PEFILE_BASERELOC_DIRECTORY.VirtualAddress);
    if (loc == -1) { _basreloc_directory_count = 0; return; }
    DWORD _basereloc_directory_address = resolve(PEFILE_BASERELOC_DIRECTORY.VirtualAddress, loc);
    _basreloc_directory_count = 0;
    int _basereloc_size_counter = 0;

    while (_basereloc_size_counter < (int)PEFILE_BASERELOC_DIRECTORY.Size) {
        IMAGE_BASE_RELOCATION tmp;
        int offset = (_basereloc_size_counter + _basereloc_directory_address);
        fseek(Ppefile, offset, SEEK_SET);
        fread(&tmp, sizeof(IMAGE_BASE_RELOCATION), 1, Ppefile);
        if (tmp.VirtualAddress == 0x00000000 && tmp.SizeOfBlock == 0x00000000) break;
        _basreloc_directory_count++;
        _basereloc_size_counter += tmp.SizeOfBlock;
    }

    if (_basreloc_directory_count > 0) {
        PEFILE_BASERELOC_TABLE = new IMAGE_BASE_RELOCATION[_basreloc_directory_count];
        _basereloc_size_counter = 0;
        for (int i = 0; i < _basreloc_directory_count; i++) {
            int offset = _basereloc_directory_address + _basereloc_size_counter;
            fseek(Ppefile, offset, SEEK_SET);
            fread(&PEFILE_BASERELOC_TABLE[i], sizeof(IMAGE_BASE_RELOCATION), 1, Ppefile);
            _basereloc_size_counter += PEFILE_BASERELOC_TABLE[i].SizeOfBlock;
        }
    }
}

void PE32FILE::PrintInfo() {
    PrintFileInfo();
    PrintDOSHeaderInfo();
    PrintRichHeaderInfo();
    PrintNTHeadersInfo();
    PrintSectionHeadersInfo();
    PrintImportTableInfo();
    PrintBaseRelocationsInfo();
}

void PE32FILE::PrintFileInfo() {
    printf(" FILE: %s\n", NAME);
    printf(" TYPE: 0x%X (PE32)\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_MAGIC);
    printf(" ----------------------------------\n");
}

void PE32FILE::PrintDOSHeaderInfo() {
    printf(" DOS HEADER:\n");
    printf(" -----------\n\n");
    printf("  Magic: 0x%X\n", PEFILE_DOS_HEADER_EMAGIC);
    printf("  File address of new exe header: 0x%X\n", PEFILE_DOS_HEADER_LFANEW);
    printf(" ----------------------------------\n");
}

void PE32FILE::PrintRichHeaderInfo() {
    if (PEFILE_RICH_HEADER_INFO.entries == 0) return;
    printf(" RICH HEADER:\n");
    printf(" ------------\n\n");
    for (int i = 0; i < PEFILE_RICH_HEADER_INFO.entries; i++) {
        printf("  0x%X 0x%X 0x%X: %d.%d.%d\n",
            PEFILE_RICH_HEADER.entries[i].buildID, PEFILE_RICH_HEADER.entries[i].prodID, PEFILE_RICH_HEADER.entries[i].useCount,
            PEFILE_RICH_HEADER.entries[i].buildID, PEFILE_RICH_HEADER.entries[i].prodID, PEFILE_RICH_HEADER.entries[i].useCount);
    }
    printf(" ----------------------------------\n");
}

void PE32FILE::PrintNTHeadersInfo() {
    printf(" NT HEADERS:\n");
    printf(" -----------\n\n");
    printf("  PE Signature: 0x%X\n", PEFILE_NT_HEADERS_SIGNATURE);
    printf("\n  File Header:\n\n");
    printf("    Machine: 0x%X\n", PEFILE_NT_HEADERS_FILE_HEADER_MACHINE);
    printf("    Number of sections: 0x%X\n", PEFILE_NT_HEADERS_FILE_HEADER_NUMBER0F_SECTIONS);
    printf("    Size of optional header: 0x%X\n", PEFILE_NT_HEADERS_FILE_HEADER_SIZEOF_OPTIONAL_HEADER);

    printf("\n  Optional Header:\n\n");
    printf("    Magic: 0x%X\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_MAGIC);
    printf("    Size of code section: 0x%X\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_CODE);
    printf("    Size of initialized data: 0x%X\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_INITIALIZED_DATA);
    printf("    Size of uninitialized data: 0x%X\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_UNINITIALIZED_DATA);
    printf("    Address of entry point: 0x%X\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_ADDRESSOF_ENTRYPOINT);
    printf("    RVA of start of code section: 0x%X\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_BASEOF_CODE);
    printf("    Base of Data: 0x%X\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_BASEOF_DATA);
    printf("    Desired image base: 0x%X\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_IMAGEBASE);
    printf("    Section alignment: 0x%X\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_SECTION_ALIGNMENT);
    printf("    File alignment: 0x%X\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_FILE_ALIGNMENT);
    printf("    Size of image: 0x%X\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_IMAGE);
    printf("    Size of headers: 0x%X\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_HEADERS);

    printf("\n  Data Directories:\n");
    printf("    * Import Directory: RVA: 0x%X | Size: 0x%X\n", PEFILE_IMPORT_DIRECTORY.VirtualAddress, PEFILE_IMPORT_DIRECTORY.Size);
    printf("    * Base Relocation Table: RVA: 0x%X | Size: 0x%X\n", PEFILE_BASERELOC_DIRECTORY.VirtualAddress, PEFILE_BASERELOC_DIRECTORY.Size);
    printf(" ----------------------------------\n");
}

void PE32FILE::PrintSectionHeadersInfo() {
    printf(" SECTION HEADERS:\n");
    printf(" ----------------\n\n");
    for (int i = 0; i < (int)PEFILE_NT_HEADERS_FILE_HEADER_NUMBER0F_SECTIONS; i++) {
        printf("    * %.8s:\n", PEFILE_SECTION_HEADERS[i].Name);
        printf("         VirtualAddress: 0x%X\n", PEFILE_SECTION_HEADERS[i].VirtualAddress);
        printf("         VirtualSize: 0x%X\n", PEFILE_SECTION_HEADERS[i].Misc.VirtualSize);
        printf("         PointerToRawData: 0x%X\n", PEFILE_SECTION_HEADERS[i].PointerToRawData);
        printf("         SizeOfRawData: 0x%X\n", PEFILE_SECTION_HEADERS[i].SizeOfRawData);
        printf("         Characteristics: 0x%X\n\n", PEFILE_SECTION_HEADERS[i].Characteristics);
    }
    printf(" ----------------------------------\n");
}

void PE32FILE::PrintImportTableInfo() {
    if (_import_directory_count == 0) return;
    printf(" IMPORT TABLE:\n");
    printf(" ----------------\n\n");

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

            ILT_ENTRY_32 rawEntry32;
            fseek(Ppefile, (ILTAddr + (entrycounter * sizeof(DWORD))), SEEK_SET);
            fread(&rawEntry32, sizeof(DWORD), 1, Ppefile);

            // IMAGE_ORDINAL_FLAG32 is 0x80000000
            bool isOrdinal = (rawEntry32 & 0x80000000) != 0;
            DWORD HintRVA = 0x0;
            WORD ordinal = 0x0;
            if (!isOrdinal) HintRVA = rawEntry32 & 0x7FFFFFFF;
            else ordinal = (WORD)(rawEntry32 & 0xFFFF);

            if (!isOrdinal && HintRVA == 0x0 && ordinal == 0x0) break;

            printf("\n       Entry:\n");
                if (!isOrdinal) {
                IMAGE_IMPORT_BY_NAME hint;
                int hintLoc = locate(HintRVA);
                DWORD HintAddr = resolve(HintRVA, hintLoc);
                fseek(Ppefile, HintAddr, SEEK_SET);
                fread(&hint, sizeof(IMAGE_IMPORT_BY_NAME), 1, Ppefile);
                printf("         Name: %s\n", hint.Name);
                printf("         Hint RVA: 0x%X\n", HintRVA);
                printf("         Hint: 0x%X\n", hint.Hint);
            }
            else if (isOrdinal) {
                printf("         Ordinal: 0x%X\n", ordinal);
            }
            entrycounter++;
        }
        printf("\n   ----------------------\n\n");
    }
    printf(" ----------------------------------\n");
}

void PE32FILE::PrintBaseRelocationsInfo() {
    if (_basreloc_directory_count == 0) return;
    printf(" BASE RELOCATIONS TABLE:\n");
    printf(" -----------------------\n");

    int szCounter = sizeof(IMAGE_BASE_RELOCATION);
    for (int i = 0; i < _basreloc_directory_count; i++) {
        DWORD PAGERVA, BLOCKSIZE, BASE_RELOC_ADDR;
        int ENTRIES;

        int relocLoc = locate(PEFILE_BASERELOC_DIRECTORY.VirtualAddress);
        BASE_RELOC_ADDR = resolve(PEFILE_BASERELOC_DIRECTORY.VirtualAddress, relocLoc);
        PAGERVA = PEFILE_BASERELOC_TABLE[i].VirtualAddress;
        BLOCKSIZE = PEFILE_BASERELOC_TABLE[i].SizeOfBlock;
        ENTRIES = (BLOCKSIZE - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

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