#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <windows.h>
#include <shobjidl.h>
#include <shlguid.h>
#include "winntdef.h"
#include "PEParserEngine.hpp" // Khai báo tầng động cơ khuôn mẫu mới

using namespace std;

wstring ResolveShortcut(const wstring& inputPath) {
    if (inputPath.length() < 4 || inputPath.substr(inputPath.length() - 4) != L".lnk") {
        return inputPath;
    }
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) return inputPath;

    IShellLinkW* pShellLink = NULL;
    wstring resolvedPath = inputPath;
    hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (LPVOID*)&pShellLink);
    if (SUCCEEDED(hr)) {
        IPersistFile* pPersistFile = NULL;
        hr = pShellLink->QueryInterface(IID_IPersistFile, (LPVOID*)&pPersistFile);
        if (SUCCEEDED(hr)) {
            hr = pPersistFile->Load(inputPath.c_str(), STGM_READ);
            if (SUCCEEDED(hr)) {
                pShellLink->Resolve(NULL, SLR_NO_UI | SLR_ANY_MATCH);
                wchar_t targetPath[MAX_PATH] = { 0 };
                hr = pShellLink->GetPath(targetPath, MAX_PATH, NULL, SLGP_RAWPATH);
                if (SUCCEEDED(hr)) resolvedPath = targetPath;
            }
            pPersistFile->Release();
        }
        pShellLink->Release();
    }
    CoUninitialize();
    return resolvedPath;
}

int main(int argc, char* argv[])
{
    if (argc != 2) {
        printf("Usage: %s [path to executable or shortcut]\n", argv[0]);
        return 1;
    }

    string ansiPath = argv[1];
    wstring wstrPath(ansiPath.begin(), ansiPath.end());
    wstring realTargetWStr = ResolveShortcut(wstrPath);
    string realTargetAnsi(realTargetWStr.begin(), realTargetWStr.end());

    vector<char> targetNameBuffer(realTargetAnsi.begin(), realTargetAnsi.end());
    targetNameBuffer.push_back('\0');

    FILE* PpeFile = nullptr;
    fopen_s(&PpeFile, targetNameBuffer.data(), "rb");
    if (PpeFile == nullptr) {
        printf("Can't open file: %s\n", targetNameBuffer.data());
        return 1;
    }

    IMAGE_DOS_HEADER dosHdr;
    WORD magicOptional = 0;
    fseek(PpeFile, 0, SEEK_SET);
    fread(&dosHdr, sizeof(IMAGE_DOS_HEADER), 1, PpeFile);

    if (dosHdr.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Error. Not a valid PE file format.\n");
        fclose(PpeFile);
        return 1;
    }

    int offsetMagic = dosHdr.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    fseek(PpeFile, offsetMagic, SEEK_SET);
    fread(&magicOptional, sizeof(WORD), 1, PpeFile);

    // Kích hoạt sinh mã Template tự động vừa khít cho ranh giới byte ảo của từng cấu trúc
    if (magicOptional == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        printf(" Binary mode PE32 (32-bit) detected.\n");
        PEParserEngine<IMAGE_NT_HEADERS32, ILT_ENTRY_32> engine32(targetNameBuffer.data(), PpeFile);
        engine32.PrintInfo();
    }
    else if (magicOptional == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        printf(" Binary mode PE32+ (64-bit) detected.\n");
        PEParserEngine<IMAGE_NT_HEADERS64, ILT_ENTRY_64> engine64(targetNameBuffer.data(), PpeFile);
        engine64.PrintInfo();
    }
    else {
        printf("Error: Unknown Optional Header Magic structure.\n");
    }

    fclose(PpeFile);
    return 0;
}