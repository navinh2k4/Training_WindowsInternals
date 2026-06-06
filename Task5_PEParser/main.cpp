#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <windows.h>
#include <shobjidl.h> // Interface phân giải shortcut hệ thống
#include <shlguid.h>
#include "winntdef.h"
#include "PE64FILE.h"
#include "PE32FILE.h" // Nhập khẩu lớp đối tượng xử lý 32-bit mới

using namespace std;

// Hàm phân giải shortcut (.lnk) bóc tách đường dẫn .exe thực tế
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
                if (SUCCEEDED(hr)) {
                    resolvedPath = targetPath;
                }
            }
            pPersistFile->Release();
        }
        pShellLink->Release();
    }
    CoUninitialize();
    return resolvedPath;
}

// Kiểm tra chữ ký DOS Signature và phân rã Magic xác định bitness hệ thống
int INITPARSE(FILE* PpeFile) {
    IMAGE_DOS_HEADER TMP_DOS_HEADER;
    WORD PEFILE_TYPE;

    fseek(PpeFile, 0, SEEK_SET);
    fread(&TMP_DOS_HEADER, sizeof(IMAGE_DOS_HEADER), 1, PpeFile);

    // Sử dụng hằng số tiêu chuẩn Windows SDK để bẻ gãy lỗi C2065
    if (TMP_DOS_HEADER.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Error. Not a PE file.\n");
        return 1;
    }

    // Sửa dứt điểm lỗi thiếu tham số hãm fseek (Thêm cờ SEEK_SET)
    int offset = TMP_DOS_HEADER.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    fseek(PpeFile, offset, SEEK_SET);
    fread(&PEFILE_TYPE, sizeof(WORD), 1, PpeFile);

    if (PEFILE_TYPE == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        return 32;
    }
    else if (PEFILE_TYPE == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return 64;
    }
    else {
        printf("Error while parsing IMAGE_OPTIONAL_HEADER.Magic. Unknown Type.\n");
        return 1;
    }
}

int main(int argc, char* argv[])
{
    if (argc != 2) {
        printf("Usage: %s [path to executable or shortcut]\n", argv[0]);
        return 1;
    }

    // Chuyển đổi an toàn từ chuỗi dòng lệnh ANSI sang Unicode Wide-char phục vụ hàm COM
    string ansiPath = argv[1];
    wstring wstrPath(ansiPath.begin(), ansiPath.end());

    // Kéo xuyên qua lớp vỏ shortcut .lnk để lấy link file gốc .exe thật kịch trần
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

    int mode = INITPARSE(PpeFile);
    if (mode == 1) {
        fclose(PpeFile);
        exit(1);
    }
    // Tự động điều phối khởi tạo vùng nhớ 32-bit bóc tách Zalo.exe thô nguyên bản
    else if (mode == 32) {
        printf(" Binary mode PE32 (32-bit) detected.\n");
        PE32FILE PeFile_32(targetNameBuffer.data(), PpeFile);
        PeFile_32.PrintInfo();
        fclose(PpeFile);
        exit(0);
    }
    // Tự động điều phối khởi tạo vùng nhớ 64-bit bóc tách file nghiên cứu hệ thống x64
    else if (mode == 64) {
        PE64FILE PeFile_1(targetNameBuffer.data(), PpeFile);
        PeFile_1.PrintInfo();
        fclose(PpeFile);
        exit(0);
    }

    return 0;
}