#include <windows.h>
#include <winhttp.h>
#include <iostream>
#include <string>
#include <vector>
#include <io.h>
#include <fcntl.h>

#pragma comment(lib, "winhttp.lib")

struct Provider {
    std::wstring name;
    std::wstring host;
    std::wstring path;
    std::wstring headers;
    std::wstring payload;
    bool isPost;
    std::wstring jsonKey;
};

// Hàm ghi file UTF-8 chuẩn
void WriteUtf8(HANDLE hFile, const std::wstring& str) {
    int size = WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, NULL, 0, NULL, NULL);
    LPSTR buf = (LPSTR)HeapAlloc(GetProcessHeap(), 0, size);
    WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, buf, size, NULL, NULL);
    DWORD written;
    WriteFile(hFile, buf, size - 1, &written, NULL);
    HeapFree(GetProcessHeap(), 0, buf);
}

void ExecuteFetch(Provider p, HANDLE hFile) {
    HINTERNET hSession = WinHttpOpen(L"SimFetcher/9.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    HINTERNET hConnect = WinHttpConnect(hSession, p.host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, p.isPost ? L"POST" : L"GET", p.path.c_str(), NULL, NULL, NULL, WINHTTP_FLAG_SECURE);

    WinHttpAddRequestHeaders(hRequest, p.headers.c_str(), -1L, WINHTTP_ADDREQ_FLAG_ADD);

    std::string payloadA(p.payload.begin(), p.payload.end());
    if (WinHttpSendRequest(hRequest, NULL, 0, (LPVOID)payloadA.c_str(), (DWORD)payloadA.length(), (DWORD)payloadA.length(), 0) && WinHttpReceiveResponse(hRequest, NULL)) {
        DWORD dwSize = 0;
        WinHttpQueryDataAvailable(hRequest, &dwSize);
        LPSTR buffer = (LPSTR)HeapAlloc(GetProcessHeap(), 0, dwSize + 1);
        WinHttpReadData(hRequest, buffer, dwSize, &dwSize);
        buffer[dwSize] = 0;

        int wSize = MultiByteToWideChar(CP_UTF8, 0, buffer, -1, NULL, 0);
        std::vector<WCHAR> wBuffer(wSize);
        MultiByteToWideChar(CP_UTF8, 0, buffer, -1, wBuffer.data(), wSize);
        std::wstring content(wBuffer.data());

        // Parse: Tìm key của từng mạng
        size_t pos = 0;
        std::wstring key = L"\"" + p.jsonKey + L"\":\"";
        while ((pos = content.find(key, pos)) != std::wstring::npos) {
            pos += key.length();
            size_t end = content.find(L"\"", pos);
            std::wstring sim = content.substr(pos, end - pos);

            // Xử lý SIM thiếu số 0 đầu
            if (sim.length() == 9) sim = L"0" + sim;

            WriteUtf8(hFile, sim + L"\t" + p.name + L"\r\n");
            std::wcout << L"[" << p.name << L"] Found: " << sim << std::endl;
            pos = end;
        }
        HeapFree(GetProcessHeap(), 0, buffer);
    }
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

int wmain() {
    _setmode(_fileno(stdout), _O_U16TEXT);
    HANDLE hFile = CreateFileW(L"TongHop_SIM.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    // Cấu hình nhà mạng
    std::vector<Provider> providers = {
        // VNPT: Cần update 'Authentication' nếu bị từ chối
        { L"VNPT", L"digishop.vnpt.vn", L"/apiprod/v2/simso/num_search?prefix=8491", L"Authentication: 12b869009caa6232ffb299a39a62c051e375fcfcdf411b3b282afa2be927c540\r\nContent-Type: application/json\r\n", L"", false, L"msisdn" },

        // Mobifone: Lấy 078
        { L"Mobi", L"khosim.mobifone.vn", L"/api/sim/getPages", L"Content-Type: application/json\r\n", L"{\"msisdnPrefix\":\"078\",\"page\":0,\"size\":50}", true, L"msisdn" }
    };

    for (const auto& p : providers) {
        ExecuteFetch(p, hFile);
    }

    CloseHandle(hFile);
    std::wcout << L"Hoàn tất. Kiểm tra file TongHop_SIM.txt" << std::endl;
    return 0;
}