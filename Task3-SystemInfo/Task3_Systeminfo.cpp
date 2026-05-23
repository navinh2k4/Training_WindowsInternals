#include <winsock2.h>     
#include <windows.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <sstream>        
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <time.h>
#include <io.h>
#include <fcntl.h>
#include <intrin.h>       // Hỗ trợ lệnh __cpuid

#pragma comment(lib, "iphlpapi.lib") 
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

using namespace std;

// ========================================================================
// 1. TẦNG CẤU HÌNH ĐỊNH DẠNG (CONFIGURATION LAYER)
// ========================================================================
const int LABEL_WIDTH = 27;

typedef LONG(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

// Khai báo nguyên mẫu toàn bộ các hàm nguyên tử hệ thống theo chuẩn Researcher
wstring GetRawDynamicRegString(HKEY hKeyRoot, LPCWSTR subKey, LPCWSTR valueName);
DWORD GetRawRegDword(HKEY hKeyRoot, LPCWSTR subKey, LPCWSTR valueName);
wstring GetKernelVersionFromNtdll(const wstring& defaultBuild);
wstring GetRawComputerName();
wstring GetRawEnvironmentVariable(LPCWSTR varName);
wstring GetRawSystemDirectory();
wstring GetRawWindowsDirectory();
wstring GetRawBootDevice();
wstring GetRawDomainName();

bool ExtractCpuVirtualization();
bool ExtractCpuSlat();
bool ExtractCpuDep();
bool ExtractFirmwareVirtualization();

wstring InterpretArcPathToDevice(const wstring& arcPath);
wstring FormatUnixTimestamp(time_t rawTime);
wstring CalculateSystemBootTime();
wstring ConvertMemoryToString(ULONGLONG bytes);
wstring TranslateOSConfiguration(const wstring& productType);
wstring FormatCliLabel(const wstring& label);

void PrintSystemRow(const wstring& label, const wstring& value);
void PrintProcessorHeader();
void PrintProcessorRow(int index, const wstring& cpuName);
void PrintDirectoryRow(const wstring& winDir, const wstring& sysDir, const wstring& bootDevice, const wstring& sysLocale, const wstring& logonServer);
void PrintNetworkHeader(int totalCards);
void PrintNetworkCardDetails(int index, const wstring& desc, const wstring& connName, bool dhcp);
void PrintNetworkIpRow(int ipIndex, const wstring& ipAddr);
void PrintHyperVHeader();
void PrintHyperVRow(const wstring& propertyName, bool supported);

void ExecuteHostNameSieve();
void ExecuteOSDetailsSieve();
void ExecuteSystemDatesSieve();
void ExecuteHardwareSieve();
void ExecuteDirectoriesSieve();
void ExecuteTimeZoneSieve();
void ExecuteMemorySieve();
void ExecuteDomainSieve();
void ExecuteNetworkSieve();
void ExecuteHyperVSieve();

// ========================================================================
// MỤC LỤC ĐIỀU KHIỂN CHÍNH (MAIN LAYER)
// ========================================================================
int main() {
    if (_setmode(_fileno(stdout), _O_U16TEXT) != -1) {
        wcout << L"\n";
        ExecuteHostNameSieve();
        ExecuteOSDetailsSieve();
        ExecuteSystemDatesSieve();
        ExecuteHardwareSieve();
        ExecuteDirectoriesSieve();
        ExecuteTimeZoneSieve();
        ExecuteMemorySieve();
        ExecuteDomainSieve();
        ExecuteNetworkSieve();
        ExecuteHyperVSieve();
        wcout << L"\n";
    }
    return 0;
}

// ========================================================================
// 2. TẦNG TRÍCH XUẤT DỮ LIỆU THÔ (LOW-LEVEL EXTRACTORS)
// ========================================================================
wstring GetRawDynamicRegString(HKEY hKeyRoot, LPCWSTR subKey, LPCWSTR valueName) {
    HKEY hKey;
    wstring result = L"N/A";
    if (RegOpenKeyExW(hKeyRoot, subKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD cbData = 0, type = 0;
        if (RegQueryValueExW(hKey, valueName, NULL, &type, NULL, &cbData) == ERROR_SUCCESS && cbData > 0) {
            vector<BYTE> memoryBuffer(cbData);
            if (RegQueryValueExW(hKey, valueName, NULL, NULL, memoryBuffer.data(), &cbData) == ERROR_SUCCESS) {
                if (type == REG_SZ || type == REG_EXPAND_SZ) {
                    result = reinterpret_cast<wchar_t*>(memoryBuffer.data());
                }
                else if (type == REG_MULTI_SZ) {
                    wchar_t* rawStrings = reinterpret_cast<wchar_t*>(memoryBuffer.data());
                    if (rawStrings && wcslen(rawStrings) > 0) result = rawStrings;
                }
            }
        }
        RegCloseKey(hKey);
    }
    return result;
}

DWORD GetRawRegDword(HKEY hKeyRoot, LPCWSTR subKey, LPCWSTR valueName) {
    HKEY hKey;
    DWORD result = 0;
    if (RegOpenKeyExW(hKeyRoot, subKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD cbData = sizeof(DWORD);
        RegQueryValueExW(hKey, valueName, NULL, NULL, reinterpret_cast<LPBYTE>(&result), &cbData);
        RegCloseKey(hKey);
    }
    return result;
}

wstring GetKernelVersionFromNtdll(const wstring& defaultBuild) {
    HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
    if (hMod) {
        RtlGetVersionPtr fn = (RtlGetVersionPtr)GetProcAddress(hMod, "RtlGetVersion");
        RTL_OSVERSIONINFOW info = { 0 };
        info.dwOSVersionInfoSize = sizeof(info);
        if (fn && fn(&info) == 0) {
            return to_wstring(info.dwMajorVersion) + L"." + to_wstring(info.dwMinorVersion) + L"." + to_wstring(info.dwBuildNumber);
        }
    }
    return L"10.0." + defaultBuild;
}

wstring GetRawComputerName() {
    WCHAR hostname[256] = { 0 };
    DWORD size = sizeof(hostname) / sizeof(hostname[0]);
    return GetComputerNameW(hostname, &size) ? wstring(hostname) : L"N/A";
}

wstring GetRawEnvironmentVariable(LPCWSTR varName) {
    WCHAR buffer[256] = { 0 };
    return GetEnvironmentVariableW(varName, buffer, 256) > 0 ? wstring(buffer) : L"N/A";
}

wstring GetRawSystemDirectory() {
    WCHAR sysDir[MAX_PATH] = { 0 };
    return GetSystemDirectoryW(sysDir, MAX_PATH) > 0 ? wstring(sysDir) : L"N/A";
}

wstring GetRawWindowsDirectory() {
    WCHAR winDir[MAX_PATH] = { 0 };
    return GetWindowsDirectoryW(winDir, MAX_PATH) > 0 ? wstring(winDir) : L"N/A";
}

wstring GetRawBootDevice() {
    wstring bootDevice = GetRawDynamicRegString(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control", L"FirmwareBootDevice");
    if (bootDevice == L"N/A" || bootDevice.empty()) {
        bootDevice = GetRawDynamicRegString(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control", L"BootDevice");
    }
    return bootDevice;
}

wstring GetRawDomainName() {
    WCHAR domain[256] = { 0 };
    DWORD size = sizeof(domain) / sizeof(domain[0]);
    if (GetComputerNameExW(ComputerNameDnsDomain, domain, &size) && wcslen(domain) > 0) {
        return wstring(domain);
    }
    return L"WORKGROUP";
}

bool ExtractCpuVirtualization() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 5)) != 0;
}

bool ExtractCpuSlat() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0x80000001);
    return (cpuInfo[3] & (1 << 6)) != 0;
}

bool ExtractCpuDep() {
    return IsProcessorFeaturePresent(PF_NX_ENABLED) != FALSE;
}

bool ExtractFirmwareVirtualization() {
    DWORD value = GetRawRegDword(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", L"FeatureSet");
    return (value & (1 << 5)) != 0;
}

// ========================================================================
// 3. TẦNG THÔNG DỊCH VÀ CHUYỂN ĐỔI (INTERPRETERS & LOGIC)
// ========================================================================
wstring InterpretArcPathToDevice(const wstring& arcPath) {
    if (arcPath.find(L"\\Device\\") != wstring::npos) {
        return arcPath;
    }
    size_t partPos = arcPath.find(L"partition(");
    if (partPos != wstring::npos) {
        size_t startIdx = partPos + 10;
        size_t endIdx = arcPath.find(L")", startIdx);
        if (endIdx != wstring::npos) {
            wstring partitionNumber = arcPath.substr(startIdx, endIdx - startIdx);
            return L"\\Device\\HarddiskVolume" + partitionNumber;
        }
    }
    return arcPath;
}

wstring FormatUnixTimestamp(time_t rawTime) {
    tm local_tm;
    if (localtime_s(&local_tm, &rawTime) == 0) {
        wstringstream wss;
        wss << put_time(&local_tm, L"%m/%d/%Y, %I:%M:%S %p");
        return wss.str();
    }
    return L"N/A";
}

wstring CalculateSystemBootTime() {
    ULONGLONG upTimeMS = GetTickCount64();
    time_t now = time(NULL);
    return FormatUnixTimestamp(now - (upTimeMS / 1000));
}

wstring ConvertMemoryToString(ULONGLONG bytes) {
    wstringstream wss;
    wss << (bytes / (1024 * 1024)) << L" MB";
    return wss.str();
}

wstring TranslateOSConfiguration(const wstring& productType) {
    if (productType == L"ServerNT") return L"Server";
    if (productType == L"LanmanNT") return L"Domain Controller";
    return L"Standalone Workstation";
}

wstring FormatCliLabel(const wstring& label) {
    wstringstream wss;
    wss << left << setw(LABEL_WIDTH) << label;
    return wss.str();
}

// ========================================================================
// 4. TẦNG HIỂN THỊ CLI THUẦN TÚY (ATOMIC PRESENTATION LAYER)
// ========================================================================
void PrintSystemRow(const wstring& label, const wstring& value) {
    wcout << FormatCliLabel(label) << value << endl;
}

void PrintProcessorHeader() {
    wcout << FormatCliLabel(L"Processor(s):") << L"1 Processor(s) Installed." << endl;
}

void PrintProcessorRow(int index, const wstring& cpuName) {
    wcout << setw(31) << L"" << L"[" << setfill(L'0') << setw(2) << index << L"]: " << setfill(L' ') << cpuName << endl;
}

void PrintDirectoryRow(const wstring& winDir, const wstring& sysDir, const wstring& bootDevice, const wstring& sysLocale, const wstring& logonServer) {
    PrintSystemRow(L"Windows Directory:", winDir);
    PrintSystemRow(L"System Directory:", sysDir);
    PrintSystemRow(L"Boot Device:", bootDevice);
    PrintSystemRow(L"System Locale:", sysLocale);
    PrintSystemRow(L"Input Locale:", sysLocale);
    PrintSystemRow(L"Logon Server:", logonServer);
}

void PrintNetworkHeader(int totalCards) {
    wcout << FormatCliLabel(L"Network Card(s):") << totalCards << L" NIC(s) Installed." << endl;
}

void PrintNetworkCardDetails(int index, const wstring& desc, const wstring& connName, bool dhcp) {
    wcout << setw(31) << L"" << L"[" << setfill(L'0') << setw(2) << index << L"]: " << setfill(L' ') << desc << endl;
    wcout << setw(36) << L"" << L"Connection Name: " << connName << endl;
    wcout << setw(36) << L"" << L"DHCP Enabled:    " << (dhcp ? L"Yes" : L"No") << endl;
}

void PrintNetworkIpRow(int ipIndex, const wstring& ipAddr) {
    wcout << setw(36) << L"" << L"[" << setfill(L'0') << setw(2) << ipIndex << L"]: " << setfill(L' ') << ipAddr << endl;
}

void PrintHyperVHeader() {
    wcout << L"Hyper-V Requirements:" << endl;
}

void PrintHyperVRow(const wstring& propertyName, bool supported) {
    wcout << setw(35) << L"" << propertyName << L": " << (supported ? L"Yes" : L"No") << endl;
}

// ========================================================================
// 5. TẦNG ĐIỀU PHỐI CHỨC NĂNG TRUNG GIAN (SIEVE & CONTROLLER)
// ========================================================================
void ExecuteHostNameSieve() {
    PrintSystemRow(L"Host Name:", GetRawComputerName());
}

void ExecuteOSDetailsSieve() {
    LPCWSTR ntKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    wstring osName = GetRawDynamicRegString(HKEY_LOCAL_MACHINE, ntKey, L"ProductName");
    wstring currentBuild = GetRawDynamicRegString(HKEY_LOCAL_MACHINE, ntKey, L"CurrentBuild");
    wstring productType = GetRawDynamicRegString(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\ProductOptions", L"ProductType");

    wstring osVersion = GetKernelVersionFromNtdll(currentBuild);
    if (currentBuild >= L"22000" && osName.find(L"Windows 10") != wstring::npos) {
        osName.replace(osName.find(L"Windows 10"), 10, L"Windows 11");
    }

    PrintSystemRow(L"OS Name:", osName);
    PrintSystemRow(L"OS Version:", osVersion + L" N/A Build " + currentBuild);
    PrintSystemRow(L"OS Manufacturer:", L"Microsoft Corporation");
    PrintSystemRow(L"OS Configuration:", TranslateOSConfiguration(productType));
    PrintSystemRow(L"OS Build Type:", L"Multiprocessor Free");
    PrintSystemRow(L"Registered Owner:", GetRawDynamicRegString(HKEY_LOCAL_MACHINE, ntKey, L"RegisteredOwner"));
    PrintSystemRow(L"Registered Organization:", GetRawDynamicRegString(HKEY_LOCAL_MACHINE, ntKey, L"RegisteredOrganization"));
    PrintSystemRow(L"Product ID:", GetRawDynamicRegString(HKEY_LOCAL_MACHINE, ntKey, L"ProductId"));
}

void ExecuteSystemDatesSieve() {
    time_t installTimestamp = GetRawRegDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"InstallDate");
    PrintSystemRow(L"Original Install Date:", FormatUnixTimestamp(installTimestamp));
    PrintSystemRow(L"System Boot Time:", CalculateSystemBootTime());
}

void ExecuteHardwareSieve() {
    LPCWSTR biosKey = L"HARDWARE\\DESCRIPTION\\System\\BIOS";
    wstring vendor = GetRawDynamicRegString(HKEY_LOCAL_MACHINE, biosKey, L"BIOSVendor");
    wstring version = GetRawDynamicRegString(HKEY_LOCAL_MACHINE, biosKey, L"BIOSVersion");
    wstring releaseDate = GetRawDynamicRegString(HKEY_LOCAL_MACHINE, biosKey, L"BIOSReleaseDate");
    wstring cpuName = GetRawDynamicRegString(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", L"ProcessorNameString");

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    wstring sysType = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) ? L"x86-based PC" : L"x64-based PC";

    PrintSystemRow(L"System Manufacturer:", GetRawDynamicRegString(HKEY_LOCAL_MACHINE, biosKey, L"SystemManufacturer"));
    PrintSystemRow(L"System Model:", GetRawDynamicRegString(HKEY_LOCAL_MACHINE, biosKey, L"SystemProductName"));
    PrintSystemRow(L"System Type:", sysType);

    PrintProcessorHeader();
    PrintProcessorRow(1, cpuName);
    PrintSystemRow(L"BIOS Version:", vendor + L" " + version + L", " + releaseDate);
}

void ExecuteDirectoriesSieve() {
    wstring winDir = GetRawWindowsDirectory();
    wstring sysDir = GetRawSystemDirectory();
    wstring rawBoot = GetRawBootDevice();
    wstring cleanBootDevice = InterpretArcPathToDevice(rawBoot);

    wstring sysLocale = GetRawDynamicRegString(HKEY_CURRENT_USER, L"Control Panel\\International", L"LocaleName");
    wstring logonServer = GetRawEnvironmentVariable(L"LOGONSERVER");

    PrintDirectoryRow(winDir, sysDir, cleanBootDevice, sysLocale, logonServer);
}

void ExecuteTimeZoneSieve() {
    TIME_ZONE_INFORMATION tzi;
    wstring zoneName = L"N/A";
    if (GetTimeZoneInformation(&tzi) != TIME_ZONE_ID_INVALID) zoneName = tzi.StandardName;
    PrintSystemRow(L"Time Zone:", zoneName);
}

void ExecuteMemorySieve() {
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    if (GlobalMemoryStatusEx(&statex)) {
        PrintSystemRow(L"Total Physical Memory:", ConvertMemoryToString(statex.ullTotalPhys));
        PrintSystemRow(L"Available Physical Memory:", ConvertMemoryToString(statex.ullAvailPhys));
        PrintSystemRow(L"Virtual Memory: Max Size:", ConvertMemoryToString(statex.ullTotalPageFile));
        PrintSystemRow(L"Virtual Memory: Available:", ConvertMemoryToString(statex.ullAvailPageFile));
        PrintSystemRow(L"Virtual Memory: In Use:", ConvertMemoryToString(statex.ullTotalPageFile - statex.ullAvailPageFile));
    }
    wstring pageFile = GetRawDynamicRegString(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", L"PagingFiles");
    PrintSystemRow(L"Page File Location(s):", pageFile);
}

void ExecuteDomainSieve() {
    PrintSystemRow(L"Domain:", GetRawDomainName());
}

void ExecuteNetworkSieve() {
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
    if (!pAddresses) return;

    ULONG ret = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAddresses, &outBufLen);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
        if (!pAddresses) return;
        ret = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAddresses, &outBufLen);
    }

    if (ret == NO_ERROR) {
        int totalAdapters = 0;
        for (PIP_ADAPTER_ADDRESSES c = pAddresses; c; c = c->Next) totalAdapters++;
        PrintNetworkHeader(totalAdapters);

        PIP_ADAPTER_ADDRESSES curr = pAddresses;
        int idx = 1;
        while (curr) {
            bool isDhcp = (curr->Flags & IP_ADAPTER_DHCP_ENABLED) != 0;
            PrintNetworkCardDetails(idx, curr->Description, curr->FriendlyName, isDhcp);

            PIP_ADAPTER_UNICAST_ADDRESS pUnicast = curr->FirstUnicastAddress;
            if (pUnicast) {
                wcout << setw(36) << L"" << L"IP address(es)" << endl;
                int ipIdx = 1;
                while (pUnicast) {
                    char buf[INET6_ADDRSTRLEN] = { 0 };
                    SOCKADDR* addr = pUnicast->Address.lpSockaddr;
                    if (addr->sa_family == AF_INET) {
                        inet_ntop(AF_INET, &(reinterpret_cast<sockaddr_in*>(addr)->sin_addr), buf, INET_ADDRSTRLEN);
                    }
                    else if (addr->sa_family == AF_INET6) {
                        inet_ntop(AF_INET6, &(reinterpret_cast<sockaddr_in6*>(addr)->sin6_addr), buf, INET6_ADDRSTRLEN);
                    }

                    wchar_t wBuf[INET6_ADDRSTRLEN];
                    size_t outSize;
                    mbstowcs_s(&outSize, wBuf, buf, INET6_ADDRSTRLEN);

                    PrintNetworkIpRow(ipIdx, wBuf);
                    pUnicast = pUnicast->Next;
                    ipIdx++;
                }
            }
            curr = curr->Next;
            idx++;
        }
    }
    free(pAddresses);
}

void ExecuteHyperVSieve() {
    PrintHyperVHeader();
    PrintHyperVRow(L"VM Monitor Mode Extensions", ExtractCpuVirtualization());
    PrintHyperVRow(L"Virtualization Enabled In Firmware", ExtractFirmwareVirtualization());
    PrintHyperVRow(L"Second Level Address Translation", ExtractCpuSlat());
    PrintHyperVRow(L"Data Execution Prevention Available", ExtractCpuDep());
}