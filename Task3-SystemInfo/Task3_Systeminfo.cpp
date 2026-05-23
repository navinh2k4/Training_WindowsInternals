#include <winsock2.h>     // BẮT BUỘC: Phải đứng trước iphlpapi.h
#include <windows.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
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

const int LABEL_WIDTH = 27; // Độ rộng lề chuẩn 27 ký tự của systeminfo gốc

typedef LONG(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

// ========================================================================
// HÀM HELPER: Đọc Registry Đa Kiểu Chuỗi (Hỗ trợ cả REG_SZ và REG_MULTI_SZ)
// ========================================================================
wstring GetRegString(HKEY hKeyRoot, LPCWSTR subKey, LPCWSTR valueName) {
    WCHAR buffer[512] = { 0 };
    DWORD size = sizeof(buffer);
    // Cho phép đọc cả REG_SZ và REG_MULTI_SZ để tránh lỗi N/A trên một số máy
    if (RegGetValueW(hKeyRoot, subKey, valueName, RRF_RT_REG_SZ | RRF_RT_REG_MULTI_SZ, NULL, buffer, &size) == ERROR_SUCCESS) {
        return wstring(buffer);
    }
    return L"N/A";
}

// ========================================================================
// 1. HOST NAME
// ========================================================================
void PrintHostName() {
    WCHAR hostname[256] = { 0 };
    DWORD size = sizeof(hostname) / sizeof(hostname[0]);
    if (GetComputerNameW(hostname, &size)) {
        wcout << left << setw(LABEL_WIDTH) << L"Host Name:" << hostname << endl;
    }
}

// ========================================================================
// 2. OS DETAILS
// ========================================================================
void PrintOSDetails() {
    LPCWSTR ntKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    wstring osName = GetRegString(HKEY_LOCAL_MACHINE, ntKey, L"ProductName");
    wstring buildLab = GetRegString(HKEY_LOCAL_MACHINE, ntKey, L"BuildLabEx");
    wstring currentBuild = GetRegString(HKEY_LOCAL_MACHINE, ntKey, L"CurrentBuild");
    wstring registeredOwner = GetRegString(HKEY_LOCAL_MACHINE, ntKey, L"RegisteredOwner");
    wstring registeredOrg = GetRegString(HKEY_LOCAL_MACHINE, ntKey, L"RegisteredOrganization");
    wstring productId = GetRegString(HKEY_LOCAL_MACHINE, ntKey, L"ProductId");

    HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
    if (hMod) {
        RtlGetVersionPtr fn = (RtlGetVersionPtr)GetProcAddress(hMod, "RtlGetVersion");
        RTL_OSVERSIONINFOW info = { 0 };
        info.dwOSVersionInfoSize = sizeof(info);
        if (fn && fn(&info) == 0) {
            if (info.dwBuildNumber >= 22000 && osName.find(L"Windows 10") != wstring::npos) {
                osName.replace(osName.find(L"Windows 10"), 10, L"Windows 11");
            }
        }
    }

    wstring config = L"Standalone Workstation";
    wstring productType = GetRegString(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\ProductOptions", L"ProductType");
    if (productType == L"ServerNT") config = L"Server";
    else if (productType == L"LanmanNT") config = L"Domain Controller";

    wcout << left << setw(LABEL_WIDTH) << L"OS Name:" << osName << endl;
    wcout << left << setw(LABEL_WIDTH) << L"OS Version:" << currentBuild << L" N/A Build " << currentBuild << endl;
    wcout << left << setw(LABEL_WIDTH) << L"OS Manufacturer:" << L"Microsoft Corporation" << endl;
    wcout << left << setw(LABEL_WIDTH) << L"OS Configuration:" << config << endl;
    wcout << left << setw(LABEL_WIDTH) << L"OS Build Type:" << L"Multiprocessor Free" << endl;
    wcout << left << setw(LABEL_WIDTH) << L"Registered Owner:" << registeredOwner << endl;
    wcout << left << setw(LABEL_WIDTH) << L"Registered Organization:" << registeredOrg << endl;
    wcout << left << setw(LABEL_WIDTH) << L"Product ID:" << productId << endl;
}

// ========================================================================
// 3. DATES (Install Date & System Boot Time)
// ========================================================================
void PrintSystemDates() {
    HKEY hKey;
    DWORD installDate = 0;
    DWORD size = sizeof(installDate);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegGetValueW(hKey, NULL, L"InstallDate", RRF_RT_REG_DWORD, NULL, &installDate, &size) == ERROR_SUCCESS) {
            time_t t = (time_t)installDate;
            tm local_tm;
            localtime_s(&local_tm, &t);
            wcout << left << setw(LABEL_WIDTH) << L"Original Install Date:" << put_time(&local_tm, L"%m/%d/%Y, %I:%M:%S %p") << endl;
        }
        RegCloseKey(hKey);
    }

    // Tính toán System Boot Time bằng toán học Kernel (Thời gian thực hiện tại - Uptime)
    ULONGLONG upTimeMS = GetTickCount64();
    time_t now = time(NULL);
    time_t bootTime = now - (upTimeMS / 1000);
    tm boot_tm;
    localtime_s(&boot_tm, &bootTime);
    wcout << left << setw(LABEL_WIDTH) << L"System Boot Time:" << put_time(&boot_tm, L"%m/%d/%Y, %I:%M:%S %p") << endl;
}

// ========================================================================
// 4. HARDWARE DETAILS
// ========================================================================
void PrintHardwareDetails() {
    LPCWSTR biosKey = L"HARDWARE\\DESCRIPTION\\System\\BIOS";
    wstring manufacturer = GetRegString(HKEY_LOCAL_MACHINE, biosKey, L"SystemManufacturer");
    wstring model = GetRegString(HKEY_LOCAL_MACHINE, biosKey, L"SystemProductName");
    wstring biosVendor = GetRegString(HKEY_LOCAL_MACHINE, biosKey, L"BIOSVendor");
    wstring biosVersion = GetRegString(HKEY_LOCAL_MACHINE, biosKey, L"BIOSVersion");
    wstring biosDate = GetRegString(HKEY_LOCAL_MACHINE, biosKey, L"BIOSReleaseDate");
    wstring cpuName = GetRegString(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", L"ProcessorNameString");

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    wstring sysType = L"x64-based PC";
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) sysType = L"x86-based PC";

    wcout << left << setw(LABEL_WIDTH) << L"System Manufacturer:" << manufacturer << endl;
    wcout << left << setw(LABEL_WIDTH) << L"System Model:" << model << endl;
    wcout << left << setw(LABEL_WIDTH) << L"System Type:" << sysType << endl;
    wcout << left << setw(LABEL_WIDTH) << L"Processor(s):" << L"1 Processor(s) Installed." << endl;
    wcout << L"                               [01]: " << cpuName << endl;
    wcout << left << setw(LABEL_WIDTH) << L"BIOS Version:" << biosVendor << L" " << biosVersion << L", " << biosDate << endl;
}

// ========================================================================
// 5. ENVIRONMENT & DIRECTORIES
// ========================================================================
void PrintDirectories() {
    WCHAR winDir[MAX_PATH], sysDir[MAX_PATH], logonServer[256];
    GetWindowsDirectoryW(winDir, MAX_PATH);
    GetSystemDirectoryW(sysDir, MAX_PATH);
    GetEnvironmentVariableW(L"LOGONSERVER", logonServer, 256);

    wstring bootDevice = GetRegString(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control", L"BootDevice");
    wstring sysLocale = GetRegString(HKEY_CURRENT_USER, L"Control Panel\\International", L"LocaleName");

    wcout << left << setw(LABEL_WIDTH) << L"Windows Directory:" << winDir << endl;
    wcout << left << setw(LABEL_WIDTH) << L"System Directory:" << sysDir << endl;
    wcout << left << setw(LABEL_WIDTH) << L"Boot Device:" << bootDevice << endl;
    wcout << left << setw(LABEL_WIDTH) << L"System Locale:" << sysLocale << endl;
    wcout << left << setw(LABEL_WIDTH) << L"Input Locale:" << sysLocale << endl;
    wcout << left << setw(LABEL_WIDTH) << L"Logon Server:" << logonServer << endl;
}

// ========================================================================
// 6. TIME ZONE
// ========================================================================
void PrintTimeZone() {
    wstring tzName = GetRegString(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation", L"TimeZoneKeyName");
    wcout << left << setw(LABEL_WIDTH) << L"Time Zone:" << tzName << endl;
}

// ========================================================================
// 7. MEMORY DETAILS & PAGE FILE
// ========================================================================
void PrintMemoryDetails() {
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    if (GlobalMemoryStatusEx(&statex)) {
        wcout << left << setw(LABEL_WIDTH) << L"Total Physical Memory:" << statex.ullTotalPhys / (1024 * 1024) << L" MB" << endl;
        wcout << left << setw(LABEL_WIDTH) << L"Available Physical Memory:" << statex.ullAvailPhys / (1024 * 1024) << L" MB" << endl;
        wcout << left << setw(LABEL_WIDTH) << L"Virtual Memory: Max Size:" << statex.ullTotalPageFile / (1024 * 1024) << L" MB" << endl;
        wcout << left << setw(LABEL_WIDTH) << L"Virtual Memory: Available:" << statex.ullAvailPageFile / (1024 * 1024) << L" MB" << endl;
        wcout << left << setw(LABEL_WIDTH) << L"Virtual Memory: In Use:" << (statex.ullTotalPageFile - statex.ullAvailPageFile) / (1024 * 1024) << L" MB" << endl;
    }
    wstring pageFile = GetRegString(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", L"PagingFiles");
    size_t pos = pageFile.find(L" ");
    if (pos != wstring::npos) pageFile = pageFile.substr(0, pos);
    wcout << left << setw(LABEL_WIDTH) << L"Page File Location(s):" << pageFile << endl;
}

// ========================================================================
// 8. DOMAIN
// ========================================================================
void PrintDomainDetails() {
    WCHAR domain[256] = { 0 };
    DWORD size = sizeof(domain) / sizeof(domain[0]);
    if (GetComputerNameExW(ComputerNameDnsDomain, domain, &size) && wcslen(domain) > 0) {
        wcout << left << setw(LABEL_WIDTH) << L"Domain:" << domain << endl;
    }
    else {
        wcout << left << setw(LABEL_WIDTH) << L"Domain:" << L"WORKGROUP" << endl;
    }
}

// ========================================================================
// 9. NETWORK ADAPTERS
// ========================================================================
void PrintNetworkAdapters() {
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
        wcout << left << setw(LABEL_WIDTH) << L"Network Card(s):" << totalAdapters << L" NIC(s) Installed." << endl;

        PIP_ADAPTER_ADDRESSES curr = pAddresses;
        int idx = 1;
        while (curr) {
            wcout << L"                               [" << (idx < 10 ? L"0" : L"") << idx << L"]: " << curr->Description << endl;
            wcout << L"                                     Connection Name: " << curr->FriendlyName << endl;
            wcout << L"                                     DHCP Enabled:    " << ((curr->Flags & IP_ADAPTER_DHCP_ENABLED) ? L"Yes" : L"No") << endl;

            PIP_ADAPTER_UNICAST_ADDRESS pUnicast = curr->FirstUnicastAddress;
            if (pUnicast) {
                wcout << L"                                     IP address(es)" << endl;
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

                    // Khắc phục lỗi lệch lề: IP được căn thẳng hàng tuyệt đối với lề con
                    wcout << L"                                     [" << (ipIdx < 10 ? L"0" : L"") << ipIdx << L"]: " << wBuf << endl;
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

// ========================================================================
// 10. HYPER-V REQUIREMENTS
// ========================================================================
void PrintHyperVRequirements() {
    BOOL vmMonitorExtensions = FALSE, virtualizationEnabled = FALSE, slat = FALSE;
    BOOL dep = IsProcessorFeaturePresent(PF_NX_ENABLED);

#ifdef _M_X64
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    vmMonitorExtensions = (cpuInfo[2] & (1 << 5)) != 0;

    int cpuInfo2[4] = { 0 };
    __cpuid(cpuInfo2, 0x80000001);
    slat = (cpuInfo2[3] & (1 << 6)) != 0;
#endif

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD value = 0, size = sizeof(DWORD);
        if (RegGetValueW(hKey, L"", L"FeatureSet", RRF_RT_REG_DWORD, NULL, &value, &size) == ERROR_SUCCESS) {
            virtualizationEnabled = (value & (1 << 5)) != 0;
        }
        RegCloseKey(hKey);
    }

    wcout << L"Hyper-V Requirements:" << endl;
    wcout << L"                                   VM Monitor Mode Extensions: " << (vmMonitorExtensions ? L"Yes" : L"No") << endl;
    wcout << L"                                   Virtualization Enabled In Firmware: " << (virtualizationEnabled ? L"Yes" : L"No") << endl;
    wcout << L"                                   Second Level Address Translation: " << (slat ? L"Yes" : L"No") << endl;
    wcout << L"                                   Data Execution Prevention Available: " << (dep ? L"Yes" : L"No") << endl;
}

// ========================================================================
// MAIN
// ========================================================================
int main() {
    _setmode(_fileno(stdout), _O_U16TEXT);
    wcout << L"\n";

    PrintHostName();
    PrintOSDetails();
    PrintSystemDates();
    PrintHardwareDetails();
    PrintDirectories();
    PrintTimeZone();
    PrintMemoryDetails();
    PrintDomainDetails();
    PrintNetworkAdapters();
    PrintHyperVRequirements();

    wcout << L"\n";
    return 0;
}