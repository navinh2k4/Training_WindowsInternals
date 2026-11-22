
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>

#include <fcntl.h>
#include <io.h>
#include <time.h>

#include <intrin.h>

#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

namespace {

constexpr int kLabelWidth = 27;
constexpr int kMaxAdapterAttempts = 4;

using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);

std::wstring get_raw_dynamic_reg_string(
    HKEY root_key,
    LPCWSTR sub_key,
    LPCWSTR value_name) {
  HKEY h_key = nullptr;
  if (::RegOpenKeyExW(root_key, sub_key, 0, KEY_READ, &h_key) != ERROR_SUCCESS ||
      h_key == nullptr) {
    return L"N/A";
  }

  DWORD cb_data = 0;
  DWORD reg_type = 0;
  std::wstring result = L"N/A";

  if (::RegQueryValueExW(
          h_key,
          value_name,
          nullptr,
          &reg_type,
          nullptr,
          &cb_data) == ERROR_SUCCESS &&
      cb_data > 0) {
    const std::size_t alloc_bytes = static_cast<std::size_t>(cb_data) + sizeof(wchar_t);
    BYTE* raw_buf = static_cast<BYTE*>(
        ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, alloc_bytes));
    if (raw_buf != nullptr) {
      DWORD io_bytes = cb_data;
      if (::RegQueryValueExW(
              h_key,
              value_name,
              nullptr,
              &reg_type,
              raw_buf,
              &io_bytes) == ERROR_SUCCESS) {
        if (reg_type == REG_SZ || reg_type == REG_EXPAND_SZ || reg_type == REG_MULTI_SZ) {
          const wchar_t* wstr_ptr = reinterpret_cast<const wchar_t*>(raw_buf);
          const std::size_t max_wchars = alloc_bytes / sizeof(wchar_t);
          std::size_t len = 0;
          while (len < max_wchars && wstr_ptr[len] != L'\0') {
            ++len;
          }
          if (len > 0) {
            result.assign(wstr_ptr, len);
          }
        }
      }
      ::HeapFree(::GetProcessHeap(), 0, raw_buf);
    }
  }

  ::RegCloseKey(h_key);
  return result;
}

DWORD get_raw_reg_dword(
    HKEY root_key,
    LPCWSTR sub_key,
    LPCWSTR value_name) noexcept {
  HKEY h_key = nullptr;
  DWORD value = 0;
  if (::RegOpenKeyExW(root_key, sub_key, 0, KEY_READ, &h_key) == ERROR_SUCCESS &&
      h_key != nullptr) {
    DWORD cb_data = static_cast<DWORD>(sizeof(DWORD));
    DWORD reg_type = 0;
    if (::RegQueryValueExW(
            h_key,
            value_name,
            nullptr,
            &reg_type,
            reinterpret_cast<LPBYTE>(&value),
            &cb_data) != ERROR_SUCCESS ||
        cb_data != sizeof(DWORD)) {
      value = 0;
    }
    ::RegCloseKey(h_key);
  }
  return value;
}

unsigned long parse_build_number_ul(const std::wstring& build_str) noexcept {
  if (build_str.empty()) {
    return 0;
  }
  unsigned long acc = 0;
  for (wchar_t ch : build_str) {
    if (ch < L'0' || ch > L'9') {
      break;
    }
    const unsigned long digit = static_cast<unsigned long>(ch - L'0');
    if (acc > (ULONG_MAX - digit) / 10UL) {
      return ULONG_MAX;
    }
    acc = acc * 10UL + digit;
  }
  return acc;
}

std::wstring get_kernel_version_from_ntdll(const std::wstring& default_build) {
  const HMODULE h_ntdll = ::GetModuleHandleW(L"ntdll.dll");
  if (h_ntdll != nullptr) {
    const FARPROC proc = ::GetProcAddress(h_ntdll, "RtlGetVersion");
    if (proc != nullptr) {
      RtlGetVersionFn fn = reinterpret_cast<RtlGetVersionFn>(proc);
      RTL_OSVERSIONINFOW info{};
      info.dwOSVersionInfoSize = static_cast<DWORD>(sizeof(info));
      if (fn(&info) == 0) {
        return std::to_wstring(info.dwMajorVersion) + L"." +
            std::to_wstring(info.dwMinorVersion) + L"." +
            std::to_wstring(info.dwBuildNumber);
      }
    }
  }
  return L"10.0." + default_build;
}

std::wstring get_raw_computer_name() {
  DWORD size = 0;
  ::GetComputerNameW(nullptr, &size);
  if (size == 0) {
    return L"N/A";
  }

  wchar_t* buf = static_cast<wchar_t*>(
      ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, static_cast<std::size_t>(size) * sizeof(wchar_t)));
  if (buf == nullptr) {
    return L"N/A";
  }

  std::wstring out = L"N/A";
  DWORD actual = size;
  if (::GetComputerNameW(buf, &actual) != FALSE && actual > 0) {
    out.assign(buf, static_cast<std::size_t>(actual));
  }

  ::HeapFree(::GetProcessHeap(), 0, buf);
  return out;
}

std::wstring get_raw_environment_variable(LPCWSTR var_name) {
  if (var_name == nullptr || var_name[0] == L'\0') {
    return L"N/A";
  }

  const DWORD needed = ::GetEnvironmentVariableW(var_name, nullptr, 0);
  if (needed == 0) {
    return L"N/A";
  }

  wchar_t* buf = static_cast<wchar_t*>(
      ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, static_cast<std::size_t>(needed) * sizeof(wchar_t)));
  if (buf == nullptr) {
    return L"N/A";
  }

  std::wstring out = L"N/A";
  const DWORD written = ::GetEnvironmentVariableW(var_name, buf, needed);
  if (written > 0 && written < needed) {
    out.assign(buf, static_cast<std::size_t>(written));
  }

  ::HeapFree(::GetProcessHeap(), 0, buf);
  return out;
}

std::wstring get_raw_system_directory() {
  const DWORD needed = ::GetSystemDirectoryW(nullptr, 0);
  if (needed == 0) {
    return L"N/A";
  }

  wchar_t* buf = static_cast<wchar_t*>(
      ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, static_cast<std::size_t>(needed) * sizeof(wchar_t)));
  if (buf == nullptr) {
    return L"N/A";
  }

  std::wstring out = L"N/A";
  const DWORD written = ::GetSystemDirectoryW(buf, needed);
  if (written > 0 && written < needed) {
    out.assign(buf, static_cast<std::size_t>(written));
  }

  ::HeapFree(::GetProcessHeap(), 0, buf);
  return out;
}

std::wstring get_raw_windows_directory() {
  const DWORD needed = ::GetWindowsDirectoryW(nullptr, 0);
  if (needed == 0) {
    return L"N/A";
  }

  wchar_t* buf = static_cast<wchar_t*>(
      ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, static_cast<std::size_t>(needed) * sizeof(wchar_t)));
  if (buf == nullptr) {
    return L"N/A";
  }

  std::wstring out = L"N/A";
  const DWORD written = ::GetWindowsDirectoryW(buf, needed);
  if (written > 0 && written < needed) {
    out.assign(buf, static_cast<std::size_t>(written));
  }

  ::HeapFree(::GetProcessHeap(), 0, buf);
  return out;
}

std::wstring get_raw_boot_device() {
  std::wstring boot_device = get_raw_dynamic_reg_string(
      HKEY_LOCAL_MACHINE,
      L"SYSTEM\\CurrentControlSet\\Control",
      L"FirmwareBootDevice");
  if (boot_device == L"N/A" || boot_device.empty()) {
    boot_device = get_raw_dynamic_reg_string(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control",
        L"BootDevice");
  }
  return boot_device;
}

std::wstring get_raw_domain_name() {
  DWORD size = 0;
  ::GetComputerNameExW(ComputerNameDnsDomain, nullptr, &size);
  if (size == 0) {
    return L"WORKGROUP";
  }

  wchar_t* buf = static_cast<wchar_t*>(
      ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, static_cast<std::size_t>(size) * sizeof(wchar_t)));
  if (buf == nullptr) {
    return L"WORKGROUP";
  }

  std::wstring out = L"WORKGROUP";
  DWORD actual = size;
  if (::GetComputerNameExW(ComputerNameDnsDomain, buf, &actual) != FALSE && actual > 0) {
    out.assign(buf, static_cast<std::size_t>(actual));
  }

  ::HeapFree(::GetProcessHeap(), 0, buf);
  return out;
}

bool extract_cpu_virtualization() noexcept {
  int cpu_info[4] = { 0, 0, 0, 0 };
  ::__cpuid(cpu_info, 1);
  return (cpu_info[2] & (1 << 5)) != 0;
}

bool extract_cpu_slat() noexcept {
  int cpu_info[4] = { 0, 0, 0, 0 };
  ::__cpuid(cpu_info, static_cast<int>(0x80000001U));
  return (cpu_info[3] & (1 << 6)) != 0;
}

bool extract_cpu_dep() noexcept {
  return ::IsProcessorFeaturePresent(PF_NX_ENABLED) != FALSE;
}

bool extract_firmware_virtualization() noexcept {
  const DWORD value = get_raw_reg_dword(
      HKEY_LOCAL_MACHINE,
      L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
      L"FeatureSet");
  return (value & (1UL << 5)) != 0;
}

std::wstring interpret_arc_path_to_device(const std::wstring& arc_path) {
  if (arc_path.find(L"\\Device\\") != std::wstring::npos) {
    return arc_path;
  }
  const std::size_t part_pos = arc_path.find(L"partition(");
  if (part_pos != std::wstring::npos) {
    const std::size_t start_idx = part_pos + 10;
    const std::size_t end_idx = arc_path.find(L")", start_idx);
    if (end_idx != std::wstring::npos) {
      const std::wstring partition_number = arc_path.substr(start_idx, end_idx - start_idx);
      return L"\\Device\\HarddiskVolume" + partition_number;
    }
  }
  return arc_path;
}

std::wstring format_unix_timestamp(std::time_t raw_time) {
  if (raw_time <= 0) {
    return L"N/A";
  }
  std::tm local_tm{};
  if (::localtime_s(&local_tm, &raw_time) == 0) {
    std::wostringstream wss;
    wss << std::put_time(&local_tm, L"%m/%d/%Y, %I:%M:%S %p");
    return wss.str();
  }
  return L"N/A";
}

std::wstring calculate_system_boot_time() {
  const std::uint64_t up_sec = ::GetTickCount64() / 1000ULL;
  const std::time_t now = ::time(nullptr);
  if (now <= 0 || static_cast<std::uint64_t>(now) < up_sec) {
    return L"N/A";
  }
  const std::time_t boot_time = now - static_cast<std::time_t>(up_sec);
  return format_unix_timestamp(boot_time);
}

std::wstring convert_memory_to_string(ULONGLONG bytes) {
  std::wostringstream wss;
  wss << (bytes / (1024ULL * 1024ULL)) << L" MB";
  return wss.str();
}

std::wstring translate_os_configuration(const std::wstring& product_type) {
  if (product_type == L"ServerNT") {
    return L"Server";
  }
  if (product_type == L"LanmanNT") {
    return L"Domain Controller";
  }
  return L"Standalone Workstation";
}

std::wstring format_cli_label(const std::wstring& label) {
  std::wostringstream wss;
  wss << std::left << std::setw(kLabelWidth) << label;
  return wss.str();
}

void print_system_row(const std::wstring& label, const std::wstring& value) {
  std::wcout << format_cli_label(label) << value << L"\n";
}

void print_processor_header() {
  std::wcout << format_cli_label(L"Processor(s):") << L"1 Processor(s) Installed.\n";
}

void print_processor_row(int index, const std::wstring& cpu_name) {
  std::wcout
      << std::setw(31) << L""
      << L"[" << std::setfill(L'0') << std::setw(2) << index << L"]: "
      << std::setfill(L' ') << cpu_name << L"\n";
}

void print_directory_row(
    const std::wstring& win_dir,
    const std::wstring& sys_dir,
    const std::wstring& boot_device,
    const std::wstring& sys_locale,
    const std::wstring& logon_server) {
  print_system_row(L"Windows Directory:", win_dir);
  print_system_row(L"System Directory:", sys_dir);
  print_system_row(L"Boot Device:", boot_device);
  print_system_row(L"System Locale:", sys_locale);
  print_system_row(L"Input Locale:", sys_locale);
  print_system_row(L"Logon Server:", logon_server);
}

void print_network_header(int total_cards) {
  std::wcout << format_cli_label(L"Network Card(s):") << total_cards << L" NIC(s) Installed.\n";
}

void print_network_card_details(
    int index,
    const wchar_t* desc,
    const wchar_t* conn_name,
    bool dhcp) {
  const std::wstring safe_desc(desc != nullptr ? desc : L"N/A");
  const std::wstring safe_conn(conn_name != nullptr ? conn_name : L"N/A");

  std::wcout
      << std::setw(31) << L""
      << L"[" << std::setfill(L'0') << std::setw(2) << index << L"]: "
      << std::setfill(L' ') << safe_desc << L"\n"
      << std::setw(36) << L"" << L"Connection Name: " << safe_conn << L"\n"
      << std::setw(36) << L"" << L"DHCP Enabled:    " << (dhcp ? L"Yes" : L"No") << L"\n";
}

void print_network_ip_row(int ip_index, const std::wstring& ip_addr) {
  std::wcout
      << std::setw(36) << L""
      << L"[" << std::setfill(L'0') << std::setw(2) << ip_index << L"]: "
      << std::setfill(L' ') << ip_addr << L"\n";
}

void print_hyperv_header() {
  std::wcout << L"Hyper-V Requirements:\n";
}

void print_hyperv_row(const std::wstring& property_name, bool supported) {
  std::wcout << std::setw(35) << L"" << property_name << L": " << (supported ? L"Yes" : L"No") << L"\n";
}

void execute_host_name_sieve() {
  print_system_row(L"Host Name:", get_raw_computer_name());
}

void execute_os_details_sieve() {
  constexpr LPCWSTR kNtKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
  std::wstring os_name = get_raw_dynamic_reg_string(HKEY_LOCAL_MACHINE, kNtKey, L"ProductName");
  const std::wstring current_build = get_raw_dynamic_reg_string(HKEY_LOCAL_MACHINE, kNtKey, L"CurrentBuild");
  const std::wstring product_type = get_raw_dynamic_reg_string(
      HKEY_LOCAL_MACHINE,
      L"SYSTEM\\CurrentControlSet\\Control\\ProductOptions",
      L"ProductType");

  const std::wstring os_version = get_kernel_version_from_ntdll(current_build);
  const unsigned long build_num = parse_build_number_ul(current_build);
  if (build_num >= 22000UL) {
    const std::size_t pos = os_name.find(L"Windows 10");
    if (pos != std::wstring::npos) {
      os_name.replace(pos, 10, L"Windows 11");
    }
  }

  print_system_row(L"OS Name:", os_name);
  print_system_row(L"OS Version:", os_version + L" N/A Build " + current_build);
  print_system_row(L"OS Manufacturer:", L"Microsoft Corporation");
  print_system_row(L"OS Configuration:", translate_os_configuration(product_type));
  print_system_row(L"OS Build Type:", L"Multiprocessor Free");
  print_system_row(L"Registered Owner:", get_raw_dynamic_reg_string(HKEY_LOCAL_MACHINE, kNtKey, L"RegisteredOwner"));
  print_system_row(L"Registered Organization:", get_raw_dynamic_reg_string(HKEY_LOCAL_MACHINE, kNtKey, L"RegisteredOrganization"));
  print_system_row(L"Product ID:", get_raw_dynamic_reg_string(HKEY_LOCAL_MACHINE, kNtKey, L"ProductId"));
}

void execute_system_dates_sieve() {
  const std::time_t install_timestamp = static_cast<std::time_t>(get_raw_reg_dword(
      HKEY_LOCAL_MACHINE,
      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
      L"InstallDate"));
  print_system_row(L"Original Install Date:", format_unix_timestamp(install_timestamp));
  print_system_row(L"System Boot Time:", calculate_system_boot_time());
}

void execute_hardware_sieve() {
  constexpr LPCWSTR kBiosKey = L"HARDWARE\\DESCRIPTION\\System\\BIOS";
  const std::wstring vendor = get_raw_dynamic_reg_string(HKEY_LOCAL_MACHINE, kBiosKey, L"BIOSVendor");
  const std::wstring version = get_raw_dynamic_reg_string(HKEY_LOCAL_MACHINE, kBiosKey, L"BIOSVersion");
  const std::wstring release_date = get_raw_dynamic_reg_string(HKEY_LOCAL_MACHINE, kBiosKey, L"BIOSReleaseDate");
  const std::wstring cpu_name = get_raw_dynamic_reg_string(
      HKEY_LOCAL_MACHINE,
      L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
      L"ProcessorNameString");

  SYSTEM_INFO si{};
  ::GetSystemInfo(&si);
  const std::wstring sys_type =
      (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) ? L"x86-based PC" : L"x64-based PC";

  print_system_row(L"System Manufacturer:", get_raw_dynamic_reg_string(HKEY_LOCAL_MACHINE, kBiosKey, L"SystemManufacturer"));
  print_system_row(L"System Model:", get_raw_dynamic_dynamic_reg_string(HKEY_LOCAL_MACHINE, kBiosKey, L"SystemProductName"));
  print_system_row(L"System Type:", sys_type);

  print_processor_header();
  print_processor_row(1, cpu_name);
  print_system_row(L"BIOS Version:", vendor + L" " + version + L", " + release_date);
}

void execute_directories_sieve() {
  const std::wstring win_dir = get_raw_windows_directory();
  const std::wstring sys_dir = get_raw_system_directory();
  const std::wstring raw_boot = get_raw_boot_device();
  const std::wstring clean_boot_device = interpret_arc_path_to_device(raw_boot);
  const std::wstring sys_locale = get_raw_dynamic_reg_string(
      HKEY_CURRENT_USER,
      L"Control Panel\\International",
      L"LocaleName");
  const std::wstring logon_server = get_raw_environment_variable(L"LOGONSERVER");

  print_directory_row(win_dir, sys_dir, clean_boot_device, sys_locale, logon_server);
}

void execute_time_zone_sieve() {
  TIME_ZONE_INFORMATION tzi{};
  std::wstring zone_name = L"N/A";
  if (::GetTimeZoneInformation(&tzi) != TIME_ZONE_ID_INVALID && tzi.StandardName[0] != L'\0') {
    zone_name.assign(tzi.StandardName);
  }
  print_system_row(L"Time Zone:", zone_name);
}

void execute_memory_sieve() {
  MEMORYSTATUSEX statex{};
  statex.dwLength = static_cast<DWORD>(sizeof(statex));
  if (::GlobalMemoryStatusEx(&statex) != FALSE) {
    print_system_row(L"Total Physical Memory:", convert_memory_to_string(statex.ullTotalPhys));
    print_system_row(L"Available Physical Memory:", convert_memory_to_string(statex.ullAvailPhys));
    print_system_row(L"Virtual Memory: Max Size:", convert_memory_to_string(statex.ullTotalPageFile));
    print_system_row(L"Virtual Memory: Available:", convert_memory_to_string(statex.ullAvailPageFile));
    print_system_row(
        L"Virtual Memory: In Use:",
        convert_memory_to_string(statex.ullTotalPageFile - statex.ullAvailPageFile));
  }
  const std::wstring page_file = get_raw_dynamic_reg_string(
      HKEY_LOCAL_MACHINE,
      L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
      L"PagingFiles");
  print_system_row(L"Page File Location(s):", page_file);
}

void execute_domain_sieve() {
  print_system_row(L"Domain:", get_raw_domain_name());
}

void execute_network_sieve() {
  constexpr ULONG kFlags = GAA_FLAG_INCLUDE_PREFIX;
  ULONG out_buf_len = 16384U;
  PIP_ADAPTER_ADDRESSES p_addresses = nullptr;
  ULONG ret = ERROR_BUFFER_OVERFLOW;

  for (int attempt = 0; attempt < kMaxAdapterAttempts; ++attempt) {
    if (p_addresses != nullptr) {
      ::HeapFree(::GetProcessHeap(), 0, p_addresses);
      p_addresses = nullptr;
    }
    p_addresses = static_cast<PIP_ADAPTER_ADDRESSES>(
        ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, static_cast<std::size_t>(out_buf_len)));
    if (p_addresses == nullptr) {
      return;
    }
    ret = ::GetAdaptersAddresses(AF_UNSPEC, kFlags, nullptr, p_addresses, &out_buf_len);
    if (ret != ERROR_BUFFER_OVERFLOW) {
      break;
    }
  }

  if (ret == NO_ERROR && p_addresses != nullptr) {
    int total_adapters = 0;
    for (PIP_ADAPTER_ADDRESSES c = p_addresses; c != nullptr; c = c->Next) {
      ++total_adapters;
    }
    print_network_header(total_adapters);

    PIP_ADAPTER_ADDRESSES curr = p_addresses;
    int idx = 1;
    while (curr != nullptr) {
      const bool is_dhcp = (curr->Flags & IP_ADAPTER_DHCP_ENABLED) != 0;
      print_network_card_details(idx, curr->Description, curr->FriendlyName, is_dhcp);

      PIP_ADAPTER_UNICAST_ADDRESS p_unicast = curr->FirstUnicastAddress;
      if (p_unicast != nullptr) {
        std::wcout << std::setw(36) << L"" << L"IP address(es)\n";
        int ip_idx = 1;
        while (p_unicast != nullptr) {
          wchar_t w_buf[INET6_ADDRSTRLEN]{};
          const SOCKADDR* addr = p_unicast->Address.lpSockaddr;
          bool converted = false;

          if (addr != nullptr) {
            if (addr->sa_family == AF_INET) {
              const auto* sin_v4 = reinterpret_cast<const sockaddr_in*>(addr);
              converted = (::InetNtopW(AF_INET, &sin_v4->sin_addr, w_buf, INET6_ADDRSTRLEN) != nullptr);
            } else if (addr->sa_family == AF_INET6) {
              const auto* sin_v6 = reinterpret_cast<const sockaddr_in6*>(addr);
              converted = (::InetNtopW(AF_INET6, &sin_v6->sin6_addr, w_buf, INET6_ADDRSTRLEN) != nullptr);
            }
          }

          if (converted) {
            print_network_ip_row(ip_idx, w_buf);
          } else {
            print_network_ip_row(ip_idx, L"N/A");
          }

          p_unicast = p_unicast->Next;
          ++ip_idx;
        }
      }

      curr = curr->Next;
      ++idx;
    }
  }

  if (p_addresses != nullptr) {
    ::HeapFree(::GetProcessHeap(), 0, p_addresses);
    p_addresses = nullptr;
  }
}

void execute_hyperv_sieve() {
  print_hyperv_header();
  print_hyperv_row(L"VM Monitor Mode Extensions", extract_cpu_virtualization());
  print_hyperv_row(L"Virtualization Enabled In Firmware", extract_firmware_virtualization());
  print_hyperv_row(L"Second Level Address Translation", extract_cpu_slat());
  print_hyperv_row(L"Data Execution Prevention Available", extract_cpu_dep());
}

}  // namespace

int wmain() {
  if (_setmode(_fileno(stdout), _O_U16TEXT) != -1) {
    _setmode(_fileno(stderr), _O_U16TEXT);
    std::wcout << L"\n";
    execute_host_name_sieve();
    execute_os_details_sieve();
    execute_system_dates_sieve();
    execute_hardware_sieve();
    execute_directories_sieve();
    execute_time_zone_sieve();
    execute_memory_sieve();
    execute_domain_sieve();
    execute_network_sieve();
    execute_hyperv_sieve();
    std::wcout << L"\n";
  }
  return 0;
}
