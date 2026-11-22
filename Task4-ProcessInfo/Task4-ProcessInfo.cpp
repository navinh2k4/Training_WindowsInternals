
#include <winsock2.h>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <fcntl.h>
#include <io.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cwchar>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

namespace {

constexpr int kLayoutWidth = 43;
constexpr int kMaxPathRetryAttempts = 6;

using NTSTATUS = LONG;

struct UNICODE_STRING_RAW final {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
};

struct PROCESS_BASIC_INFORMATION_RAW final {
  NTSTATUS ExitStatus;
  PVOID PebBaseAddress;
  ULONG_PTR AffinityMask;
  LONG BasePriority;
  ULONG_PTR UniqueProcessId;
  ULONG_PTR InheritedFromUniqueProcessId;
};

using NtQueryInformationProcessFn = NTSTATUS(WINAPI*)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

struct privilege_record final {
  std::wstring name;
  std::wstring state;
};

struct module_record final {
  std::wstring name;
  std::wstring full_path;
  PVOID base_address = nullptr;
  DWORD size = 0;
};

struct thread_record final {
  DWORD id = 0;
  LONG priority = 0;
  std::wstring status;
};

struct process_toolhelp_core final {
  DWORD pid = 0;
  DWORD parent_pid = 0;
  DWORD thread_count = 0;
  bool found = false;
};

bool parse_pid_u32(const wchar_t* text, DWORD& out_pid) noexcept {
  out_pid = 0;
  if (text == nullptr || text[0] == L'\0') {
    return false;
  }

  unsigned long acc = 0;
  for (std::size_t i = 0; text[i] != L'\0'; ++i) {
    const wchar_t ch = text[i];
    if (ch < L'0' || ch > L'9') {
      return false;
    }
    const unsigned long digit = static_cast<unsigned long>(ch - L'0');
    if (acc > (static_cast<unsigned long>(UINT32_MAX) - digit) / 10UL) {
      return false;
    }
    acc = acc * 10UL + digit;
  }

  out_pid = static_cast<DWORD>(acc);
  return true;
}

HANDLE create_process_snapshot() noexcept {
  return ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
}

bool get_first_process_entry(
    HANDLE h_snapshot,
    PROCESSENTRY32W& entry) noexcept {
  entry = {};
  entry.dwSize = static_cast<DWORD>(sizeof(PROCESSENTRY32W));
  return ::Process32FirstW(h_snapshot, &entry) != FALSE;
}

bool get_next_process_entry(
    HANDLE h_snapshot,
    PROCESSENTRY32W& entry) noexcept {
  entry = {};
  entry.dwSize = static_cast<DWORD>(sizeof(PROCESSENTRY32W));
  return ::Process32NextW(h_snapshot, &entry) != FALSE;
}

process_toolhelp_core extract_target_process_core_info(
    DWORD target_pid,
    const std::wstring& target_name,
    bool search_by_pid) {
  process_toolhelp_core core_result{};
  const HANDLE h_snapshot = create_process_snapshot();
  if (h_snapshot == INVALID_HANDLE_VALUE || h_snapshot == nullptr) {
    return core_result;
  }

  PROCESSENTRY32W pe{};
  if (get_first_process_entry(h_snapshot, pe)) {
    do {
      const bool match = search_by_pid
          ? (pe.th32ProcessID == target_pid)
          : (::_wcsicmp(pe.szExeFile, target_name.c_str()) == 0);
      if (match) {
        core_result.pid = pe.th32ProcessID;
        core_result.parent_pid = pe.th32ParentProcessID;
        core_result.thread_count = pe.cntThreads;
        core_result.found = true;
        break;
      }
    } while (get_next_process_entry(h_snapshot, pe));
  }

  ::CloseHandle(h_snapshot);
  return core_result;
}

std::wstring get_process_executable_path(HANDLE h_process) {
  if (h_process == nullptr || h_process == INVALID_HANDLE_VALUE) {
    return L"N/A";
  }

  DWORD capacity = MAX_PATH;
  for (int attempt = 0; attempt < kMaxPathRetryAttempts; ++attempt) {
    wchar_t* buf = static_cast<wchar_t*>(
        ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, static_cast<std::size_t>(capacity) * sizeof(wchar_t)));
    if (buf == nullptr) {
      return L"N/A";
    }

    DWORD io_size = capacity;
    if (::QueryFullProcessImageNameW(h_process, 0, buf, &io_size) != FALSE) {
      std::wstring result = (io_size > 0) ? std::wstring(buf, static_cast<std::size_t>(io_size)) : L"N/A";
      ::HeapFree(::GetProcessHeap(), 0, buf);
      return result;
    }

    const DWORD err = ::GetLastError();
    ::HeapFree(::GetProcessHeap(), 0, buf);
    if (err != ERROR_INSUFFICIENT_BUFFER) {
      return L"N/A";
    }
    capacity *= 2U;
  }

  return L"N/A";
}

bool query_peb_basic_info(
    HANDLE h_process,
    PROCESS_BASIC_INFORMATION_RAW& out_pbi) noexcept {
  out_pbi = {};
  const HMODULE h_ntdll = ::GetModuleHandleW(L"ntdll.dll");
  if (h_ntdll == nullptr) {
    return false;
  }

  const FARPROC raw_proc = ::GetProcAddress(h_ntdll, "NtQueryInformationProcess");
  if (raw_proc == nullptr) {
    return false;
  }

  auto query_fn = reinterpret_cast<NtQueryInformationProcessFn>(raw_proc);
  ULONG return_length = 0;
  constexpr DWORD kProcessBasicInformation = 0;
  const NTSTATUS status = query_fn(
      h_process,
      kProcessBasicInformation,
      &out_pbi,
      static_cast<ULONG>(sizeof(out_pbi)),
      &return_length);
  return status == 0 && out_pbi.PebBaseAddress != nullptr;
}

std::wstring get_process_command_line_from_peb(HANDLE h_process) {
  PROCESS_BASIC_INFORMATION_RAW pbi{};
  if (!query_peb_basic_info(h_process, pbi)) {
    return L"N/A";
  }

  constexpr ULONG_PTR kPebProcessParametersOffset =
      (sizeof(PVOID) == 8) ? 0x20U : 0x10U;
  constexpr ULONG_PTR kCmdLineOffset =
      (sizeof(PVOID) == 8) ? 0x70U : 0x40U;

  PVOID process_params_addr = nullptr;
  SIZE_T bytes_read = 0;
  const std::uintptr_t params_ptr_addr =
      reinterpret_cast<std::uintptr_t>(pbi.PebBaseAddress) + kPebProcessParametersOffset;

  if (::ReadProcessMemory(
          h_process,
          reinterpret_cast<LPCVOID>(params_ptr_addr),
          &process_params_addr,
          sizeof(process_params_addr),
          &bytes_read) == FALSE ||
      process_params_addr == nullptr) {
    return L"N/A";
  }

  UNICODE_STRING_RAW cmd_uni{};
  const std::uintptr_t cmd_ptr_addr =
      reinterpret_cast<std::uintptr_t>(process_params_addr) + kCmdLineOffset;

  if (::ReadProcessMemory(
          h_process,
          reinterpret_cast<LPCVOID>(cmd_ptr_addr),
          &cmd_uni,
          sizeof(cmd_uni),
          &bytes_read) == FALSE ||
      cmd_uni.Buffer == nullptr ||
      cmd_uni.Length == 0) {
    return L"N/A";
  }

  const std::size_t byte_len = static_cast<std::size_t>(cmd_uni.Length);
  const std::size_t char_count = byte_len / sizeof(wchar_t);
  wchar_t* cmd_buf = static_cast<wchar_t*>(
      ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, byte_len + sizeof(wchar_t)));
  if (cmd_buf == nullptr) {
    return L"N/A";
  }

  std::wstring result = L"N/A";
  if (::ReadProcessMemory(
          h_process,
          cmd_uni.Buffer,
          cmd_buf,
          byte_len,
          &bytes_read) != FALSE &&
      bytes_read > 0) {
    const std::size_t actual_chars = std::min(char_count, static_cast<std::size_t>(bytes_read) / sizeof(wchar_t));
    result.assign(cmd_buf, actual_chars);
  }

  ::HeapFree(::GetProcessHeap(), 0, cmd_buf);
  return result;
}

std::wstring get_process_owner_name(HANDLE h_process) {
  HANDLE h_token = nullptr;
  if (::OpenProcessToken(h_process, TOKEN_QUERY, &h_token) == FALSE || h_token == nullptr) {
    return L"N/A";
  }

  DWORD token_size = 0;
  ::GetTokenInformation(h_token, TokenUser, nullptr, 0, &token_size);
  if (token_size == 0) {
    ::CloseHandle(h_token);
    return L"N/A";
  }

  BYTE* token_buf = static_cast<BYTE*>(
      ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, static_cast<std::size_t>(token_size)));
  if (token_buf == nullptr) {
    ::CloseHandle(h_token);
    return L"N/A";
  }

  std::wstring owner_name = L"N/A";
  DWORD actual_token_size = token_size;
  if (::GetTokenInformation(
          h_token,
          TokenUser,
          token_buf,
          token_size,
          &actual_token_size) != FALSE) {
    const PTOKEN_USER p_token_user = reinterpret_cast<PTOKEN_USER>(token_buf);
    DWORD name_len = 0;
    DWORD domain_len = 0;
    SID_NAME_USE sid_use = SidTypeUnknown;
    ::LookupAccountSidW(
        nullptr,
        p_token_user->User.Sid,
        nullptr,
        &name_len,
        nullptr,
        &domain_len,
        &sid_use);

    if (name_len > 0 && domain_len > 0) {
      wchar_t* name_buf = static_cast<wchar_t*>(
          ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, static_cast<std::size_t>(name_len) * sizeof(wchar_t)));
      wchar_t* domain_buf = static_cast<wchar_t*>(
          ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, static_cast<std::size_t>(domain_len) * sizeof(wchar_t)));

      if (name_buf != nullptr && domain_buf != nullptr) {
        DWORD io_name_len = name_len;
        DWORD io_domain_len = domain_len;
        if (::LookupAccountSidW(
                nullptr,
                p_token_user->User.Sid,
                name_buf,
                &io_name_len,
                domain_buf,
                &io_domain_len,
                &sid_use) != FALSE) {
          owner_name = std::wstring(domain_buf) + L"\\" + std::wstring(name_buf);
        }
      }

      if (name_buf != nullptr) {
        ::HeapFree(::GetProcessHeap(), 0, name_buf);
      }
      if (domain_buf != nullptr) {
        ::HeapFree(::GetProcessHeap(), 0, domain_buf);
      }
    }
  }

  ::HeapFree(::GetProcessHeap(), 0, token_buf);
  ::CloseHandle(h_token);
  return owner_name;
}

std::wstring get_process_created_time(HANDLE h_process) {
  FILETIME create_utc{};
  FILETIME exit_time{};
  FILETIME kernel_time{};
  FILETIME user_time{};

  if (::GetProcessTimes(h_process, &create_utc, &exit_time, &kernel_time, &user_time) != FALSE) {
    FILETIME create_local{};
    if (::FileTimeToLocalFileTime(&create_utc, &create_local) != FALSE) {
      SYSTEMTIME sys_time{};
      if (::FileTimeToSystemTime(&create_local, &sys_time) != FALSE) {
        std::wostringstream wss;
        wss << std::setfill(L'0')
            << std::setw(4) << sys_time.wYear << L"-"
            << std::setw(2) << sys_time.wMonth << L"-"
            << std::setw(2) << sys_time.wDay << L" "
            << std::setw(2) << sys_time.wHour << L":"
            << std::setw(2) << sys_time.wMinute << L":"
            << std::setw(2) << sys_time.wSecond;
        return wss.str();
      }
    }
  }
  return L"N/A";
}

std::wstring get_process_architecture(HANDLE h_process) {
  BOOL is_wow64 = FALSE;
  if (::IsWow64Process(h_process, &is_wow64) != FALSE) {
    if (is_wow64 != FALSE) {
      return L"x86 (32-bit running on 64-bit OS)";
    }
    SYSTEM_INFO si{};
    ::GetNativeSystemInfo(&si);
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
      return L"x64";
    }
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
      return L"x86";
    }
  }
  return L"Unknown";
}

std::vector<privilege_record> extract_process_privileges(HANDLE h_process) {
  std::vector<privilege_record> priv_list;
  HANDLE h_token = nullptr;
  if (::OpenProcessToken(h_process, TOKEN_QUERY, &h_token) == FALSE || h_token == nullptr) {
    return priv_list;
  }

  DWORD size = 0;
  ::GetTokenInformation(h_token, TokenPrivileges, nullptr, 0, &size);
  if (size == 0) {
    ::CloseHandle(h_token);
    return priv_list;
  }

  BYTE* priv_buf = static_cast<BYTE*>(
      ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, static_cast<std::size_t>(size)));
  if (priv_buf == nullptr) {
    ::CloseHandle(h_token);
    return priv_list;
  }

  DWORD actual_size = size;
  if (::GetTokenInformation(
          h_token,
          TokenPrivileges,
          priv_buf,
          size,
          &actual_size) != FALSE) {
    const PTOKEN_PRIVILEGES p_privs = reinterpret_cast<PTOKEN_PRIVILEGES>(priv_buf);
    for (DWORD i = 0; i < p_privs->PrivilegeCount; ++i) {
      DWORD name_len = 0;
      ::LookupPrivilegeNameW(nullptr, &p_privs->Privileges[i].Luid, nullptr, &name_len);
      if (name_len == 0) {
        continue;
      }

      wchar_t* name_buf = static_cast<wchar_t*>(
          ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, static_cast<std::size_t>(name_len) * sizeof(wchar_t)));
      if (name_buf != nullptr) {
        DWORD io_len = name_len;
        if (::LookupPrivilegeNameW(nullptr, &p_privs->Privileges[i].Luid, name_buf, &io_len) != FALSE) {
          privilege_record rec{};
          rec.name = name_buf;
          rec.state = ((p_privs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0)
              ? L"Enabled"
              : L"Disabled";
          priv_list.push_back(rec);
        }
        ::HeapFree(::GetProcessHeap(), 0, name_buf);
      }
    }
  }

  ::HeapFree(::GetProcessHeap(), 0, priv_buf);
  ::CloseHandle(h_token);
  return priv_list;
}

std::vector<module_record> extract_process_modules(DWORD pid) {
  std::vector<module_record> module_list;
  const HANDLE h_snapshot = ::CreateToolhelp32Snapshot(
      TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
      pid);
  if (h_snapshot == INVALID_HANDLE_VALUE || h_snapshot == nullptr) {
    return module_list;
  }

  MODULEENTRY32W me{};
  me.dwSize = static_cast<DWORD>(sizeof(MODULEENTRY32W));
  if (::Module32FirstW(h_snapshot, &me) != FALSE) {
    do {
      module_record rec{};
      rec.name = me.szModule;
      rec.full_path = me.szExePath;
      rec.base_address = me.modBaseAddr;
      rec.size = me.modBaseSize;
      module_list.push_back(rec);
      me = {};
      me.dwSize = static_cast<DWORD>(sizeof(MODULEENTRY32W));
    } while (::Module32NextW(h_snapshot, &me) != FALSE);
  }

  ::CloseHandle(h_snapshot);
  return module_list;
}

std::wstring get_thread_real_status(DWORD thread_id) {
  std::wstring status_str = L"Waiting";
  const HANDLE h_thread = ::OpenThread(THREAD_QUERY_INFORMATION, FALSE, thread_id);
  if (h_thread == nullptr || h_thread == INVALID_HANDLE_VALUE) {
    return status_str;
  }

  FILETIME c_time{};
  FILETIME e_time{};
  FILETIME k_time{};
  FILETIME u_time{};
  if (::GetThreadTimes(h_thread, &c_time, &e_time, &k_time, &u_time) != FALSE) {
    ULARGE_INTEGER kernel_time{};
    kernel_time.LowPart = k_time.dwLowDateTime;
    kernel_time.HighPart = k_time.dwHighDateTime;

    ULARGE_INTEGER user_time{};
    user_time.LowPart = u_time.dwLowDateTime;
    user_time.HighPart = u_time.dwHighDateTime;

    if (kernel_time.QuadPart > 0 || user_time.QuadPart > 0) {
      status_str = L"Running";
    }
  }

  const DWORD suspend_count = ::SuspendThread(h_thread);
  if (suspend_count != static_cast<DWORD>(-1)) {
    ::ResumeThread(h_thread);
    if (suspend_count > 0) {
      status_str = L"Suspended";
    }
  }

  ::CloseHandle(h_thread);
  return status_str;
}

std::vector<thread_record> extract_process_threads(DWORD target_pid) {
  std::vector<thread_record> thread_list;
  const HANDLE h_snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (h_snapshot == INVALID_HANDLE_VALUE || h_snapshot == nullptr) {
    return thread_list;
  }

  THREADENTRY32 te{};
  te.dwSize = static_cast<DWORD>(sizeof(THREADENTRY32));
  if (::Thread32First(h_snapshot, &te) != FALSE) {
    do {
      if (te.th32OwnerProcessID == target_pid) {
        thread_record rec{};
        rec.id = te.th32ThreadID;
        rec.priority = te.tpBasePri;
        rec.status = get_thread_real_status(te.th32ThreadID);
        thread_list.push_back(rec);
      }
      te = {};
      te.dwSize = static_cast<DWORD>(sizeof(THREADENTRY32));
    } while (::Thread32Next(h_snapshot, &te) != FALSE);
  }

  ::CloseHandle(h_snapshot);
  return thread_list;
}

std::wstring translate_priority_class(DWORD priority_class) {
  switch (priority_class) {
    case IDLE_PRIORITY_CLASS:
      return L"IDLE_PRIORITY_CLASS";
    case BELOW_NORMAL_PRIORITY_CLASS:
      return L"BELOW_NORMAL_PRIORITY_CLASS";
    case NORMAL_PRIORITY_CLASS:
      return L"NORMAL_PRIORITY_CLASS";
    case ABOVE_NORMAL_PRIORITY_CLASS:
      return L"ABOVE_NORMAL_PRIORITY_CLASS";
    case HIGH_PRIORITY_CLASS:
      return L"HIGH_PRIORITY_CLASS";
    case REALTIME_PRIORITY_CLASS:
      return L"REALTIME_PRIORITY_CLASS";
    default:
      return L"NORMAL_PRIORITY_CLASS";
  }
}

std::wstring format_memory_size_mb(SIZE_T bytes) {
  std::wostringstream wss;
  const double mb = static_cast<double>(bytes) / (1024.0 * 1024.0);
  wss << std::fixed << std::setprecision(1) << mb << L" MB";
  return wss.str();
}

std::wstring format_module_size_string(DWORD bytes) {
  std::wostringstream wss;
  if (bytes >= 1024U * 1024U) {
    const double mb = static_cast<double>(bytes) / (1024.0 * 1024.0);
    wss << std::fixed << std::setprecision(1) << mb << L" MB";
  } else {
    wss << (bytes / 1024U) << L" KB";
  }
  return wss.str();
}

std::wstring extract_file_name_from_path(const std::wstring& full_path) {
  const std::size_t pos = full_path.find_last_of(L"\\/");
  return (pos != std::wstring::npos) ? full_path.substr(pos + 1) : full_path;
}

void print_row_formatted(const std::wstring& label, const std::wstring& value) {
  std::wcout << std::left << std::setw(kLayoutWidth) << label << L": " << value << L"\n";
}

int print_final_report(DWORD pid, const process_toolhelp_core& toolhelp_core) {
  const HANDLE h_process = ::OpenProcess(
      PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
      FALSE,
      pid);
  if (h_process == nullptr || h_process == INVALID_HANDLE_VALUE) {
    const DWORD err = ::GetLastError();
    std::wcerr << L"Error: Unable to open target PID for report. Win32=" << err << L"\n";
    return (err != ERROR_SUCCESS) ? static_cast<int>(err) : static_cast<int>(ERROR_ACCESS_DENIED);
  }

  const std::wstring full_path = get_process_executable_path(h_process);
  const std::wstring proc_name = extract_file_name_from_path(full_path);

  DWORD session_id = 0;
  if (::ProcessIdToSessionId(pid, &session_id) == FALSE) {
    session_id = 0;
  }

  DWORD handle_count = 0;
  ::GetProcessHandleCount(h_process, &handle_count);

  PROCESS_MEMORY_COUNTERS_EX pmc{};
  pmc.cb = static_cast<DWORD>(sizeof(PROCESS_MEMORY_COUNTERS_EX));
  ::GetProcessMemoryInfo(
      h_process,
      reinterpret_cast<PPROCESS_MEMORY_COUNTERS>(&pmc),
      static_cast<DWORD>(sizeof(pmc)));

  BOOL is_target_wow64 = FALSE;
  ::IsWow64Process(h_process, &is_target_wow64);

  std::wcout
      << L"===========================================\n"
      << L"PROCESS INFORMATION REPORT\n"
      << L"===========================================\n\n"
      << L"[PROCESS BASIC INFO]\n"
      << L"-------------------------------------------\n";

  print_row_formatted(L"Process Name", proc_name);
  print_row_formatted(L"Process ID (PID)", std::to_wstring(pid));
  print_row_formatted(L"Parent PID", std::to_wstring(toolhelp_core.parent_pid));
  print_row_formatted(L"Executable Path", full_path);
  print_row_formatted(L"Command Line", get_process_command_line_from_peb(h_process));
  print_row_formatted(L"Session ID", std::to_wstring(session_id));
  print_row_formatted(L"Priority Class", translate_priority_class(::GetPriorityClass(h_process)));
  print_row_formatted(L"Handle Count", std::to_wstring(handle_count));
  print_row_formatted(L"Thread Count", std::to_wstring(toolhelp_core.thread_count));
  print_row_formatted(L"Architecture", get_process_architecture(h_process));
  print_row_formatted(L"Created Time", get_process_created_time(h_process));
  print_row_formatted(L"User", get_process_owner_name(h_process));

  std::wcout
      << L"\n-------------------------------------------\n"
      << L"[PRIVILEGES]\n"
      << L"-------------------------------------------\n";

  const std::vector<privilege_record> privileges = extract_process_privileges(h_process);
  if (privileges.empty()) {
    std::wcout << L"No privileges available or access denied.\n";
  } else {
    for (const auto& priv : privileges) {
      std::wcout << std::left << std::setw(30) << priv.name << L": " << priv.state << L"\n";
    }
  }

  std::wcout
      << L"\n-------------------------------------------\n"
      << L"[MEMORY USAGE]\n"
      << L"-------------------------------------------\n";

  print_row_formatted(L"Working Set (RAM)", format_memory_size_mb(pmc.WorkingSetSize));
  print_row_formatted(L"Private Bytes", format_memory_size_mb(pmc.PrivateUsage));
  print_row_formatted(L"Pagefile Usage", format_memory_size_mb(pmc.PagefileUsage));
  print_row_formatted(L"Peak Working Set", format_memory_size_mb(pmc.PeakWorkingSetSize));

  std::wcout
      << L"\n-------------------------------------------\n"
      << L"[MODULES LOADED]\n"
      << L"-------------------------------------------\n"
      << std::left << std::setw(18) << L"Base Address" << L" "
      << std::left << std::setw(10) << L"Size" << L" Module Name (Full Path)\n"
      << L"-------------------------------------------\n";

  const std::vector<module_record> modules = extract_process_modules(pid);
  const int address_width = (is_target_wow64 != FALSE) ? 8 : 16;
  for (const auto& mod : modules) {
    std::wcout
        << L"0x" << std::uppercase << std::hex << std::setw(address_width) << std::setfill(L'0')
        << reinterpret_cast<ULONG_PTR>(mod.base_address)
        << std::nouppercase << std::dec << std::setfill(L' ') << L" "
        << std::right << std::setw(7) << format_module_size_string(mod.size)
        << L"    " << mod.full_path << L"\n";
  }
  std::wcout << L"Total Modules Loaded : " << modules.size() << L"\n";

  std::wcout
      << L"\n-------------------------------------------\n"
      << L"[THREADS]\n"
      << L"-------------------------------------------\n"
      << std::left << std::setw(12) << L"Thread ID"
      << std::left << std::setw(16) << L"Base Priority"
      << L"Status\n"
      << L"-------------------------------------------\n";

  std::vector<thread_record> threads = extract_process_threads(pid);
  std::sort(
      threads.begin(),
      threads.end(),
      [](const thread_record& a, const thread_record& b) noexcept {
        return a.id < b.id;
      });

  for (const auto& th : threads) {
    std::wcout
        << std::left << std::setw(12) << th.id
        << std::left << std::setw(16) << th.priority
        << th.status << L"\n";
  }
  std::wcout << L"Total Threads: " << threads.size() << L"\n";

  std::wcout
      << L"\n-------------------------------------------\n"
      << L"[SYSTEM CONTEXT]\n"
      << L"-------------------------------------------\n";

  print_row_formatted(L"Process Bitness", (sizeof(PVOID) == 8) ? L"64-bit" : L"32-bit");
  print_row_formatted(L"OS Architecture", L"x64");
  print_row_formatted(L"IsWow64Process", (is_target_wow64 != FALSE) ? L"Yes" : L"No");

  PVOID image_base = nullptr;
  PROCESS_BASIC_INFORMATION_RAW pbi{};
  if (query_peb_basic_info(h_process, pbi)) {
    constexpr ULONG_PTR kPebImageBaseOffset =
        (sizeof(PVOID) == 8) ? 0x10U : 0x08U;
    SIZE_T bytes_read = 0;
    const std::uintptr_t base_ptr_addr =
        reinterpret_cast<std::uintptr_t>(pbi.PebBaseAddress) + kPebImageBaseOffset;
    ::ReadProcessMemory(
        h_process,
        reinterpret_cast<LPCVOID>(base_ptr_addr),
        &image_base,
        sizeof(image_base),
        &bytes_read);
  }

  std::wcout
      << L"PEB ImageBaseAddress : 0x"
      << std::hex << std::uppercase << reinterpret_cast<ULONG_PTR>(image_base)
      << std::nouppercase << std::dec << L"\n";
  print_row_formatted(L"Image Path from PEB", full_path);

  std::wcout
      << L"===========================================\n"
      << L"END OF REPORT\n"
      << L"===========================================\n";

  ::CloseHandle(h_process);
  return 0;
}

}  // namespace

int wmain(int argc, wchar_t* argv[]) {
  if (_setmode(_fileno(stdout), _O_U16TEXT) == -1) {
    return 1;
  }
  _setmode(_fileno(stderr), _O_U16TEXT);

  if (argc < 3 || argv == nullptr || argv[1] == nullptr || argv[2] == nullptr) {
    std::wcout
        << L"Usage: process_info.exe -n <process_name> | -p <PID>\n"
        << L"Example: process_info.exe -n notepad.exe\n";
    return 1;
  }

  const std::wstring arg_flag(argv[1]);
  const std::wstring arg_value(argv[2]);
  process_toolhelp_core toolhelp_core{};

  if (arg_flag == L"-p") {
    DWORD target_pid = 0;
    if (!parse_pid_u32(argv[2], target_pid)) {
      std::wcerr << L"Error: Invalid PID argument.\n";
      return static_cast<int>(ERROR_INVALID_PARAMETER);
    }
    toolhelp_core = extract_target_process_core_info(target_pid, L"", true);
  } else if (arg_flag == L"-n") {
    toolhelp_core = extract_target_process_core_info(0, arg_value, false);
  } else {
    std::wcerr << L"Error: Invalid flag. Expected -n or -p.\n";
    return static_cast<int>(ERROR_INVALID_PARAMETER);
  }

  if (!toolhelp_core.found) {
    std::wcerr << L"Error: Target process not found.\n";
    return static_cast<int>(ERROR_NOT_FOUND);
  }

  return print_final_report(toolhelp_core.pid, toolhelp_core);
}
