# Windows Internals - PE Injection Labs (PE01 to PE10)

This folder contains 10 progressive labs focused on Windows process memory manipulation, API evasion, and stealthy code execution. All modules are built for **Native Windows x64** with strict memory hygiene (zero static buffers, two-step allocation, and no handle leaks).

---

## Lab Progression

| Lab | Name | Description |
| :---: | :--- | :--- |
| **PE01** | Classic Code Injection (Local) | Allocate memory inside the current process, write shellcode, and execute it via a new thread. |
| **PE02** | Classic Code Injection (Remote) | Inject shellcode into a remote process using `VirtualAllocEx`, `WriteProcessMemory`, and `CreateRemoteThread`. |
| **PE03** | Classic Code Injection with API Obfuscate | Remote injection without using `GetProcAddress`. Manually parse the EAT (Export Address Table) of `ntdll.dll` to resolve native APIs. |
| **PE04** | Classic Code Injection Remote with VP | Remote injection with explicit page protection handling (`VirtualProtectEx` to set `PAGE_EXECUTE_READWRITE`). |
| **PE05** | Classic DLL Injection | Force a remote process to load a malicious DLL via `LoadLibraryA` using `CreateRemoteThread`. |
| **PE06** | Reflective DLL Injection | Manual DLL mapping from memory. Write Position-Independent Code (PIC) to handle `.reloc` (base relocations), resolve IAT, and call `DllMain` without writing to disk. |
| **PE07** | Reflective DLL Loading (Lagos Island) | Advanced reflective loader with enhanced relocation and dependency handling (Lagos Island variant). |
| **PE08** | Process Hollowing | Create a suspended process, unmap its original PE, map a new PE into memory, and hijack the main thread using a **22-byte JMP stub**. |
| **PE09** | PE Code Injection | Overwrite existing code sections (.text) inside a remote PE with custom shellcode. |
| **PE10** | AddressOfEntryPoint Code Injection | Hijack execution flow by directly overwriting the `AddressOfEntryPoint` field in the remote process's PE headers. |

---

## Key Technical Principles

- **Zero Static Buffers**: No fixed-size arrays like `WCHAR buf[256]`. Every string is dynamically allocated using a **two-step boundary discovery** (call API with `NULL` → get exact size → allocate precise `std::vector`).
- **Memory Safety**: Every handle is closed (`CloseHandle`) and every heap allocation is freed to prevent leaks.
- **Position-Independent Code (PIC)**: All shellcode payloads are written to run safely in remote memory without RIP-relative boundary crashes.
- **Direct Syscalls**: Some modules use raw `syscall` instructions to bypass user-mode EDR hooks.

---

## Build Instructions

- **Architecture**: Native Windows x64
- **Configuration**: Release x64
- **Runtime Library**: Multi-threaded (`/MT`) - static linking for independent execution on any VM.

> All commits are tagged with: *"feat: optimize virtual memory allocation and harden local injection logic"* - ensuring consistent code quality across all 10 labs.

---

## Requirements

- **OS**: Windows 10 / Windows 11 (x64)
- **Compiler**: Visual Studio 2019 or later (with C++17 support)
- **SDK**: Windows SDK (10.0+)

---

## Disclaimer

These labs are built strictly for **educational and research purposes**. They are designed to help security professionals understand Windows internals, offensive execution techniques, and memory forensics. Use only in isolated lab environments.
