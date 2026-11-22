## 1. Technical Overview

This module reviews Portable Executable (PE) header navigation (`IMAGE_DOS_HEADER::e_lfanew` at offset `0x3C` to `IMAGE_NT_HEADERS`), Windows system call architecture, and how defenders detect header tampering or direct syscall usage via kernel and endpoint telemetry.

### Research Objectives
- Understand how PE parsers locate NT headers via `e_lfanew` and why altering header pointers or syscall paths is a defensive detection signal.
- Review how endpoint security tools detect anomalous memory mappings, section/header inconsistencies, and unauthorized system calls across Windows builds.
- Apply clean C++20 Win32 coding hygiene (`wmain`, static `/MT` linkage, no exceptions/RTTI, and explicit `CloseHandle` cleanup).

---

## 2. Windows Internals & Defensive Concepts

PE files and mapped images use `e_lfanew` to locate `IMAGE_NT_HEADERS`, while user-mode code transitions to kernel services through system call interfaces:

```text
DOS Header (e_lfanew @ 0x3C) -> NT Headers & Sections
       │
       ▼
System Call / Memory Telemetry (ETW, Kernel Callbacks & Stack/Memory Checks)
```
Detection & Telemetry: Build-specific system call numbers vary across Windows versions, and defenders rely on kernel ETW providers, object/process callbacks, and memory integrity checks rather than static API names alone.

Hardening Controls: Enforce code integrity, least-privilege process access, exploit mitigations, and continuous endpoint monitoring.

3. Build Configuration (Release / x64 / /MT)
Select Release and x64 in Visual Studio or CMake.

Set Runtime Library to Multi-threaded (/MT) for static CRT linkage with exceptions and RTTI disabled.

Build and run from a console while notepad.exe is running to inspect process and header telemetry.
