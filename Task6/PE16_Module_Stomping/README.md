
# [PE 16] Loaded Module & Image Section Telemetry — Defensive Analysis

## 1. Technical Overview

This module reviews how Windows maps `MEM_IMAGE` modules into process address spaces, how defenders inspect loaded module lists (`TH32CS_SNAPMODULE`) and image sections, and why endpoint detection platforms flag modifications to executable image pages or mismatches between disk binaries and in-memory code.

### Research Objectives
- Enumerate loaded modules in a target process safely using `CreateToolhelp32Snapshot` and least-privilege `OpenProcess` rights (`PROCESS_QUERY_LIMITED_INFORMATION`).
- Understand how security tools detect tampering with image-backed executable pages (such as module stomping or section overwrites) and unbacked private memory.
- Apply clean C++20 Win32 coding standards (`wmain`, static `/MT` linkage, no exceptions/RTTI, and explicit `CloseHandle` cleanup).

---

## 2. Windows Internals & Defensive Concepts

When Windows maps a DLL or executable image, the memory manager associates the range with `MEM_IMAGE` and tracks it in loader structures and kernel telemetry:

```text
Process & Module Enumeration (TH32CS_SNAPMODULE)
       │
       ▼
Base Address & Image Size Inspection
       │
       ▼
Image Integrity & Memory Telemetry (ETW / VirtualQueryEx)
```
Telemetry & Detection: Defenders monitor unexpected module loads, writes or protection changes against MEM_IMAGE sections, and discrepancies between file bytes on disk and mapped image bytes in memory.

Hardening Controls: Enforce code integrity policies, arbitrary code guard (ACG) and control flow guard (CFG) where supported, least-privilege handle access, and continuous endpoint monitoring.

3. Build Configuration (Release / x64 / /MT)
Select Release and x64 in Visual Studio or CMake.

Set Runtime Library to Multi-threaded (/MT) for static CRT linkage with exceptions and RTTI disabled.

Build and run from a console while notepad.exe is running to inspect loaded module metadata.
