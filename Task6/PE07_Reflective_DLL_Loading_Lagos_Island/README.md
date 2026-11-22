
# [PE 07] NTDLL Image Layout & Hook Integrity — Defensive Analysis

## 1. Technical Overview

This module reviews how `ntdll.dll` is mapped into user-mode processes, how its `.text` section layout relates to on-disk image metadata, and how endpoint security solutions use user-mode API hooking alongside kernel telemetry to observe system calls.

### Research Objectives
- Inspect `ntdll.dll` section metadata (`VirtualAddress`, `PointerToRawData`, `Misc.VirtualSize`) safely with bounds validation.
- Understand how defenders detect modifications to executable module sections or anomalous syscall behavior.
- Maintain clean resource lifecycle management (`UnmapViewOfFile`, `CloseHandle`) and static `/MT` C++20 coding standards.

---

## 2. Windows Internals & Defensive Concepts

`ntdll.dll` provides the user-mode native API layer and syscall stubs in Windows processes:

```text
CreateFileW / CreateFileMappingW / MapViewOfFile (Read-Only)
       │
       ▼
PE64 Header & Section Table Bounds Check (.text)
       │
       ▼
UnmapViewOfFile & CloseHandle (Explicit Cleanup)
```
Integrity & Telemetry: Endpoint security products monitor executable page protection changes, section tampering, and kernel ETW/object callbacks to maintain visibility even when user-mode hooks are altered.

Hardening Controls: Combine protected process configurations, code integrity policies, and sensor-level telemetry rather than relying on a single detection layer.

3. Build Configuration (Release / x64 / /MT)
Select Release and x64 in Visual Studio or CMake.

Set Runtime Library to Multi-threaded (/MT) for static CRT linkage with exceptions and RTTI disabled.

Build and run from a console to inspect ntdll.dll .text section offsets.
