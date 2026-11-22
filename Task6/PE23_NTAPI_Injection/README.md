
# [PE 23] Native API Layer (`ntdll.dll`) & Endpoint Telemetry — Defensive Analysis

## 1. Technical Overview

This module examines the relationship between documented Win32 APIs and native routines exported by `ntdll.dll` (`Nt*` / `Zw*`), and explains why modern endpoint detection and response (EDR) platforms rely on kernel callbacks, ETW providers, and memory/handle telemetry rather than single user-mode API hooks alone.

### Research Objectives
- Understand how Win32 APIs layer over `ntdll.dll` native routines to transition from user mode to kernel services.
- Review why defenders monitor process handle permissions, virtual memory state changes, and thread/ETW events across user-mode layers.
- Apply clean C++20 Win32 coding standards (`wmain`, static `/MT` linkage, no exceptions/RTTI, and explicit `CloseHandle` cleanup).

---

## 2. Windows Internals & Defensive Concepts

In Windows, user-mode calls pass through subsystem DLLs and `ntdll.dll` before invoking system calls into the kernel:

```text
Win32 API Wrapper (kernel32 / KernelBase)
       │
       ▼
Native Routine in ntdll.dll (Nt* / Zw*)
       │
       ▼
Kernel Transition & Telemetry (ETW, Object/Process/Thread Callbacks)
```
Telemetry & Detection: Security solutions correlate kernel process/thread/image callbacks, ETW memory and thread events, and suspicious cross-process handle requests (PROCESS_VM_WRITE, PROCESS_VM_OPERATION, PROCESS_CREATE_THREAD) to detect unauthorized cross-process activity.

Hardening Controls: Enforce least-privilege handle scoping, code integrity and exploit protection policies, and continuous endpoint telemetry.

3. Build Configuration (Release / x64 / /MT)
Select Release and x64 in Visual Studio or CMake.

Set Runtime Library to Multi-threaded (/MT) for static CRT linkage with exceptions and RTTI disabled.

Build and run from a console while notepad.exe is running to observe native memory query telemetry.
