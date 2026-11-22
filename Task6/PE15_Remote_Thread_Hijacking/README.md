
# [PE 15] Thread Context Inspection & Execution Flow Telemetry — Defensive Analysis

## 1. Technical Overview

This module examines how Windows enumerates threads within a process (`CreateToolhelp32Snapshot` with `TH32CS_SNAPTHREAD`), how thread execution context (`CONTEXT` and instruction pointer `Rip`) is queried during diagnostics, and how defenders detect thread hijacking or anomalous execution flow changes.

### Research Objectives
- Enumerate process threads safely and distinguish primary vs. secondary threads during diagnostic inspection.
- Understand how thread context queries (`GetThreadContext` / `SetThreadContext`) and unexpected instruction pointer changes relate to endpoint telemetry.
- Follow clean C++20 Win32 coding standards (`wmain`, static `/MT` linkage, no exceptions/RTTI, and explicit `CloseHandle` cleanup).

---

## 2. Windows Internals & Defensive Concepts

Each thread in a Windows process is scheduled by the kernel with its own stack and saved hardware register context:

```text
TH32CS_SNAPTHREAD Enumeration
       │
       ▼
Scoped Thread Query (THREAD_GET_CONTEXT / THREAD_SUSPEND_RESUME)
       │
       ▼
Context & Telemetry Monitoring (ETW / Process & Thread Callbacks)
```
Defensive Detection: Endpoint security tools monitor thread context modifications, calls into unbacked or unexpected memory regions, and suspicious cross-process thread handles.

Hardening Controls: Enforce least-privilege access rights, enable exploit protection policies where applicable, and maintain continuous behavioral telemetry.

3. Build Configuration (Release / x64 / /MT)
Select Release and x64 in Visual Studio or CMake.

Set Runtime Library to Multi-threaded (/MT) for static CRT linkage with exceptions and RTTI disabled.

Build and run from a console while notepad.exe is running to inspect thread enumeration and context telemetry.
