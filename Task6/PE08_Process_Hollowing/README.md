
# [PE 08] Suspended Process Creation & PEB Inspection — Defensive Analysis

## 1. Technical Overview

This module examines how Windows creates a process in a suspended initial state (`CREATE_SUSPENDED`), how the Process Environment Block (PEB) and entry point metadata are laid out in memory, and how defenders monitor suspended process creation, thread context queries, and image replacement patterns.

### Research Objectives
- Understand how `CreateProcessW(..., CREATE_SUSPENDED)` initializes a process and primary thread before execution begins.
- Review PEB and PE64 header inspection (`GetThreadContext`, `ReadProcessMemory`) and explicit handle/process cleanup (`TerminateProcess`, `CloseHandle`).
- Examine detection strategies and mitigations for process hollowing and image masquerading.

---

## 2. Windows Internals & Defensive Concepts

When a process starts with `CREATE_SUSPENDED`, the kernel sets up the address space, loads core system modules, and prepares the initial thread context prior to resuming execution:

```text
CreateProcessW (CREATE_SUSPENDED)
       │
       ▼
PEB & PE64 Entry Point Metadata Inspection
       │
       ▼
TerminateProcess & CloseHandle (Deterministic Cleanup)
```
Telemetry & Detection: Security solutions monitor processes launched in a suspended state, cross-process memory writes or protection changes on section images, and mismatches between on-disk binaries and in-memory image headers.

Hardening Controls: Enforce code integrity policies, monitor parent-child process lineage, and restrict unnecessary cross-process access handles.

3. Build Configuration (Release / x64 / /MT)
Select Release and x64 in Visual Studio or CMake.

Set Runtime Library to Multi-threaded (/MT) for static CRT linkage with exceptions and RTTI disabled.

Build and run from a console to inspect suspended process creation and cleanup.
