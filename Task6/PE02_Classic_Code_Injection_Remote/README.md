# [PE 02] Cross-Process Virtual Memory & Handle Security — Defensive Analysis

## 1. Technical Overview

This module examines how Windows isolates virtual address spaces across processes and how access rights govern cross-process memory operations (`OpenProcess`, `VirtualAllocEx`, `VirtualProtectEx`, `VirtualFreeEx`). Understanding these mechanisms helps defenders detect unauthorized cross-process memory allocation, permission transitions, or thread creation patterns.

### Research Objectives
- Review process discovery via Toolhelp snapshots and least-privilege handle requests (`PROCESS_QUERY_LIMITED_INFORMATION`, `PROCESS_VM_OPERATION`).
- Observe cross-process virtual memory allocation and page protection states without exposing writable-executable (`RWX`) regions.
- Verify deterministic cleanup of remote allocations and process handles.

---

## 2. Windows Internals & Defensive Concepts

Windows enforces virtual memory isolation per process using page tables and object access checks:

```text
CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS)
       │
       ▼
OpenProcess (scoped access rights)
       │
       ▼
VirtualAllocEx / VirtualProtectEx  ──► Avoid RWX; release via VirtualFreeEx
       │
       ▼
CloseHandle                        ──► Release object handle reference
```

Scoped Handle Access: Requesting only the minimum required access rights limits exposure and aligns with least-privilege operational hygiene.

Page Protection Hygiene: Avoiding PAGE_EXECUTE_READWRITE and releasing remote allocations with MEM_RELEASE prevents lingering private memory regions in target processes.

3. Build Configuration (Release / x64 / /MT)
Select Release and x64 in Visual Studio or CMake.

Set Runtime Library to Multi-threaded (/MT) for static CRT linkage.

Build the executable and run it while a target notepad.exe instance is active to observe memory regions and cleanup.

4. Defensive Telemetry & Mitigations
Detection Focus: Security monitoring tracks cross-process memory allocation, protection changes, and remote thread creation across sensitive or unrelated processes.

Hardening Controls: Apply process access protection policies, enforce W^X memory controls, and audit privileged handle usage.
