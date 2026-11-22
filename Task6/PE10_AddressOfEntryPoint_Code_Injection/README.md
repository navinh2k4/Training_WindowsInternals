
# [PE 10] Entry Point Metadata & Process Execution Telemetry — Defensive Analysis

## 1. Technical Overview

This module examines how Windows initializes a process in a suspended state (`CREATE_SUSPENDED`), how `ImageBase` and `AddressOfEntryPoint` are defined in PE64 headers, and how endpoint security solutions detect modifications to image code or unexpected entry-point redirection.

### Research Objectives
- Inspect `ImageBase` and `AddressOfEntryPoint` metadata for a suspended x64 process safely with bounds checking.
- Understand how defenders detect unauthorized edits to `MEM_IMAGE` pages or deviations from normal entry-point execution.
- Apply clean C++20 Win32 hygiene (`wmain`, static `/MT` linkage, no exceptions/RTTI, and explicit resource cleanup).

---

## 2. Windows Internals & Defensive Concepts

In a PE64 image, `AddressOfEntryPoint` specifies the relative virtual address (RVA) where execution begins after image mapping:

```text
CreateProcessW (CREATE_SUSPENDED)
       │
       ▼
PEB & PE64 OptionalHeader Inspection (ImageBase + AddressOfEntryPoint)
       │
       ▼
TerminateProcess & CloseHandle (Explicit Cleanup)
```
Telemetry & Detection: Defenders monitor suspended process creation, writes or protection changes against mapped MEM_IMAGE sections, and image-load or process-creation telemetry.

Hardening Controls: Enforce code integrity policies, monitor process creation chains, and restrict unnecessary cross-process handle permissions.

3. Build Configuration (Release / x64 / /MT)
Select Release and x64 in Visual Studio or CMake.

Set Runtime Library to Multi-threaded (/MT) for static CRT linkage with exceptions and RTTI disabled.

Build and run from a console to inspect entry-point metadata and cleanup.
