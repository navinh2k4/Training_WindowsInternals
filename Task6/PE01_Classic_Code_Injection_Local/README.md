# [PE 01] Local Process Memory & Thread Behavior — Defensive Analysis

## 1. Technical Overview

This module examines local process virtual memory allocation, page protection transitions, and secondary thread execution within Windows user mode. From a defensive engineering perspective, understanding how private memory pages and thread start addresses behave helps analysts distinguish legitimate runtime behavior from anomalous memory patterns (such as writable-executable regions or unexpected thread entry points).

### Research Objectives
- Observe Windows user-mode virtual memory page allocation and protection states (`VirtualAlloc`, `VirtualProtect`).
- Review thread creation and synchronization semantics (`CreateThread`, `WaitForSingleObject`).
- Apply defensive memory hygiene such as Write XOR Execute (`W^X`) separation and explicit handle/memory cleanup.

---

## 2. Windows Internals & Defensive Concepts

Windows tracks virtual address space in page granularity using `MEM_RESERVE` and `MEM_COMMIT` states:

```text
VirtualAlloc (PAGE_READWRITE)
       │
       ▼
VirtualProtect (PAGE_EXECUTE_READ)  ──► Enforces W^X separation
       │
       ▼
CreateThread / WaitForSingleObject  ──► Thread scheduling & cleanup
```
Page Allocation & Protection (VirtualAlloc / VirtualProtect): Allocating memory directly with PAGE_EXECUTE_READWRITE (RWX) is a common telemetry indicator for defenders. Transitioning from PAGE_READWRITE to PAGE_EXECUTE_READ avoids leaving writable executable pages exposed.

Thread Lifecycle & Cleanup: Secondary threads execute under the process token and must be synchronized and closed via CloseHandle, while allocated virtual regions are released with VirtualFree(..., MEM_RELEASE).

3. Build Configuration (Release / x64 / /MT)
Select Release and x64 in Visual Studio or CMake.

Set Runtime Library to Multi-threaded (/MT) for static CRT linkage.

Build the executable and run it from a console or debugger to inspect memory protections and thread state.

4. Defensive Inspection & Mitigations
Memory & Thread Telemetry: Analysts inspect private memory commitments, page protection changes, and thread creation events to detect unauthorized code execution patterns.

Hardening Controls: Enforce W^X page permissions, enable exploit protection policies (such as ACG / CFG where applicable), and restrict unnecessary cross-process or elevated handles.
