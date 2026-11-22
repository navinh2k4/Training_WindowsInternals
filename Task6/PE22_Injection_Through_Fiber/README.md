
# [PE 22] Win32 Fibers & User-Mode Context Switching — Defensive Analysis

## 1. Technical Overview

This module examines Windows Fibers (`ConvertThreadToFiberEx`, `CreateFiberEx`, `SwitchToFiber`, `DeleteFiber`, `ConvertFiberToThread`), how user-mode cooperative scheduling switches fiber stacks within a single OS thread, and how defenders monitor anomalous execution flow or unbacked code when fibers are abused.

### Research Objectives
- Understand how fibers differ from kernel-scheduled threads: a single OS thread can switch between fiber contexts in user mode without creating additional kernel thread objects.
- Review deterministic fiber cleanup (`DeleteFiber` and `ConvertFiberToThread`) and defensive telemetry around unexpected control-flow transfers.
- Maintain C++20 Win32 coding standards (`wmain`, static `/MT` linkage, no exceptions/RTTI, and explicit resource cleanup).

---

## 2. Windows Internals & Defensive Concepts

Fibers execute on user-mode fiber contexts associated with a host OS thread:

```text
ConvertThreadToFiberEx (Primary Fiber on Current Thread)
       │
       ▼
CreateFiberEx (Secondary Fiber Context & Stack)
       │
       ▼
SwitchToFiber (User-Mode Stack & Register Context Swap)
       │
       ▼
DeleteFiber & ConvertFiberToThread (Deterministic Cleanup)
```
Telemetry & Detection: Because fibers run within an existing thread's identity, defenders rely on memory protection audits (VirtualQueryEx), call-stack/return-address inspection, ETW image/memory events, and API call monitoring rather than thread-creation counts alone.

Hardening Controls: Enforce W^X memory protections, code integrity policies, and continuous endpoint behavioral monitoring.

3. Build Configuration (Release / x64 / /MT)
Select Release and x64 in Visual Studio or CMake.

Set Runtime Library to Multi-threaded (/MT) for static CRT linkage with exceptions and RTTI disabled.

Build and run from a console to observe primary-to-worker fiber switching and cleanup.
