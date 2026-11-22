
# [PE 14] Process Image Telemetry & File-Lifecycle Detection — Defensive Analysis

## 1. Technical Overview

This module reviews how Windows tracks process creation, image sections, and backing files, and how endpoint detection and response (EDR) platforms detect unbacked or deleted-file process execution patterns such as image tampering and process ghosting.

### Research Objectives
- Understand how Windows associates processes with image sections and file objects during startup and telemetry collection.
- Examine why defenders correlate process-creation callbacks, image-load events, and file-system metadata rather than relying on a single artifact.
- Apply clean C++20 Win32 coding standards (`wmain`, static `/MT` linkage, no exceptions/RTTI, and explicit `CloseHandle` cleanup).

---

## 2. Windows Internals & Defensive Concepts

During process creation, the Windows kernel initializes process and thread objects, maps image sections, and emits telemetry through kernel callbacks and ETW providers:

```text
Process & Thread Enumeration (Toolhelp32)
       │
       ▼
Scoped Process Query (PROCESS_QUERY_LIMITED_INFORMATION)
       │
       ▼
Kernel Callbacks, ETW & File/Image Telemetry
```
Telemetry & Detection: Defenders monitor anomalies such as processes whose image lacks a backing file on disk, mismatches between reported image paths and mapped sections, and suspicious parent-child relationships.

Hardening Controls: Enforce code integrity policies, monitor kernel/ETW process and image events, and apply least-privilege handle and access controls.

3. Build Configuration (Release / x64 / /MT)
Select Release and x64 in Visual Studio or CMake.

Set Runtime Library to Multi-threaded (/MT) for static CRT linkage with exceptions and RTTI disabled.

Build and run from a console to inspect active process and PEB telemetry.
