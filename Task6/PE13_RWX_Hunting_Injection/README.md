
# [PE 13] Virtual Memory Region Scanning & Telemetry — Defensive Analysis

## 1. Technical Overview

This module examines how Windows exposes user-mode virtual address space metadata via `VirtualQueryEx` and `MEMORY_BASIC_INFORMATION`, and how defenders analyze memory protection states (`RW`, `RX`, `RWX`) and private allocations to identify anomalous execution activity.

### Key Concepts
- **Virtual Address Space Inspection**: `VirtualQueryEx` reports page state (`MEM_COMMIT`, `MEM_RESERVE`, `MEM_FREE`), region type (`MEM_PRIVATE`, `MEM_MAPPED`, `MEM_IMAGE`), and protection flags.
- **Defensive Telemetry**: Defenders monitor writable-executable (`RWX`) regions, unexpected permission changes on private or image pages, and process handle operations to detect unauthorized code execution.

---

## 2. Mechanism Summary

Windows tracks process memory ranges in page-aligned regions managed by the memory manager. Security monitoring correlates `VirtualQueryEx` scans, ETW events, and thread/process activity to distinguish normal heap/stack usage from suspicious memory patterns while enforcing least-privilege access and `W^X` hygiene.

---

## 3. Build Configuration (Release / x64 / `/MT`)

1. Select **Release** and **x64** in Visual Studio or CMake.
2. Set Runtime Library to **Multi-threaded (`/MT`)** for static CRT linkage with exceptions and RTTI disabled.
3. Build and run from a console while a target `notepad.exe` process is running to inspect memory region metadata.
