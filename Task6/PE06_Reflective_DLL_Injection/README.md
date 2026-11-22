
# [PE 06] PE64 Structure Parsing & In-Memory Telemetry — Defensive Analysis

## 1. Technical Overview

This module reviews Portable Executable (PE32+) structure parsing—including DOS headers, NT headers, section tables, export directories, and base relocations—alongside defensive visibility into in-memory modules and unbacked executable regions.

### Research Objectives
- Understand how PE32+ headers, section RVAs/raw offsets, export tables, and relocation blocks are structured.
- Examine how endpoint security tools detect unbacked code execution or discrepancies between loaded module lists and mapped memory regions.
- Follow defensive coding hygiene (`wmain`, static `/MT` linkage, no exceptions/RTTI, and explicit handle/heap cleanup).

---

## 2. Windows Internals & Defensive Concepts

In Windows, the OS loader maps PE images from disk according to section alignment and relocation entries, registering loaded modules in the process loader structures.

```text
PE32+ Header & Section Parsing (RVA <-> Raw Offset)
       │
       ▼
Export / Relocation / Import Metadata Inspection
       │
       ▼
Defensive Telemetry (Module List vs. Private/Unbacked Memory)
```
Module vs. Private Memory Discrepancies: Defenders correlate Ldr module lists, ETW image-load events, and memory region scans (VirtualQueryEx) to identify unbacked or manually mapped executable pages.

Hardening Controls: Enable process mitigation policies (such as CFG/ACG where supported), code integrity enforcement, and continuous EDR behavioral monitoring.

3. Build Configuration (Release / x64 / /MT)
Select Release and x64 in Visual Studio or CMake.

Set Runtime Library to Multi-threaded (/MT) for static CRT linkage.

Build the executable and run it from a console to inspect PE64 metadata and target process handle status.
