
# [PE 05] Dynamic Link Library Loading & Process Telemetry — Defensive Analysis

## 1. Technical Overview

This module reviews how Windows loads Dynamic Link Libraries (`.dll`) into a process address space via the Windows PE Loader (`LoadLibrary` / `LdrLoadDll`) and how defenders monitor module loading and cross-process activity.

### Research Objectives
- Understand how Windows maps PE modules, resolves imports, and invokes `DllMain` (`DLL_PROCESS_ATTACH`).
- Review how process enumeration (`CreateToolhelp32Snapshot`) and scoped process handles (`PROCESS_QUERY_LIMITED_INFORMATION`) support defensive inspection.
- Examine detection strategies for unexpected module loads and remote thread creation events.

---

## 2. Windows Internals & Defensive Concepts

When a module is loaded into a process, the Windows PE Loader maps image sections, applies relocations if needed, resolves imported symbols, and notifies `DllMain` on `DLL_PROCESS_ATTACH`.

```text
Target Process Discovery (Toolhelp32)
       │
       ▼
Scoped Handle Query (PROCESS_QUERY_LIMITED_INFORMATION)
       │
       ▼
PE Loader & Module Telemetry (Loaded Modules / Sysmon Event 7 / ETW)
```
Loader Lock & DllMain: DllMain executes under the loader lock; keeping initialization minimal and avoiding blocking calls prevents deadlocks.

Defensive Monitoring: Defenders monitor loaded module lists, unsigned or unusual DLL paths, and cross-process thread creation (CreateRemoteThread / kernel callbacks).

3. Build Configuration (Release / x64 / /MT)
Select Release and x64 in Visual Studio or CMake.

Set Runtime Library to Multi-threaded (/MT) for static CRT linkage.

Build the project and run the binary from a console to observe module path resolution and process lookup behavior.

4. Mitigations & Hardening
Enforce DLL search path hardening (SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_* flags where applicable).

Enable code integrity and process mitigation policies (such as ACG or CFG) to restrict unauthorized module loads and code execution.
