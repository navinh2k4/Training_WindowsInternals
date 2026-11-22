
# [PE 24] x64 System Call Mechanics & Kernel Telemetry — Defensive Analysis

## 1. Technical Overview

This module examines how Windows x64 user-mode code transitions to kernel mode via the `syscall` instruction (`mov r10, rcx`, System Service Number in `eax`, `syscall`), why System Service Numbers (SSNs) vary across Windows builds, and how endpoint security solutions detect anomalous syscall activity through kernel and ETW telemetry.

### Research Objectives
- Understand the x64 calling convention and `syscall` register setup (`r10`, `eax`) and why hardcoding SSNs is brittle across OS versions.
- Review how defenders monitor process handles, memory protections, call stacks, and ETW/kernel events when user-mode `ntdll.dll` stubs are bypassed.
- Maintain clean C++20 Win32 coding standards (`wmain`, static `/MT` linkage, no exceptions/RTTI, and explicit `CloseHandle` cleanup).

---

## 2. Windows Internals & Defensive Concepts

On x64 Windows, user-mode native stubs stage parameters according to the x64 ABI before executing `syscall`:

```text
User-Mode Caller (x64 ABI: rcx, rdx, r8, r9, stack)
       │
       ▼
Stub Setup (mov r10, rcx; mov eax, SSN; syscall)
       │
       ▼
Kernel Transition & Telemetry (ETW, Kernel Callbacks & Stack/Memory Checks)
```
Telemetry & Detection: Modern EDRs rely on kernel callbacks, ETW providers, stack walking / return-address validation, and memory integrity checks so detection does not depend solely on hooks inside ntdll.dll.

Hardening Controls: Enforce least-privilege handle permissions, code integrity policies, exploit mitigations, and continuous endpoint telemetry.

3. Build Configuration (Release / x64 / /MT + MASM)
Select Release and x64 in Visual Studio or CMake.

Enable MASM build customization for .asm sources and set Runtime Library to Multi-threaded (/MT) with exceptions and RTTI disabled.

Build and run from a console while notepad.exe is running to observe process lookup and memory query status.
