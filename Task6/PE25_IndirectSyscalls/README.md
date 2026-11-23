# [PE 25] Call Stack Integrity & System Call Provenance — Defensive Analysis

## 1. Technical Overview

This module examines how endpoint security solutions perform call-stack walking and return-address/instruction-pointer validation around system calls, and why defenders correlate kernel callbacks, ETW telemetry, and memory integrity checks alongside user-mode module boundaries.

### Research Objectives
- Understand how call-stack inspection evaluates whether a `syscall` instruction originates inside a legitimate system module (`ntdll.dll`) versus an unexpected code range.
- Review defensive telemetry and hardening controls across process handles, memory page protections, and kernel/ETW event streams.
- Apply clean C++20 Win32 coding standards (`wmain`, static `/MT` linkage, no exceptions/RTTI, and explicit `CloseHandle` cleanup).

---

## 2. Windows Internals & Defensive Concepts

Defenders evaluate call stacks, return addresses, and memory regions to detect anomalous control flow into kernel services:

```text
User-Mode Stub / Pointer Target
       │
       ▼
syscall Instruction Location & Call Stack Inspection
       │
       ▼
Kernel / ETW Telemetry & Memory Integrity Checks
```
Telemetry & Detection: Modern security monitoring combines call-stack unwinding, unbacked memory detection (VirtualQueryEx), handle permission audits, and ETW/kernel callbacks to maintain visibility.

Hardening Controls: Enforce least-privilege process access, code integrity and exploit mitigations, and continuous endpoint telemetry.

3. Build Configuration (Release / x64 / /MT + MASM)
Select Release and x64 in Visual Studio or CMake.

Enable MASM build customization for .asm sources and set Runtime Library to Multi-threaded (/MT) with exceptions and RTTI disabled.

Build and run from a console while notepad.exe is running to observe syscall address inspection and memory query status.
