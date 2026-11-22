
# [PE 11] Asynchronous Procedure Calls (APC) & Thread Queue Telemetry — Defensive Analysis

## 1. Technical Overview

This module examines Windows Asynchronous Procedure Calls (APCs), per-thread APC queues, and early-stage thread initialization behavior (`CREATE_SUSPENDED` and `QueueUserAPC`) from a defensive engineering standpoint. Understanding how queued APCs interact with thread scheduling helps security analysts detect anomalous cross-thread or early-bird execution patterns.

### Research Objectives
- Review how Windows threads maintain kernel-managed APC queues and drain pending callbacks during thread dispatch or alertable states.
- Understand why early-stage queue manipulation on newly created processes is a high-value telemetry signal for EDR and kernel monitoring.
- Maintain clean C++20 Win32 coding standards (`wmain`, static `/MT` linkage, no exceptions/RTTI, and explicit `HeapAlloc`/`HeapFree`/`CloseHandle` cleanup).

---

## 2. Windows Internals & Defensive Concepts

Each Windows thread has a kernel `KTHREAD` structure containing user-mode and kernel-mode APC queues:

```text
CreateProcessW (CREATE_SUSPENDED)
       │
       ▼
QueueUserAPC (Enqueues KAPC on Target Thread)
       │
       ▼
Thread Dispatch / Alertable State Drain ──► Endpoint & Kernel Telemetry
```
APC Queue & Scheduling: Queued user-mode APCs run in the context of the target thread when the thread enters an alertable wait or during initial thread dispatch before user entry code runs.

Defensive Detection & Hardening: Defenders monitor suspended child-process creation, cross-process APC queuing (QueueUserAPC / NtQueueApcThread), and unbacked memory execution. Applying least-privilege process access, code integrity policies, and continuous endpoint telemetry reduces exposure.

3. Build Configuration (Release / x64 / /MT)
Select Release and x64 in Visual Studio or CMake.

Set Runtime Library to Multi-threaded (/MT) for static CRT linkage with exceptions and RTTI disabled.

Build and run from a console to observe suspended process setup, APC queuing, and explicit handle cleanup.
