# Training Windows Internals

This repository contains my personal lab work for learning **Windows OS internals**, **native API programming**, and **offensive security research**. All projects are written in **C++ (x64)** with strict memory-safety rules.

---

## Repository Structure

| Folder | Description |
| :--- | :--- |
| **Task2-Tasklist** | Clone of `tasklist.exe` – enumerates running processes and their details. |
| **Task3-SystemInfo** | Clone of `systeminfo.exe` – retrieves hardware and OS configuration. |
| **Task4-ProcessInfo** | Advanced process metadata collector (token privileges, session info, etc.). |
| **Task5_PEParser** | Static PE file parser – extracts headers, sections, import/export tables, and Rich Header. |
| **Task6** | **10 PE Injection Labs** – from basic local injection to advanced process hollowing and reflective DLL loading (see details below). |
| `.github/workflows` | CI pipeline for automatic portfolio updates (optional). |

---

## Task6 – PE Injection Labs (PE01 to PE10)

This is the core of the repository – a step‑by‑step journey through process memory manipulation and code execution redirection.

| Lab | Focus |
| :---: | :--- |
| **PE01** | Local code injection (same process) |
| **PE02** | Remote code injection (`VirtualAllocEx` / `CreateRemoteThread`) |
| **PE03** | Remote injection with **API obfuscation** (manual EAT parsing, direct syscalls) |
| **PE04** | Remote injection with explicit page protection management |
| **PE05** | Classic DLL injection via `LoadLibraryA` |
| **PE06** | **Reflective DLL injection** – manual mapping from memory (PIC) |
| **PE07** | Advanced reflective loader (Lagos Island variant) |
| **PE08** | **Process Hollowing** – suspend, unmap, inject new PE, hijack thread |
| **PE09** | Overwrite existing `.text` section with custom shellcode |
| **PE10** | Overwrite `AddressOfEntryPoint` to redirect execution flow |

---

## Key Engineering Principles (applied to ALL labs)

- **Zero static buffers** – no fixed `WCHAR buf[256]`.
- **Two-step dynamic allocation** – call API with `NULL` → get exact size → allocate `std::vector` precisely.
- **Resource hygiene** – every handle closed (`CloseHandle`), every heap block freed.
- **Position‑Independent Code (PIC)** – all payloads are relocatable and safe for remote memory.
- **Native x64 / Release / Multi‑threaded (/MT)** – static linking for clean VM execution.

---

## Build & Run

- **IDE**: Visual Studio 2019/2022
- **Solution**: `Training_WindowsInternals.slnx`
- **Configuration**: `Release x64`
- Each project is standalone – open the solution, build the desired module, and run.

---

## Disclaimer

This repository is for **educational and research purposes only**. All techniques are studied in isolated lab environments to understand Windows internals, malware analysis, and defensive countermeasures. Do not use any code on systems without explicit permission.
