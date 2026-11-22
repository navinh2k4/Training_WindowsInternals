
# [PE 20] Image Section Characteristics & RWX Auditing — Defensive Analysis

## 1. Technical Overview

This module inspects PE section flags (`IMAGE_SECTION_HEADER::Characteristics`) in mapped modules to audit writable-executable (`RWX`) misconfigurations and understand how defenders detect code staging inside image-backed memory regions (`MEM_IMAGE`).

### Key Concepts
- **Section Permission Auditing**: Modern binaries separate executable code (`.text`, read-execute) from mutable data (`.data`, read-write); unintended `RWX` sections increase exploitation and evasion risk.
- **Defensive Telemetry & Hardening**: Defenders monitor modifications to `MEM_IMAGE` sections, anomalous execution paths in third-party DLLs, and linker hardening flags (`/NXCOMPAT`, `/DYNAMICBASE`, proper section separation).

---

## 2. Mechanism Summary

PE loaders map image sections according to section alignment and characteristics flags. Security auditing identifies `RWX` sections at build/review time and correlates runtime memory integrity checks with process and module telemetry.

---

## 3. Build Configuration (Release / x64 / `/MT`)

1. Select **Release** and **x64** in Visual Studio or CMake.
2. Set Runtime Library to **Multi-threaded (`/MT`)** for static CRT linkage with exceptions and RTTI disabled.
3. Build and run from a console to inspect section attributes on a system module.
