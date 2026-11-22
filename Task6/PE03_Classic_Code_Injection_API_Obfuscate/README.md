# [PE 03] Dynamic Symbol Resolution & Static Detection — Defensive Analysis

## 1. Technical Overview

This module reviews dynamic API resolution and string representation in Windows binaries from a defensive detection perspective. Security analysts examine how dynamic symbol lookup affects static signature visibility and how runtime telemetry captures process and module activity regardless of string encoding.

### Core Concepts
- **Static vs. Dynamic Symbol Visibility**: Static import tables and plain-text strings provide immediate indicators, while runtime symbol resolution shifts analysis toward behavioral and memory telemetry.
- **Defensive Telemetry**: Monitoring API usage, module resolution, and cross-process access patterns provides visibility even when static strings are absent.

---

## 2. Mechanism Summary

Binaries may resolve module exports dynamically at runtime rather than relying solely on static imports, while stack-constructed character arrays avoid embedding contiguous string literals in `.rdata`. Defenders counter this by correlating process lineage, handle requests, and memory protection transitions rather than relying exclusively on static strings.

---

## 3. Build & Hardening Notes

- Compile with **Release**, **x64**, and static CRT (`/MT`) with exceptions and RTTI disabled.
- Apply defense-in-depth controls such as process hardening policies, least-privilege execution, and endpoint telemetry monitoring.
