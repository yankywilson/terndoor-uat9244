# TernDoor: Technical Analysis of a CrowDoor Variant Deployed by UAT-9244

**A China-nexus modular backdoor targeting telecommunications providers**

| | |
|---|---|
| **Malware family** | TernDoor (lineage: TernDoor ← CrowDoor ← SparrowDoor) |
| **Threat actor** | UAT-9244 (China-nexus) |
| **Cluster association** | FamousSparrow, Tropic Trooper |
| **Sectors targeted** | Telecommunications |
| **Report date** | June 18, 2026 |
| **Classification** | TLP:CLEAR |
| **Primary public reference** | https://blog.talosintelligence.com/uat-9244/ |

---

## Executive summary

**TernDoor** is a modular Windows backdoor used by **UAT-9244**, a China-nexus espionage actor that overlaps with the **FamousSparrow** and **Tropic Trooper** clusters. It is the latest evolution of a long-running malware lineage that began with **SparrowDoor** and continued through **CrowDoor**.

TernDoor is delivered through **DLL side-loading**. A legitimately signed host executable loads a malicious loader, which decrypts and executes the backdoor entirely in memory. The backdoor establishes persistence, deploys a kernel-mode driver, and **injects itself into `msiexec.exe`**, from which it conducts command-and-control operations.

The backdoor provides a full remote-access toolkit: **remote command execution, file transfer, system reconnaissance, process manipulation via a signed-driver interface, and a command-and-control layer supporting multiple network transports**. Its strings and configuration are obfuscated, and its scheduled-task persistence is actively hidden from standard enumeration.

---

## New in this report

TernDoor was first publicly documented by **Cisco Talos** in March 2026, which established the actor, the lineage, the side-loading chain, the loader decryption key, and the core C2 infrastructure. This analysis corroborates that reporting and adds **three previously undocumented technical findings**:

**1. A five-mode command-and-control transport factory.** Public reporting describes TernDoor's C2 as HTTP/HTTPS. In fact, the backdoor selects among **five transports at runtime** via a bitmask channel selector — direct TCP, two distinct proxy modes, HTTP, and HTTPS — implemented as discrete C++ connection classes (`TcpConn`, `HttpConn`, `HttpsConn`). A connection manager attempts the configured transports in sequence until one succeeds. See [Command and control](#command-and-control).

**2. A custom multi-pass string-deobfuscation routine.** TernDoor obfuscates its strings with a two-pass per-character transform keyed from an embedded 16-byte table. The algorithm and key material are documented here for the first time and are provided as detection selectors. See [String and configuration obfuscation](#string-and-configuration-obfuscation).

**3. A second persistence mechanism via the Task Scheduler COM API.** In addition to the previously reported `schtasks.exe` method, TernDoor can register its scheduled task directly through the **`ITaskService` COM interface** (`RegisterTaskDefinition`), creating the task with no corresponding `schtasks.exe` process. See [Persistence](#persistence).

These three findings rest on independent reverse engineering of the backdoor recovered from an injected `msiexec.exe` process image. Each is tagged **(previously undocumented)** at the relevant point below.

---

## Key findings

- **TernDoor is delivered via DLL side-loading** using a signed host binary (`wsprint.exe`) that loads a malicious loader (`BugSplatRc64.dll`).
- **The loader decrypts its payload with RC4** using the hardcoded key `qwiozpVngruhg123`, then executes it from memory.
- **The backdoor injects into `msiexec.exe`** and verifies this injection context before fully executing.
- **Command-and-control supports five transport modes** — direct TCP, two proxy modes, HTTP, and HTTPS — selected at runtime through a transport factory *(previously undocumented)*.
- **Persistence is established through three mechanisms**: a `schtasks.exe` scheduled task, the Task Scheduler COM API *(previously undocumented)*, and a registry Run key. The scheduled task is hidden through registry manipulation.
- **A kernel-mode driver** (`WSPrint.sys`) exposing the device `\Device\VMTool` is deployed to hide components and suspend, resume, or terminate processes.
- **Strings and configuration are obfuscated** with a custom multi-pass routine *(previously undocumented)*.
- **C2 infrastructure shares a single self-signed TLS certificate** (`CN=8.8.8.8`), which serves as a reliable cluster identifier.

---

## Attribution

TernDoor is assessed to be the work of **UAT-9244**, a **China-nexus** threat actor. Cisco Talos assesses **with high confidence** that UAT-9244 closely overlaps with **FamousSparrow** and **Tropic Trooper**, based on the shared **SparrowDoor → CrowDoor → TernDoor** malware lineage and operational tradecraft. **Simplified Chinese debug strings** in the toolset reinforce the China-nexus assessment.

The lineage is well established. **SparrowDoor** is the backdoor used exclusively by FamousSparrow. **CrowDoor** is a variant first documented in Tropic Trooper intrusions and later attributed to the Earth Estries cluster. **TernDoor** is the current variant, sharing CrowDoor's design while introducing new command codes and capabilities.

Although UAT-9244 and the telecommunications-focused **Salt Typhoon** activity both target the telecom sector, **no verified connection between the two has been established**. TernDoor should not be conflated with Salt Typhoon.

China-nexus espionage operates on a shared-tooling model in which backdoors such as the SparrowDoor/CrowDoor lineage and ShadowPad are distributed across multiple contractors. Shared malware therefore indicates a relationship or common supplier rather than a single operator.

---

## Targeting

UAT-9244 targets **telecommunications providers**, with observed activity against operators in **South America**. The use of valid infrastructure, in-memory execution, signed-driver process manipulation, and multi-mode C2 is consistent with a capable espionage operation focused on persistent network access.

---

## Infection chain

TernDoor's execution proceeds through a side-load, an in-memory decrypt, a drop-and-persist stage, and finally process injection:

| Stage | Component | Action |
|---|---|---|
| 1 | `WSPrint.exe` (signed host) | Loads `BugSplatRc64.dll` via DLL side-loading |
| 2 | `BugSplatRc64.dll` (loader) | Reads `WSPrint.dll`, decrypts it with RC4, executes in memory |
| 3 | TernDoor | Drops its components to `C:\ProgramData\WSPrint\` |
| 4 | TernDoor | Establishes persistence (scheduled task and/or run key) |
| 5 | `C:\ProgramData\WSPrint\WSPrint.exe` | The persisted copy executes on boot |
| 6 | `msiexec.exe` | TernDoor injects into `msiexec.exe` and runs its C2 loop |

TernDoor checks that it has been injected into `msiexec.exe` before fully executing — a behavior inherited from earlier CrowDoor variants.

---

## Loader analysis: BugSplatRc64.dll

The loader is a 64-bit DLL that runs from `DllMain` (it exports no functions) when side-loaded by the signed host `wsprint.exe`.

**Execution flow:**

1. Calls `GetModuleFileName` to obtain the host executable's path.
2. Replaces the file extension to derive the path to the encrypted payload, `WSPrint.dll`, located alongside the host.
3. Allocates executable memory with `VirtualAlloc` (`PAGE_EXECUTE_READWRITE`).
4. Reads `WSPrint.dll` and decrypts it with **RC4** using the hardcoded key **`qwiozpVngruhg123`**.
5. Transfers execution to the decrypted payload in memory.

**Characteristics:**

| Property | Value |
|---|---|
| Decryption | RC4, key `qwiozpVngruhg123` |
| Payload | `WSPrint.dll` (encrypted), read from the host directory |
| API resolution | By hash; resolved at runtime (GetModuleFileName, CreateFile, VirtualAlloc, ReadFile, CloseHandle, and others) |
| Compiler | Microsoft Visual C++ 2019 |
| Packing | None |

The loader resolves its Windows API calls by hash rather than by name, a common technique to hinder static analysis.

---

## Backdoor capabilities

Once executing inside `msiexec.exe`, TernDoor provides the following capabilities. Its numeric command identifiers differ from those of earlier CrowDoor variants.

| Capability | Description |
|---|---|
| **Command execution** | Creates processes and runs arbitrary commands via `CreateProcessW/A`, `CreateProcessAsUserW`, and `ShellExecuteW`, including an interactive remote shell |
| **Process control** | Terminates processes via `TerminateProcess` |
| **File operations** | Reads and writes arbitrary files via `ReadFile` and `WriteFile` |
| **System reconnaissance** | Collects host and user information via `GetComputerNameW` and `GetUserNameW` |
| **Service/driver deployment** | Installs and starts services (`OpenSCManagerW`, `CreateServiceW`, `StartServiceW`), including the kernel driver |
| **Self-uninstall** | Removes its own components from the host |

---

## Command and control

TernDoor implements a **C2 layer that supports five transport modes** *(previously undocumented)*, selected at runtime through a transport factory using a bitmask channel selector. The implementation is built around discrete C++ connection classes — `TcpConn`, `HttpConn`, and `HttpsConn`.

| Selector | Transport | Class |
|---|---|---|
| `0x01` | Direct TCP socket | `TcpConn` |
| `0x04` | Proxy (mode A) | proxy connection class |
| `0x08` | Proxy (mode B) | proxy connection class |
| `0x10` | HTTP | `HttpConn` |
| `0x80` | HTTPS | `HttpsConn` |

The two proxy modes parse a host-and-port pair from the backdoor's configuration. A connection manager attempts the configured transports in sequence until one succeeds.

**Configuration.** TernDoor decodes a configuration structure specifying the **C2 IP address**, the **number of connection retries**, the **C2 port**, and an optional **User-Agent** for HTTP-based traffic.

**Infrastructure.** TernDoor's C2 servers share a single **self-signed TLS certificate** with the subject `CN=8.8.8.8` on port 443. This reused certificate is the most reliable network-level identifier for the cluster. Known C2 servers are listed in the [indicators of compromise](#indicators-of-compromise).

---

## Persistence

TernDoor establishes persistence through up to three mechanisms.

**Scheduled task (command line).** The backdoor creates a SYSTEM-level task that runs at boot:

```
schtasks /create /tn WSPrint /tr "C:\ProgramData\WSPrint\WSPrint.exe" /ru "SYSTEM" /sc onstart /F
```

It then **hides the task** by manipulating the registry under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\WSPrint`, deleting the `SD` value and altering the `Index` value so the task does not appear in standard enumeration.

**Scheduled task (COM API)** *(previously undocumented)***.** TernDoor can also register its task directly through the **Task Scheduler COM interface** (`ITaskService` / `RegisterTaskDefinition`), creating the task without spawning a `schtasks.exe` process. This path produces a scheduled task with no corresponding `schtasks.exe` execution.

**Registry Run key.** A Run key may be set to launch the backdoor at user logon:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Default = C:\ProgramData\WSPrint\WSPrint.exe
```

---

## Kernel driver

TernDoor deploys a kernel-mode driver, **`WSPrint.sys`**, which is **AES-encrypted within the backdoor's shellcode** and decrypted at deployment. The driver exposes the device **`\Device\VMTool`** (symbolically linked to `\DosDevices\VMTool`) and is used to **hide implant components and to suspend, resume, and terminate processes** from kernel space.

---

## String and configuration obfuscation

*(previously undocumented)*

TernDoor obfuscates its strings with a custom multi-pass routine. Each wide character is transformed through an additive-XOR operation, followed by a second position-dependent pass keyed from an embedded 16-byte table. The backdoor decodes its strings in memory at runtime, so the plaintext is recoverable from a memory image of the running process but not from the encrypted on-disk components. The recovered key tables are provided as detection selectors in [`iocs/iocs.md`](iocs/iocs.md).

---

## MITRE ATT&CK

| Tactic | Technique | ID |
|---|---|---|
| Execution | Command and Scripting Interpreter | T1059 |
| Execution | Shared Modules | T1129 |
| Persistence | Scheduled Task | T1053.005 |
| Persistence | Registry Run Keys | T1547.001 |
| Persistence / Priv. Esc. | Windows Service (driver) | T1543.003 |
| Defense Evasion | DLL Side-Loading | T1574.002 |
| Defense Evasion | Process Injection | T1055 |
| Defense Evasion | System Binary Proxy Execution: Msiexec | T1218.007 |
| Defense Evasion | Indicator Removal (task hiding) | T1070 |
| Defense Evasion | Impair Defenses | T1562.001 |
| Defense Evasion | Obfuscated Files or Information | T1027 |
| Discovery | System Owner/User Discovery | T1033 |
| Discovery | System Information Discovery | T1082 |
| Collection | Data from Local System | T1005 |
| Command and Control | Application Layer Protocol: Web | T1071.001 |
| Command and Control | Non-Application Layer Protocol (TCP) | T1095 |
| Command and Control | Proxy | T1090 |

---

## Detection and mitigation

Detection content is provided in this repository:

- **YARA** — loader, in-memory backdoor, transport classes, driver: [`detections/yara/terndoor.yar`](detections/yara/terndoor.yar)
- **Sigma** — side-load, scheduled-task and run-key persistence, task hiding, `msiexec` injection, driver install: [`detections/sigma/`](detections/sigma/)
- **KQL** — hunting queries for Microsoft Defender and Sentinel: [`detections/kql/terndoor-hunting.kql`](detections/kql/terndoor-hunting.kql)
- **Suricata/Snort** — known C2 servers and the reused certificate: [`detections/network/terndoor.rules`](detections/network/terndoor.rules)
- **SOC guide** — full detection and hunting playbook: [`detections/README.md`](detections/README.md)

**Recommended mitigations:**

- Alert on `msiexec.exe` executing without installer arguments and subsequently initiating outbound network connections.
- Monitor for scheduled tasks and services referencing `C:\ProgramData\WSPrint\`, reconciling scheduled tasks against `schtasks.exe` execution to surface the COM-API creation path.
- Block and alert on the known C2 servers and any TLS session presenting the `CN=8.8.8.8` self-signed certificate.
- Restrict and monitor kernel driver installation; investigate any driver exposing `\Device\VMTool`.

---

## Indicators of compromise

A complete, machine-readable indicator set is provided in [`iocs/iocs.md`](iocs/iocs.md). Summary below.

**File hashes (SHA-256)**

```
711d9427ee43bc2186b9124f31cba2db5f54ec9a0d56dc2948e1a4377bada289   BugSplatRc64.dll (loader)
3c098a687947938e36ab34b9f09a11ebd82d50089cbfe6e237d810faa729f8ff   BugSplatRc64.dll (loader)
f36913607356a32ea106103387105c635fa923f8ed98ad0194b66ec79e379a02   BugSplatRc64.dll (loader)
a5e413456ce9fc60bb44d442b72546e9e4118a61894fbe4b5c56e4dfad6055e3   WSPrint.dll (payload)
075b20a21ea6a0d2201a12a049f332ecc61348fc0ad3cfee038c6ad6aa44e744   WSPrint.dll (payload)
1f5635a512a923e98a90cdc1b2fb988a2da78706e07e419dae9e1a54dd4d682b   WSPrint.dll (payload)
2d2ca7d21310b14f5f5641bbf4a9ff4c3e566b1fbbd370034c6844cedc8f0538   WSPrint.sys (driver)
```

**C2 servers**

```
154.205.154.82:443
207.148.121.95:443
207.148.120.52:443
212.11.64.105
216.238.118.179
```

**TLS certificate**

```
Subject:   CN=8.8.8.8 (self-signed)
SHA-256:   0c7e36683a100a96f695a952cf07052af9a47f5898e1078311fd58c5fdbdecc8
SHA-1:     2b170a6d90fceba72aba3c7bc5c40b9725f43788
```

**Host artifacts**

```
Directory:        C:\ProgramData\WSPrint\
Files:            WSPrint.exe, BugSplatRc64.dll, WSPrint.dll, WSPrint.sys
Scheduled task:   WSPrint (SYSTEM, /sc onstart)
Driver device:    \Device\VMTool
Injection host:   C:\Windows\System32\msiexec.exe
RC4 loader key:   qwiozpVngruhg123
```

---

## Repository contents

| Path | Description |
|---|---|
| `README.md` | This intelligence report. |
| `iocs/iocs.md` | Full indicator set with detection selectors. |
| `detections/README.md` | Detection and hunting guide for SOC teams. |
| `detections/yara/terndoor.yar` | YARA rules. |
| `detections/sigma/` | Sigma behavioral rules. |
| `detections/kql/terndoor-hunting.kql` | KQL hunting queries. |
| `detections/network/terndoor.rules` | Suricata/Snort signatures. |

---

## References

1. Cisco Talos — Malhotra, A. & White, B. *UAT-9244 targets South American telecommunication providers with three new malware implants.* March 5, 2026. https://blog.talosintelligence.com/uat-9244/
2. ESET — Côté Cyr, A. *You will always remember this as the day you finally caught FamousSparrow.* March 26, 2025.
3. UK NCSC — *Malware Analysis Report: SparrowDoor.* February 28, 2022.
4. Trend Micro — *Game of Emperor: Unveiling Long-Term Earth Estries Cyber Intrusions.* November 2024.
5. ITOCHU / Macnica (VB2023) — *Unveiling activities of Tropic Trooper 2023.*
