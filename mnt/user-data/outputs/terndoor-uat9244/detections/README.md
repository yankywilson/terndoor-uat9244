# Defending Against TernDoor — SOC Detection & Hunting Guide

**Audience:** SOC analysts, detection engineers, threat hunters.
**TLP:CLEAR** · Reference: https://blog.talosintelligence.com/uat-9244/

---

## Read this first — three operating realities

**1. "WSPrint" is also a legitimate product name.** TernDoor deliberately masquerades under it. **Never alert on the `WSPrint` path alone.** Every rule here pairs it with a hard malicious indicator: the loader `BugSplatRc64.dll`, the driver `WSPrint.sys`, the `SYSTEM`+`onstart` task, an `msiexec` anomaly, or a known C2 server.

**2. There is no reliable C2 payload signature.** Network detection is **infrastructure-based** — the published C2 servers and the reused `CN=8.8.8.8` self-signed certificate — not protocol-content-based.

**3. The implant lives inside `msiexec.exe`.** On-disk scanning of the loader and payload is necessary but not sufficient. **Memory scanning of `msiexec.exe`** is where the YARA implant rules apply.

---

## Coverage map (by ATT&CK phase)

| Phase | Behavior | Detection |
|---|---|---|
| Execution / Defense Evasion | DLL side-load (`wsprint.exe` → `BugSplatRc64.dll`) | Sigma `sideload_imageload`; KQL #3; YARA loader |
| Persistence | schtasks `WSPrint` SYSTEM/onstart | Sigma `schtasks_persistence`; KQL #1 |
| Persistence | ITaskService COM task | host telemetry — see "COM persistence" |
| Persistence | registry run key | Sigma `runkey_persistence`; KQL #7 |
| Persistence / Drop | files to `ProgramData\WSPrint` | Sigma `programdata_drop`; KQL #2 |
| Defense Evasion | `msiexec.exe` injection / anomaly | Sigma `msiexec_injection`; KQL #4 |
| Defense Evasion | TaskCache task-hiding | Sigma `taskcache_hiding`; KQL #6 |
| Priv. Esc / Evasion | driver `WSPrint.sys` / `\Device\VMTool` | Sigma `driver_service`; KQL #8; YARA driver |
| Command and Control | known C2 servers / reused cert | network rules; KQL #5 |
| Identification | implant in memory | YARA implant + RTTI + key-table rules |

---

## Strongest single detections (deploy first)

1. **The RC4 key string** `qwiozpVngruhg123` — published, hardcoded, near-zero-FP. The YARA loader rule keys on it. Sweep hosts and sample repositories.
2. **The schtasks command** — `ProgramData\WSPrint\WSPrint.exe` + `SYSTEM` + `onstart` in one `schtasks /create`. (Sigma `schtasks_persistence`, KQL #1.)
3. **The side-load pairing** — `wsprint.exe` loading `BugSplatRc64.dll`. (Sigma `sideload_imageload`, KQL #3.)
4. **The reused certificate** — `CN=8.8.8.8` self-signed on 443, or the leaf fingerprint `0c7e3668…`. (Network rules sid 9000006/9000007.)

---

## Hunting playbook

**Hunt A — anomalous `msiexec`.** Legitimate `msiexec.exe` runs with installer arguments (`/i`, `/x`, `/q`, a `.msi` path). TernDoor's injected `msiexec` ran as **bare `msiexec.exe`** and acted as the C2 host. Hunt for `msiexec` with no installer args that **subsequently makes outbound network connections** (KQL #4). Highest-value behavioral hunt; resilient to file renaming.

**Hunt B — driver + device.** Any kernel driver exposing `\Device\VMTool` is anomalous. Hunt for `WSPrint.sys` loads and `VMTool` device creation (KQL #8). The driver is AES-encrypted in shellcode and used to suspend/resume/terminate processes — pair with process-tampering telemetry.

**Hunt C — COM persistence.** Beyond `schtasks.exe`, TernDoor can create its task through the **Task Scheduler COM API** (`ITaskService` → `RegisterTaskDefinition`), producing a task **without** a `schtasks.exe` process. Enumerate scheduled tasks pointing to `ProgramData\WSPrint\` and reconcile against process-creation telemetry: a `WSPrint` task that exists with **no corresponding `schtasks.exe` execution** indicates the COM path.

**Hunt D — memory sweep.** Run the YARA implant rules (`TernDoor_Implant_Memory_Strings`, `TernDoor_Implant_RTTI_Transport_Classes`, `TernDoor_StringDeob_KeyTables`) against **`msiexec.exe` process memory** fleet-wide.

**Hunt E — infrastructure retro-hunt.** Sweep proxy/firewall/Zeek logs for the published C2 servers and the `216.238.118.179` node, and for TLS sessions presenting the `CN=8.8.8.8` / `0c7e3668…` certificate (network rules; KQL #5). Pivot new hits on the **reused keypair**, not on CN/SNI/JA3.

---

## Containment and response

- **Isolate** hosts with confirmed `ProgramData\WSPrint\` components or anomalous `msiexec` C2.
- **Remove persistence:** delete the `WSPrint` scheduled task (check **both** the task store and the registry `TaskCache`, since it may be hidden), and the `HKCU\...\Run\Default` value if present.
- **Unload and remove the driver** (`WSPrint.sys` / `\Device\VMTool`); validate no other process-tampering persists.
- **Hunt laterally** for the same certificate and C2 across the estate — this actor reuses one keypair.
- **Credential hygiene:** the task runs as `SYSTEM`; assume local privilege and rotate affected secrets.

---

## Limitations

- **Live C2 traffic by content** is not characterized; rely on the IP/certificate infrastructure rules.
- **New samples with a different RC4 key or renamed components** evade the string/key rules; the behavioral rules (msiexec anomaly, side-load relationship, task/driver behavior) are the durable layer.
