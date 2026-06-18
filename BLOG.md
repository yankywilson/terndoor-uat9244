# Hunting TernDoor: From a Salt Typhoon False Lead to a Full Backdoor Teardown

*A long-cycle CTI/DFIR investigation into UAT-9244 — the infrastructure hunt, the attribution, the reverse engineering, and the three things the public reporting missed.*

**TLP:CLEAR** · Companion to the [TernDoor / UAT-9244 intelligence report](README.md) and [reverse-engineering analysis](REVERSE-ENGINEERING.md).

---

## Why this writeup exists

Most malware blogs show you the destination — the IOCs, the capabilities, a clean diagram. This one shows the **road**, because the road is where the lessons are.

This investigation started as a **Salt Typhoon** infrastructure hunt and ended somewhere else entirely: a complete teardown of **TernDoor**, a China-nexus modular backdoor used by **UAT-9244**, with **three technical findings that aren't in the public reporting**. Along the way it produced a handful of false leads that were caught and killed — a fake C2 beacon that turned out to be a Windows component phoning home, three infrastructure pivots that dissolved into commodity noise, and a memory artifact that another tool mislabeled as the implant.

The dead ends matter as much as the wins. They're in here too.

---

## Part 1 — The infrastructure hunt

### The starting assumption was wrong, and that's fine

The hunt began under the **Salt Typhoon** banner. The cluster's aliases read like an APT phone book — **GhostEmperor, FamousSparrow, Earth Estries, UNC2286, RedMike, GhostSpider** — and the pull to fold everything into one mega-actor is strong.

It's also a trap. Vendors cluster on different telemetry, and "shared malware" gets mistaken for "same operator" constantly in China-nexus tracking, where a **digital-quartermaster model** distributes tooling (SparrowDoor/CrowDoor, ShadowPad, DEMODEX) across multiple contractors. So the working rule from the start: **shared tooling caps attribution at MODERATE.** A backdoor in common shows a relationship or a supplier, not one set of hands on the keyboard.

By the end of the OSINT phase, the Salt Typhoon framing was **refuted** for this cluster. Cisco Talos had already said it plainly in their March 2026 UAT-9244 report — they **could not establish a connection** between UAT-9244 and Salt Typhoon, even though both target telecom. Our infrastructure work reached the same verdict independently. The actor here is **UAT-9244**, with a **high-confidence overlap with FamousSparrow and Tropic Trooper** (Talos's assessment) and a **LOW / unestablished** Salt Typhoon nexus.

### The only selector that actually identifies the cluster

Here's the single most useful finding of the entire infrastructure phase:

**The reused self-signed TLS certificate is the only identity-grade selector for this cluster.**

| Certificate field | Value |
|---|---|
| Subject | `CN=8.8.8.8` (self-signed; a Google-DNS lookalike placeholder) |
| SPKI SHA-256 | `db9ad2cac7aa42c08cfbb5160a872f71ee711e5c2b04acc066e6769002459455` |
| Leaf SHA-256 | `0c7e36683a100a96f695a952cf07052af9a47f5898e1078311fd58c5fdbdecc8` |
| Leaf SHA-1 | `2b170a6d90fceba72aba3c7bc5c40b9725f43788` |
| Serial | `1` |
| Port | 443 |

Everything else is noise. **CN, hostname, port, and JA3 are all unreliable** for this cluster. The actor reuses one keypair across nodes, so the certificate — specifically the SPKI/leaf fingerprint — is what you pivot on. Pivoting on `CN=8.8.8.8` alone is worthless: it's a common lazy placeholder, and a sweep for it returns a sea of unrelated hosts. Only nodes carrying the **actor's keypair** count.

### Bounding the estate

Using the certificate as the anchor, the live cluster bounded to **five to six nodes across two sub-clusters**:

| Sub-cluster | ASN | Hygiene | Notes |
|---|---|---|---|
| **Vultr pair** | AS20473 | Tighter; no SMB exposed | Includes the net-new node below |
| **Kaopu HK trio** | AS138915 | Looser; SMB 139/445 exposed | Buenos Aires + Hong Kong nodes |

Known C2 nodes from Talos: `154.205.154.82`, `207.148.121.95`, `207.148.120.52`, and `212.11.64.105` (which also hosted a loader and the PeerTime implant).

The net-new contribution from this hunt:

> **`216.238.118.179`** — Vultr (AS20473), Osasco, Brazil. Carrying the actor certificate on 443, but **absent from the public reporting** and **absent from Turkey's USOM blocklist** (on which four of the five known nodes appear). The USOM gap is consistent with it being the **newest deployment** — it simply hadn't aged into the blocklists yet.

A note on port **4354**: it shows up alongside the certificate on the settled cluster nodes and is a useful corroborating fingerprint *in combination with the keypair*. A separate, earlier attempt to sweep port 4354 on its own — across an unrelated xTom /24 — went nowhere. Same number, two very different evidentiary weights. The keypair is the anchor; 4354 only means something next to it.

### The lifecycle: kept alive, then abandoned in a wave

A registration-signature sweep across all seven actor personas — gibberish ProtonMail SOA RNAME values, nameservers across `1domainregistry.com`, `orderbox-dns.com`, `monovm.com`, `naracauva.com.ru` — found **zero new registrations after September 2025**.

The pattern that emerged: the existing estate was **kept live for roughly three to four months past the September 8, 2025 public exposure**, then abandoned in a **synchronized wave in early 2026** — suspended-domain SOA phase, followed by a bulk recycle to `value-domain.com` (GMO Japan) nameservers and parking on a SAKURA IP (`160.16.200.77`). That synchronization is itself a weak signal of central management.

### Three pivots that died (and one beacon that lied)

Good hunting means killing your own leads before they mislead you. Four are worth naming:

**The domain lead that wasn't.** `telefoinfo.com` surfaced via historical data and looked promising. It dissolved into commodity registration noise — not an actor tell.

**Windows machine-name hostname pivots.** Pivoting on hostnames pulled DCERPC/RDP certificate artifacts that turned out to be **stock VPS image defaults**, not actor infrastructure.

**The `CN=8.8.8.8` sweep.** As above — a lazy placeholder shared by countless unrelated hosts. Only the keypair narrows it.

**The "Edge/ClientHello trap."** This is the one to remember. A packet capture appeared to show an implant beaconing — until the PCAP was actually *read* rather than trusted. The traffic was **100% Microsoft OS telemetry**: certificate/OCSP/update checks over `Microsoft-CryptoAPI/10.0`, SNI to Microsoft and DigiCert. The "C2 beacon" was a Windows component doing exactly what Windows components do. **PCAP-first discipline** — reading the bytes before accepting any AI-generated or pattern-matched interpretation — caught it.

The meta-lesson across all four: **AI and memory findings are leads, not facts.** Everything gets independently reproduced before it's load-bearing.

---

## Part 2 — The intelligence picture

### Who UAT-9244 is

**UAT-9244** is a China-nexus espionage actor that **overlaps with FamousSparrow and Tropic Trooper at high confidence** (per Talos), targeting **telecommunications providers**, with observed activity against operators in **South America**.

The malware lineage is the backbone of the attribution:

```
SparrowDoor  →  CrowDoor  →  TernDoor
(FamousSparrow)  (Tropic Trooper /   (UAT-9244)
                  Earth Estries)
```

- **SparrowDoor** is the backdoor used exclusively by FamousSparrow.
- **CrowDoor** is the variant first documented in Tropic Trooper intrusions, later attributed to Earth Estries.
- **TernDoor** is the current variant — same design DNA, new command codes and capabilities.

**Simplified Chinese debug strings** in the toolset reinforce the China-nexus call. But — to repeat the discipline that ran through the whole case — the *cluster identity* sits at **MODERATE** because it rests on communal tooling, and the **Salt Typhoon nexus is LOW**. Tooling overlap is high-confidence; same-operator identity is not.

### What TernDoor is

A **modular Windows backdoor** delivered by **DLL side-loading**, executing entirely in memory, persisting through multiple mechanisms, deploying a kernel driver, and ultimately running its command-and-control loop from inside **`msiexec.exe`**.

The full chain, confirmed end to end:

| Stage | Component | Action |
|---|---|---|
| 1 | `WSPrint.exe` (signed host) | Side-loads `BugSplatRc64.dll` |
| 2 | `BugSplatRc64.dll` (loader) | RC4-decrypts `WSPrint.dll`, executes in memory |
| 3 | TernDoor | Drops components to `C:\ProgramData\WSPrint\` |
| 4 | TernDoor | Establishes persistence |
| 5 | `C:\ProgramData\WSPrint\WSPrint.exe` | Persisted copy runs on boot |
| 6 | `msiexec.exe` | TernDoor injects and runs its C2 loop |

That chain wasn't handed over — it was **earned through reverse engineering**. Here's how.

---

## Part 3 — The reverse engineering

Two artifacts were analyzed: the **loader** as a PE, and the **backdoor** recovered from an injected `msiexec.exe` process image. Live execution of the malware was prohibited throughout, so this is **static analysis** of the loader plus static analysis of the recovered implant image — no detonation on the analysis host.

### The unlock: bundling the sandbox submission

Early manual attempts to detonate the loader came up empty, and it took a while to understand why. The loader has **no exported functions**, so a bare `rundll32 …,#1` invocation does nothing. And the payload wasn't co-located in the way the loader expects.

The breakthrough was mundane and important: **submit the signed host EXE as the entrypoint, with all three files co-located**, as one archive. That fired the entire chain and produced the injected `msiexec` image the rest of the analysis depends on. The loader's whole design assumes the host-beside-payload layout; reproduce that, and it runs.

### The loader's decrypt routine

`BugSplatRc64.dll` runs from `DllMain`, resolves its APIs **by hash** (a resolver at RVA `0x1040` handling seven `kernel32` functions, defeating IAT inspection), then derives the payload path from its own host path and decrypts in place:

```c
// BugSplatRc64.dll — reconstructed load routine
WCHAR path[MAX_PATH];
GetModuleFileNameW(NULL, path, MAX_PATH);     // ...\WSPrint.exe
replace_extension(path, L"dll");              // ...\WSPrint.dll

HANDLE h   = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
DWORD  sz  = GetFileSize(h, NULL);
BYTE  *buf = VirtualAlloc(NULL, 0x100000, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
ReadFile(h, buf, sz, &rd, NULL);

rc4(buf, rd, "qwiozpVngruhg123", 16);         // RC4, first 16 bytes as key
((void(*)(void))buf)();                        // execute in place
```

The decryption is **standard RC4** with the hardcoded key **`qwiozpVngruhg123`**. Compiler: MSVC 2019 (v16.11), LTCG, not packed (`.text` entropy ≈ 6.44).

A worthwhile detour: decrypting the **uploaded** payload file offline with the correct key produced **garbage**. Not a wrong algorithm, not a wrong key — the uploaded file simply isn't byte-identical to what the loader reads at runtime. The decompile proves the routine; the **bundled detonation** confirmed it works. The lesson there: when a decode fails, the file provenance is a suspect, not just the cipher.

### The injection self-check that explained everything

TernDoor **verifies it's running inside `msiexec.exe` before fully unpacking** — a trait inherited from CrowDoor. This one fact retroactively explained every failed manual-unpack attempt: run the loader bare, and it decodes a stub that bails. The backdoor body only materializes inside the injected `msiexec`. If you're fighting a loader that "does nothing," look for the host check before you blame your tooling.

### Finding #1 — the five-mode C2 transport factory *(previously undocumented)*

Public reporting describes TernDoor's C2 as **HTTP/HTTPS**. The reality is richer. A **transport factory** at offset `0x9FD0` selects among **five transports at runtime** via a **bitmask channel selector** pulled from the decoded config:

```c
// FUN_00009FD0 — transport factory (reconstructed)
if      (selector & 0x01) { obj = operator_new(0x70);  TcpConn_ctor (obj, cfg); }
else if (selector & 0x04) { obj = operator_new(0x400); proxyA_ctor  (obj, cfg); } // FUN_3050
else if (selector & 0x08) { obj = operator_new(0x400); proxyB_ctor  (obj, cfg); } // FUN_65E0
else if (selector & 0x10) { obj = operator_new(0x78);  HttpConn_ctor (obj, cfg); }
else if (selector & 0x80) { obj = operator_new(0x80);  HttpsConn_ctor(obj, cfg); }
```

| Selector | Object size | Transport |
|---|---|---|
| `0x01` | `0x70` | Direct TCP (`TcpConn`) |
| `0x04` | `0x400` | Proxy, mode A |
| `0x08` | `0x400` | Proxy, mode B |
| `0x10` | `0x78` | HTTP (`HttpConn`) |
| `0x80` | `0x80` | HTTPS (`HttpsConn`) |

The connection classes are confirmed by **RTTI** — `.?AVHttpConn@@` (`0xE9320`), `.?AVHttpsConn@@` (`0xE9360`), `.?AVTcpConn@@` (`0xE9438`). The two proxy modes parse a **host:port pair** from the config. A **connection manager** at `0x2730` walks the configured transports and **tries each until one connects**, calling the connect method at **vtable offset `+8`**:

```c
// FUN_00002730 — connection manager (reconstructed)
for (each bit set in cfg->transport_mask) {
    void *t = make_transport(bit, cfg);
    if (t && (*(connect_fn*)(*(void***)t + 1))(t) == SUCCESS)  // vtable slot +8
        return t;
    destroy(t);
}
```

The decoded configuration carries the **C2 IP**, **retry count**, **C2 port**, and an optional **User-Agent** for the HTTP transports. Calling this "HTTP/HTTPS" undersells it by three transports and a fallback engine.

### Finding #2 — the string-deobfuscation scheme *(previously undocumented)*

TernDoor's strings are obfuscated on disk and decoded in memory through a **two-pass per-character transform**: an additive-XOR pass with two per-string constants, then a **position-keyed pass** driven by an embedded 16-byte table.

```
Pass 1:  t[i]     = ((enc[i] + K) ^ X) - K        # K, X are per-string constants
Pass 2:  s        = table[i & 0x0F]
         plain[i] = ((i + s) ^ (s + t[i])) - s
```

The key table appears **three times** in the image (offsets `0xC9490`, `0xC9510`, `0xC9538`) stored as 16-bit little-endian words, with a **byte-stream variant** at `0xC9560`. Both were byte-verified directly against the dump:

| Offset(s) | Bytes (logical) | ASCII |
|---|---|---|
| `0xC9490` / `0xC9510` / `0xC9538` | `6B 6A 6F 62 49 55 62 62 25 38 37 34 35 68 67 55` | `kjobIUbb%8745hgU` |
| `0xC9560` | `61 62 67 25 62 59 43 59 48 76 6E 62 25 33 32 34` | `abg%bYCYHvnb%324` |

A working reference decryptor:

```python
def terndoor_string_deob(enc: bytes, K: int, X: int, table: bytes) -> bytes:
    buf = bytearray((((b + K) ^ X) - K) & 0xFF for b in enc)   # pass 1
    for i in range(len(buf)):                                  # pass 2
        s = table[i & 0x0F]
        buf[i] = (((i + s) ^ (s + buf[i])) - s) & 0xFF
    return bytes(buf)

KEY_TABLE = bytes([0x6B,0x6A,0x6F,0x62,0x49,0x55,0x62,0x62,
                   0x25,0x38,0x37,0x34,0x35,0x68,0x67,0x55])
```

No public source publishes this algorithm or these key bytes for TernDoor, CrowDoor, or SparrowDoor. The prior family reporting documents only config/transport crypto (XOR or RC4), not this string scheme.

### Finding #3 — a second persistence path via the COM API *(previously undocumented)*

The public reporting documents the `schtasks.exe` method. TernDoor has a **second one**.

The command-line handler (`0x50CD0`) builds and runs the familiar task, then hides it by editing `TaskCache\Tree\WSPrint` (deleting `SD`, zeroing `Index`):

```
schtasks /create /tn WSPrint /tr "C:\ProgramData\WSPrint\WSPrint.exe" /ru "SYSTEM" /sc onstart /F
```

But a **separate function at `0x52330`** registers the same persistence through the **Task Scheduler COM interface** — `ITaskService` → `RegisterTaskDefinition` — producing a scheduled task **with no `schtasks.exe` process at all**:

```c
// FUN_00052330 — COM persistence (reconstructed)
CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, &pSvc);
pSvc->Connect(...);  pSvc->GetFolder(L"\\", &pFolder);  pSvc->NewTask(0, &pDef);
//   Principal RunLevel=HIGHEST; Trigger=BootTrigger; Action=ExecAction(WSPrint.exe)
pFolder->RegisterTaskDefinition(L"WSPrint", pDef, TASK_CREATE_OR_UPDATE, ...);
```

The error paths reference the Task Scheduler HRESULTs `0x80070431`, `0x80070420`, `0x8007041D` (`SCHED_E_*`), confirming the path. This has a direct **hunting consequence**: a `WSPrint` task that exists with **no corresponding `schtasks.exe` execution** in your process telemetry is the COM path showing itself. (A registry Run key — `HKCU\…\Run\Default` → the persisted EXE — is a third, simpler mechanism.)

### The kernel driver and the capability set

TernDoor deploys **`WSPrint.sys`**, **AES-encrypted inside the shellcode** and decrypted at deployment, installed via the service APIs and exposing **`\Device\VMTool`**. It **hides components and suspends/resumes/terminates processes** from kernel space.

The backdoor's capabilities, mapped to the APIs recovered from the implant image: remote command execution and an interactive shell (`CreateProcessW/A`, `CreateProcessAsUserW`, `ShellExecuteW`), process termination (`TerminateProcess`), arbitrary file read/write (`ReadFile`/`WriteFile`), and host/user reconnaissance (`GetComputerNameW`, `GetUserNameW`).

### What stayed out of reach (and why that's honest)

Two items were **not** recovered, and the writeup says so plainly rather than papering over them:

**The numeric command-ID table.** TernDoor dispatches C2 opcodes through a **runtime-resolved virtual table** — the mapping from opcode to handler is bound only when the backdoor is live, against a `this` pointer that exists only at runtime. Recovering it statically from the dump isn't possible without live execution, which was prohibited. Talos noted the same family detail — the codes differ from earlier CrowDoor variants — without publishing them.

**The C2 IP from this specific sample.** The config was never decoded into the captured process. This was **triple-confirmed absent**: no ASCII IP or port-443 marker in the memory image, no actor traffic on the wire (that was the Edge telemetry), and an empty sandbox network panel. The Talos-published C2 IPs stand in for correlation; our sample simply never coughed up its own.

A third artifact deserves a footnote: a `pe-sieve` scan flagged an injected `.shc` region as implant shellcode. It wasn't TernDoor — it was **ScyllaHide's** `HookLibraryx64.dll`, the anti-anti-debug hook library, mislabeled by the tool. Another lead, caught and killed.

---

## Part 4 — What's new here

To be precise about the contribution, every finding was checked against the public corpus — Talos's UAT-9244 report, ESET's 2021 and 2025 SparrowDoor analyses, the UK NCSC SparrowDoor MAR (2022), Trend Micro's Earth Estries report (2024), and ITOCHU/Macnica's VB2023 work.

| Finding | Status vs public reporting |
|---|---|
| Five-mode C2 transport factory (TCP + 2 proxy + HTTP + HTTPS, bitmask selector, RTTI classes) | **Novel** — public sources describe a single transport each; none document the factory |
| String-deobfuscation scheme + key tables | **Novel** — not published for this family |
| COM-API persistence (`ITaskService`) | **Novel** — `schtasks.exe` method is public; the COM path is not |

What's **confirmation, not discovery** — and credited as such: the loader RC4 key (Talos publishes the same `qwiozpVngruhg123`), the side-load chain, the `msiexec` injection, the `schtasks` command, the install paths, the driver and `\Device\VMTool`, and the C2 IOCs. We reproduced them independently; we didn't find them first.

The net-new **infrastructure** contribution is the node `216.238.118.179`.

---

## Part 5 — Indicators and detection

Full indicators are in [`iocs/iocs.md`](iocs/iocs.md); detection content and a SOC hunting playbook are in [`detections/`](detections/). The highlights:

**Hashes (SHA-256).** Loaders `711d9427…`, `3c098a68…`, `f3691360…`; payloads `a5e41345…`, `075b20a2…`, `1f5635a5…`; driver `2d2ca7d2…`.

**C2.** `154.205.154.82`, `207.148.121.95`, `207.148.120.52`, `212.11.64.105`, and the net-new `216.238.118.179` — all on the reused `CN=8.8.8.8` certificate.

**The detections that matter most:**

- **The RC4 key string** `qwiozpVngruhg123` — published, hardcoded, near-zero false positives. Best single on-disk selector.
- **Anomalous `msiexec`** — bare `msiexec.exe` with no installer arguments that then makes outbound connections. The most **rename-resilient** behavioral hunt, because it keys on the technique, not a filename.
- **The reused certificate** — `CN=8.8.8.8` / leaf `0c7e3668…` on 443. The only identity-grade network selector.
- **The memory selectors** — the RTTI class names and the string-deob key tables, swept against `msiexec.exe` process memory.

A standing caution that runs through the whole detection set: **"WSPrint" is also a legitimate product name.** The actor masquerades under it deliberately. Never alert on the path alone — always pair it with a hard indicator (the loader DLL, the driver, the SYSTEM/onstart task, an `msiexec` anomaly, or a known C2).

And on the network layer, an honest limitation: the implant **never beaconed live** during analysis, so there's **no C2 payload signature**. Network detection here is **infrastructure-based** — IPs and the reused certificate — not protocol content.

---

*Detection content, full IOCs, and the technical report are in this repository. Findings on the actor's identity are held at calibrated confidence; shared tooling does not equal a shared operator. Independent reproduction is recommended before operational reliance on the novel findings.*
