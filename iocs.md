# TernDoor / UAT-9244 — Indicators of Compromise

**TLP:CLEAR** · Lineage: TernDoor ← CrowDoor ← SparrowDoor · Reference: https://blog.talosintelligence.com/uat-9244/

Source column: **Talos** = published in the Cisco Talos UAT-9244 report; **This analysis** = identified or first documented here.

---

## File hashes (SHA-256)

| Component | SHA-256 | Source |
|---|---|---|
| Loader `BugSplatRc64.dll` | `711d9427ee43bc2186b9124f31cba2db5f54ec9a0d56dc2948e1a4377bada289` | Talos |
| Loader `BugSplatRc64.dll` | `3c098a687947938e36ab34b9f09a11ebd82d50089cbfe6e237d810faa729f8ff` | Talos |
| Loader `BugSplatRc64.dll` | `f36913607356a32ea106103387105c635fa923f8ed98ad0194b66ec79e379a02` | Talos |
| Encoded payload `WSPrint.dll` | `a5e413456ce9fc60bb44d442b72546e9e4118a61894fbe4b5c56e4dfad6055e3` | Talos |
| Encoded payload `WSPrint.dll` | `075b20a21ea6a0d2201a12a049f332ecc61348fc0ad3cfee038c6ad6aa44e744` | Talos |
| Encoded payload `WSPrint.dll` | `1f5635a512a923e98a90cdc1b2fb988a2da78706e07e419dae9e1a54dd4d682b` | Talos |
| Side-load host `WSPrint.exe` | `e49ea6317ca5569a627624a19ff105176f97e0e29257c7ca37cf196e67fea1b2` | This analysis (signed host) |
| Driver `WSPrint.sys` | `2d2ca7d21310b14f5f5641bbf4a9ff4c3e566b1fbbd370034c6844cedc8f0538` | Talos |

---

## Command-and-control servers

| Indicator | Port | Note | Source |
|---|---|---|---|
| `154.205.154.82` | 443 | C2 | Talos |
| `207.148.121.95` | 443 | C2 | Talos |
| `207.148.120.52` | 443 | C2 | Talos |
| `212.11.64.105` | — | C2 / hosted loader and PeerTime | Talos |
| `216.238.118.179` | — | Vultr (AS20473), Osasco BR; additional cluster node | This analysis |

Talos additionally identified approximately 18 suspected UAT-9244 servers via certificate pivoting.

---

## TLS certificate (cluster identifier)

| Field | Value | Source |
|---|---|---|
| Subject | `CN=8.8.8.8` (self-signed) | Talos / This analysis |
| Leaf SHA-256 | `0c7e36683a100a96f695a952cf07052af9a47f5898e1078311fd58c5fdbdecc8` | Talos / This analysis |
| Leaf SHA-1 | `2b170a6d90fceba72aba3c7bc5c40b9725f43788` | Talos |
| Port | 443 | Talos / This analysis |

The C2 servers reuse a single self-signed keypair; this certificate is the most reliable network-level identifier for the cluster.

---

## Host artifacts

| Artifact | Value | Source |
|---|---|---|
| Install directory | `C:\ProgramData\WSPrint\` | Talos / This analysis |
| Dropped files | `WSPrint.exe`, `BugSplatRc64.dll`, `WSPrint.dll`, `WSPrint.sys` | Talos / This analysis |
| Scheduled task | `WSPrint` (`/ru SYSTEM`, `/sc onstart`) | Talos / This analysis |
| Task command | `schtasks /create /tn WSPrint /tr "C:\ProgramData\WSPrint\WSPrint.exe" /ru "SYSTEM" /sc onstart /F` | Talos / This analysis |
| Task hiding | `HKLM\...\Schedule\TaskCache\Tree\WSPrint` (delete `SD`, set `Index`=0) | Talos / This analysis |
| Run key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Default` → `C:\ProgramData\WSPrint\WSPrint.exe` | Talos |
| Driver device | `\Device\VMTool` (`\DosDevices\VMTool`) | Talos / This analysis |
| Injection host | `C:\Windows\System32\msiexec.exe` | Talos / This analysis |
| Loader RC4 key | `qwiozpVngruhg123` | Talos / This analysis |

---

## Detection selectors (this analysis)

| Selector | Value |
|---|---|
| String-deobfuscation key table (16-bit LE) | `6B 00 6A 00 6F 00 62 00 49 00 55 00 62 00 62 00 25 00 38 00 37 00 34 00 35 00 68 00 67 00 55 00` |
| String-deobfuscation key table (byte variant) | `61 62 67 25 62 59 43 59 48 76 6E 62 25 33 32 34` |
| C2 transport classes (RTTI) | `.?AVHttpConn@@`, `.?AVHttpsConn@@`, `.?AVTcpConn@@` |
| Transport selector bitmask | `0x01` TCP · `0x04`/`0x08` proxy · `0x10` HTTP · `0x80` HTTPS |

---

## Vendor detection signatures

| Type | Value | Source |
|---|---|---|
| ClamAV | `Win.Malware.TernDoor` | Talos |
| Snort | SID `65551` | Talos |
