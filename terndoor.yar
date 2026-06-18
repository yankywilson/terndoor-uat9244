/*
   TernDoor / UAT-9244 — YARA detection rules
   Lineage: TernDoor <- CrowDoor <- SparrowDoor
   Reference: https://blog.talosintelligence.com/uat-9244/
   TLP:CLEAR

   Notes:
   - The loader rule keys on the published RC4 decode key, a very strong selector.
   - The implant rules key on in-memory (post-deobfuscation) plaintext strings, the
     recovered string-deobfuscation key tables, and the C++ RTTI class names. Run
     these against process memory of msiexec.exe, not only on-disk files.
   - "WSPrint" alone is NOT a reliable selector (a legitimate product uses that name).
     Every rule requires multiple conditions.
*/

rule TernDoor_Loader_BugSplatRc64
{
    meta:
        description = "TernDoor DLL side-loading loader (BugSplatRc64.dll), UAT-9244"
        author = "CTI/DFIR"
        date = "2026-06-18"
        reference = "https://blog.talosintelligence.com/uat-9244/"
        hash1 = "711d9427ee43bc2186b9124f31cba2db5f54ec9a0d56dc2948e1a4377bada289"
        hash2 = "3c098a687947938e36ab34b9f09a11ebd82d50089cbfe6e237d810faa729f8ff"
        hash3 = "f36913607356a32ea106103387105c635fa923f8ed98ad0194b66ec79e379a02"
        tlp = "CLEAR"
    strings:
        $rc4key  = "qwiozpVngruhg123" ascii fullword
        $payload = "WSPrint.dll" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $rc4key
}

rule TernDoor_Implant_Memory_Strings
{
    meta:
        description = "TernDoor backdoor in memory (post-deobfuscation) - drop/persist/driver strings"
        author = "CTI/DFIR"
        date = "2026-06-18"
        reference = "https://blog.talosintelligence.com/uat-9244/"
        context = "Run against process memory of injected msiexec.exe"
        tlp = "CLEAR"
    strings:
        $sch  = "schtasks /create /tn %s /tr \"%s\" /ru \"%s\" %s /F" wide
        $on   = "/sc onstart" wide
        $prog = "ProgramData\\WSPrint" wide
        $vm   = "\\Device\\VMTool" wide
        $tc   = "TaskCache\\Tree" wide
        $svc  = "System\\CurrentControlSet\\Services" wide
    condition:
        3 of them
}

rule TernDoor_Implant_RTTI_Transport_Classes
{
    meta:
        description = "TernDoor C2 transport classes (RTTI) - HttpConn/HttpsConn/TcpConn"
        author = "CTI/DFIR"
        date = "2026-06-18"
        context = "Five-mode transport factory; RTTI present in implant image"
        tlp = "CLEAR"
    strings:
        $r1 = ".?AVHttpConn@@" ascii
        $r2 = ".?AVHttpsConn@@" ascii
        $r3 = ".?AVTcpConn@@" ascii
    condition:
        2 of them
}

rule TernDoor_StringDeob_KeyTables
{
    meta:
        description = "TernDoor string-deobfuscation key tables (previously undocumented selector)"
        author = "CTI/DFIR"
        date = "2026-06-18"
        note = "16-bit LE table appears multiple times; byte-stream table is a second variant"
        tlp = "CLEAR"
    strings:
        $kt_wide = { 6B 00 6A 00 6F 00 62 00 49 00 55 00 62 00 62 00
                     25 00 38 00 37 00 34 00 35 00 68 00 67 00 55 00 }
        $kt_byte = { 61 62 67 25 62 59 43 59 48 76 6E 62 25 33 32 34 }
    condition:
        any of them
}

rule TernDoor_Driver_WSPrint_Sys
{
    meta:
        description = "TernDoor kernel driver (WSPrint.sys) - process hide/suspend/resume/terminate"
        author = "CTI/DFIR"
        date = "2026-06-18"
        reference = "https://blog.talosintelligence.com/uat-9244/"
        hash1 = "2d2ca7d21310b14f5f5641bbf4a9ff4c3e566b1fbbd370034c6844cedc8f0538"
        tlp = "CLEAR"
    strings:
        $dev1 = "\\Device\\VMTool" wide ascii
        $dev2 = "\\DosDevices\\VMTool" wide ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}
