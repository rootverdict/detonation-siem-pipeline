# Regex Practice — Sysmon Log IOC Extraction & Detection
**Path:** `detections/ads/regex-notes.md`
**Date:** 2026-06-24
**Context:** W1D3 study — regex for IOC extraction from raw Sysmon EID 1 logs

---

## Why Regex Matters in SOC Work

Sysmon logs arrive as unstructured or semi-structured text blobs. Before a SIEM decoder maps fields cleanly into `win.eventdata.*`, analysts need regex to:
- Extract IOCs from raw `full_log` fields when structured parsing fails
- Write detection conditions in Wazuh rules (`type="pcre2"`)
- Build IOC extractors that work on raw log files, not just parsed JSON
- Understand what the SIEM decoder is doing under the hood

**ATT&CK relevance:** Every technique that leaves command-line evidence (T1059.*, T1053.*, T1036.*, T1105) is detectable via regex on process create logs.

---

## Anatomy of a Raw Sysmon EID 1 Log Line

```
Dec 24 10:00:00 win10-victim WinEvtLog: Microsoft-Windows-Sysmon/Operational: INFORMATION(1):
Microsoft-Windows-Sysmon: SYSTEM: NT AUTHORITY: win10-victim: Process Create:
RuleName: -
UtcTime: 2026-06-24 10:00:00.000
ProcessGuid: {4a23f1b2-1234-5678-abcd-000000000001}
ProcessId: 4444
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
FileVersion: -
Description: Windows PowerShell
CommandLine: powershell.exe -enc JABjAD0ATgBlAHcA...
CurrentDirectory: C:\Users\victim\
User: DESKTOP-IC2TRF8\victim
Hashes: SHA256=9785001B0DCF755EDDB8AF294A373C0B87B2498660F724E76C4D53F9C217C7A3,MD5=AABBCCDD...
ParentImage: C:\Windows\explorer.exe
ParentCommandLine: explorer.exe
```

Key fields for detection: `Image`, `CommandLine`, `Hashes`, `ParentImage`, `User`, `IntegrityLevel`

---

## Pattern 1 — IPv4 Address Extraction

### Regex
```python
import re

RE_IPV4 = re.compile(
    r"\b"                          # word boundary — no partial matches
    r"(?!127\.)"                   # exclude loopback 127.x.x.x
    r"(?!169\.254\.)"              # exclude link-local 169.254.x.x
    r"(?!10\.)"                    # exclude RFC1918 private (optional — remove in internal net context)
    r"(?!192\.168\.)"              # exclude RFC1918 private (optional)
    r"(?!0\.0\.0\.0)"             # exclude null route
    r"(\d{1,3}\.){3}\d{1,3}"     # four octets
    r"\b"
)

log = "Connection from 203.0.113.45 to 192.168.100.7 port 4444"
matches = RE_IPV4.findall(log)
# Result: ['203.0.113.45']  — 192.168.100.7 excluded by RFC1918 filter
```

### Wazuh rule equivalent (pcre2)
```xml
<field name="full_log" type="pcre2">
  \b(?!127\.|169\.254\.|0\.0\.0\.0)(\d{1,3}\.){3}\d{1,3}\b
</field>
```

### Common mistake
`\d{1,3}` matches 999 — it does not validate that each octet is ≤255. For strict validation use:
```python
RE_IPV4_STRICT = re.compile(
    r"\b(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b"
)
```
For IOC extraction in SOC work, the loose version is usually fine — you'll see it in most open-source extractors including what we use in extract_iocs.py.

---

## Pattern 2 — Domain Extraction

### Regex
```python
RE_DOMAIN = re.compile(
    r"\b"
    r"(?:[a-zA-Z0-9-]+\.)"        # one or more subdomains/labels
    r"+"                           # allow deep nesting (sub.sub.domain.com)
    r"(?:com|net|org|io|gov|edu|ru|cn|de|co|uk|xyz|top|info)"  # TLD allowlist
    r"\b",
    re.IGNORECASE
)

log = "QueryName: evil-c2.xyz ParentImage: C:\\Windows\\explorer.exe"
matches = RE_DOMAIN.findall(log)
# Result: ['evil-c2.xyz']
```

### Why TLD allowlist instead of `\.\w{2,6}`
`\.\w{2,6}` matches file extensions too — `powershell.exe`, `config.xml`, `update.log` all match. The TLD allowlist eliminates these false positives at the cost of missing obscure TLDs.

### Wazuh rule equivalent
```xml
<!-- Sysmon EID 22 DNS query for suspicious TLD -->
<rule id="100010" level="8">
  <if_group>sysmon_event_22</if_group>
  <field name="win.eventdata.queryName" type="pcre2">(?i)\.(xyz|top|ru|cn|tk|pw)$</field>
  <description>Suspicious DNS query to uncommon TLD</description>
  <mitre><id>T1071.001</id></mitre>
</rule>
```

---

## Pattern 3 — Windows File Path Extraction

### Regex
```python
RE_WIN_PATH = re.compile(
    r"[A-Za-z]:\\"                 # drive letter + backslash
    r"(?:[^\\/:*?\"<>|\r\n]+"     # path components (no illegal chars)
    r"\\)*"                        # zero or more subdirectories
    r"[^\\/:*?\"<>|\r\n]*"        # filename (no extension required)
    r"\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|scr|msi|lnk)"  # suspicious extensions
)

log = r"Image: C:\Windows\Temp\payload.exe CommandLine: C:\Users\victim\Downloads\update.ps1"
matches = RE_WIN_PATH.findall(log)
# Result: ['C:\\Windows\\Temp\\payload.exe', 'C:\\Users\\victim\\Downloads\\update.ps1']
```

### High-value paths to alert on
```python
SUSPICIOUS_PATHS = re.compile(
    r"(?i)"                                    # case-insensitive
    r"(\\Temp\\"                               # C:\Windows\Temp or %TEMP%
    r"|\\AppData\\Roaming\\"                   # user roaming appdata
    r"|\\AppData\\Local\\Temp\\"              # user temp
    r"|\\ProgramData\\"                        # shared appdata
    r"|\\Users\\Public\\"                      # world-writable
    r"|\\Windows\\System32\\Tasks\\"          # scheduled task XML storage
    r")"
    r"[^\\]+\.(exe|dll|ps1|bat|vbs|hta)"     # executable in suspicious path
)
```
**ATT&CK:** T1036.005 (Match Legitimate Name or Location), T1059.001, T1053.005

---

## Pattern 4 — SHA256 Hash Extraction

### Regex
```python
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Sysmon Hashes field format: "SHA256=AABB...,MD5=CCDD..."
RE_SHA256_LABELED = re.compile(r"(?i)SHA256=([a-fA-F0-9]{64})")

log = "Hashes: SHA256=9785001B0DCF755EDDB8AF294A373C0B87B2498660F724E76C4D53F9C217C7A3,MD5=AABBCCDD"
match = RE_SHA256_LABELED.search(log)
# Result: '9785001B0DCF755EDDB8AF294A373C0B87B2498660F724E76C4D53F9C217C7A3'
```

### Common mistake
The unlabeled `\b[a-fA-F0-9]{64}\b` also matches MD5 (32 chars) if you accidentally write `{32}` or can collide with other hex strings. Always prefer the labeled version for Sysmon logs. Use the bare version only for fallback full_log scanning.

---

## Pattern 5 — Base64 Blob Detection (PowerShell -enc)

### Regex
```python
RE_BASE64_BLOB = re.compile(
    r"(?:-enc|-encodedcommand)\s+"   # preceded by PS encoded flag
    r"([A-Za-z0-9+/]{20,}={0,2})"  # base64 chars, min 20, optional padding
)

log = 'CommandLine: powershell.exe -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdA=='
match = RE_BASE64_BLOB.search(log)
blob = match.group(1) if match else None
# blob: 'JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdA=='

# Decode it
import base64
decoded = base64.b64decode(blob + "==").decode("utf-16-le", errors="replace")
# Result: '$c=New-Object System.Net.WebClient'
```

### Why UTF-16-LE
PowerShell internally uses UTF-16-LE encoding. `-EncodedCommand` always expects UTF-16-LE base64. If you decode as UTF-8 you get garbage. This is a common interview gotcha.

---

## Pattern 6 — Writing a Wazuh Detection Using pcre2 Regex

### Goal: Detect PowerShell spawned from unusual parents (living-off-the-land)

Legitimate PowerShell parents: `explorer.exe`, `cmd.exe`, `services.exe`
Suspicious parents: `winword.exe`, `excel.exe`, `outlook.exe`, `mshta.exe`, `wscript.exe`

```xml
<!-- T1566.001 + T1059.001 — Office macro spawning PowerShell -->
<rule id="100003" level="14">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe$</field>
  <field name="win.eventdata.parentImage" type="pcre2">
    (?i)(winword|excel|outlook|powerpnt|mshta|wscript|cscript)\.exe$
  </field>
  <description>T1566.001 - Office/script host spawning PowerShell (macro likely)</description>
  <mitre>
    <id>T1566.001</id>
    <id>T1059.001</id>
  </mitre>
  <group>attack,execution,initial_access,macro,t1566_001,</group>
</rule>
```

This rule will be added to local_rules.xml in W2 when we expand coverage.

---

## Quick Reference — pcre2 Flags in Wazuh Rules

| Flag | Meaning | Example |
|------|---------|---------|
| `(?i)` | Case-insensitive | `(?i)powershell\.exe` matches `PowerShell.EXE` |
| `(?s)` | Dot matches newline | Rarely needed in single-line log fields |
| `\.` | Literal dot | Without backslash, `.` matches any character |
| `$` | End of string | `powershell\.exe$` won't match `powershell.exe.bak` |
| `\b` | Word boundary | `\benc\b` won't match `encoded` |
| `(?i)(-enc\|-encodedcommand)` | Alternation | Match either flag |

---

## Interview Talking Points

- **"Walk me through how you'd extract IOCs from a raw Sysmon log"** — "I run three passes: labeled regex for SHA256 (SHA256= prefix), TLD-allowlisted domain regex, and RFC1918-excluded IPv4 regex. I prefer labeled extraction over bare hex matching to avoid false positives. For command lines I look for base64 blobs after -enc and decode as UTF-16-LE since that's what PowerShell uses internally."

- **"Why UTF-16-LE for PowerShell encoded commands?"** — "PowerShell's internal string representation is UTF-16-LE. The -EncodedCommand parameter was designed to accept commands pre-encoded in that format so special characters survive shell quoting. If you decode as UTF-8 you get null bytes between every character."

- **"What's the difference between pcre2 and standard regex in Wazuh?"** — "Wazuh uses PCRE2 as its regex engine in rules with `type='pcre2'`. The main practical differences are lookaheads/lookbehinds work, named capture groups work, and `\b` word boundaries behave correctly. The older `type='osregex'` is a simpler engine with fewer features — I always use pcre2 for detection rules."

- **"How would you detect base64 without the -enc flag?"** — "Look for long base64 blobs (40+ chars) in CommandLine fields not preceded by a known flag, or scan ScriptBlock logs (EID 4104) for FromBase64String calls. You can also alert on the length of the CommandLine field itself — legitimate commands rarely exceed 500 characters."
