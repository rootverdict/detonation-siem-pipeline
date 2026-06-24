# ADS-Lite: T1059.001 — PowerShell Encoded Command Execution

## Goal
Detect PowerShell processes launched with encoded or obfuscated command arguments
that adversaries use to hide malicious payloads from command-line inspection and
bypass script-block logging. Covers -enc, -encodedcommand, IEX, Invoke-Expression,
and DownloadString primitives.

**Wazuh Rule:** 100001 (level 12)
**Sigma Rule:** sigma-rules/t1059_001_powershell_encoded.yml
**MITRE ATT&CK:** T1059.001 — Command and Scripting Interpreter: PowerShell
**Log Source:** Sysmon EID 1 (Process Create) → win.eventdata.commandLine
**Tactic:** Execution (TA0002)

---

## Blind Spots

| Blind Spot | ATT&CK Technique Affected | Detection Alternative | Interview Talking Point |
|------------|--------------------------|----------------------|------------------------|
| PowerShell v2 downgrade (`-version 2`) disables script-block logging entirely — EID 4104 never fires | T1059.001 + T1562.001 | Sysmon EID 1 still fires on process create; alert on `-version 2` in commandLine | "V2 downgrade is a known logging bypass — I layer Sysmon process create on top of AMSI/script-block so one bypass doesn't blind me completely" |
| Constrained Language Mode bypass via COM objects or WDAC gaps | T1059.001 | Monitor EID 1 for unusual parent processes spawning powershell.exe | "CLM can be bypassed; I don't rely on it as a sole control — I alert on the process spawn regardless" |
| Fileless execution via `[System.Reflection.Assembly]::Load()` without IEX/DownloadString keywords | T1059.001 + T1620 | Extend regex to cover `::Load(`, `Reflection.Assembly`, `FromBase64String` | "My current rule catches the most common primitives but misses raw reflection — next iteration adds those keywords" |
| AMSI bypass patching in memory before execution | T1562.001 | Alert on known AMSI patch byte patterns via Sysmon EID 8 (CreateRemoteThread) or EDR | "AMSI patching happens before my rule triggers — I'd need memory scanning or EDR telemetry to catch that layer" |
| Renamed powershell.exe (e.g. `svch0st.exe`) | T1036.003 | Sysmon EID 1 OriginalFileName field — alert on OriginalFileName=PowerShell.EXE regardless of Image name | "Image-path matching is bypassable via rename — OriginalFileName from PE header is harder to fake and Sysmon captures it" |

---

## Validation

### Step 1 — Live Trigger (Win10 Victim)
```powershell
# -enc flag (Base64 encodes: $c=New-Object System.Net.WebClient)
powershell.exe -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdA==

# IEX variant
powershell.exe -nop -w hidden -c "IEX('whoami')"

# DownloadString variant
powershell.exe -c "(New-Object Net.WebClient).DownloadString('http://127.0.0.1/test')"
```

### Step 2 — Confirm Alert Fires on soc-lab
```bash
docker exec wazuh-docker-wazuh.manager-1 tail -f /var/ossec/logs/alerts/alerts.json | \
  python3 -c "
import sys, json
for line in sys.stdin:
    try:
        a = json.loads(line.strip())
        if a.get('rule', {}).get('id') == '100001':
            print('[MATCH]', a['rule']['description'])
            print('  cmd:', a.get('data',{}).get('win',{}).get('eventdata',{}).get('commandLine',''))
    except: pass
"
```

### Step 3 — Expected Result
- Rule 100001 fires at level 12
- win.eventdata.image ends with powershell.exe
- win.eventdata.commandLine contains the trigger keyword
- Alert visible in Wazuh Dashboard under Security Events

### Step 4 — Negative Test (Should NOT Fire)
```powershell
# Normal PowerShell — no encoded flags
powershell.exe -c "Get-Date"
powershell.exe Get-Process
```
Confirm rule 100001 does NOT appear for these.
