# ADS-Lite: T1053.005 — Scheduled Task Creation via schtasks.exe

## Goal
Detect creation of new scheduled tasks via schtasks.exe, a common persistence
mechanism used by adversaries to survive reboots and execute payloads under
SYSTEM or elevated user context without requiring an active session.

**Wazuh Rule:** 100002 (level 10)
**Sigma Rule:** sigma-rules/t1053_005_scheduled_task_creation.yml
**MITRE ATT&CK:** T1053.005 — Scheduled Task/Job: Scheduled Task
**Log Source:** Sysmon EID 1 (Process Create) → win.eventdata.commandLine
**Tactic:** Persistence (TA0003), Privilege Escalation (TA0004)

---

## Blind Spots

| Blind Spot | ATT&CK Technique Affected | Detection Alternative | Interview Talking Point |
|------------|--------------------------|----------------------|------------------------|
| Task creation via Task Scheduler COM API directly (no schtasks.exe spawned) | T1053.005 | Windows Security EID 4698 (task created) — add localfile block for Microsoft-Windows-TaskScheduler/Operational | "schtasks.exe is just one creation vector — COM API calls bypass my process-create rule entirely; I need EID 4698 as a second layer" |
| Task creation via PowerShell `Register-ScheduledTask` cmdlet | T1053.005 | EID 4698 from TaskScheduler log + Sysmon EID 1 on powershell.exe with Register-ScheduledTask in cmdline | "Register-ScheduledTask never spawns schtasks.exe so my rule is blind to it — PowerShell script-block logging or EID 4698 covers it" |
| Existing task modification (`/change` flag) instead of `/create` | T1053.005 | Extend rule 100002 regex to include `/change` OR add rule 100003 specifically for task modification | "I only alert on /create — an attacker modifying an existing trusted task name avoids my rule" |
| Task XML dropped to disk and imported (`schtasks /create /xml`) | T1053.005 | Alert on /xml flag in schtasks commandLine; also monitor Sysmon EID 11 for .xml writes to Task folder | "XML import is a LOL-bin technique — the task name and trigger are hidden inside the file, not the command line" |
| AT command (legacy, disabled by default on modern Windows) | T1053.005 | Monitor for at.exe process creation — rare enough that any execution should alert | "AT is largely irrelevant on modern systems but worth a rule in legacy environments" |

---

## Validation

### Step 1 — Live Trigger (Win10 Victim)
```powershell
# Basic scheduled task creation
schtasks.exe /create /tn "WindowsUpdateHelper" /tr "powershell.exe -enc JABj" /sc onlogon /ru System /f

# Verify task was registered
schtasks /query /tn "WindowsUpdateHelper"

# Cleanup after test
schtasks /delete /tn "WindowsUpdateHelper" /f
```

### Step 2 — Confirm Alert Fires on soc-lab
```bash
docker exec wazuh-docker-wazuh.manager-1 tail -f /var/ossec/logs/alerts/alerts.json | \
  python3 -c "
import sys, json
for line in sys.stdin:
    try:
        a = json.loads(line.strip())
        if a.get('rule', {}).get('id') == '100002':
            print('[MATCH]', a['rule']['description'])
            print('  cmd:', a.get('data',{}).get('win',{}).get('eventdata',{}).get('commandLine',''))
    except: pass
"
```

### Step 3 — Expected Result
- Rule 100002 fires at level 10
- win.eventdata.image ends with schtasks.exe
- win.eventdata.commandLine contains /create
- Alert visible in Wazuh Dashboard under Security Events

### Step 4 — Negative Test (Should NOT Fire)
```powershell
# Query and list tasks — should not trigger
schtasks /query
schtasks /query /fo LIST /v
```
Confirm rule 100002 does NOT appear for query-only commands.
