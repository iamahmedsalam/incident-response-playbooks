# PB-001 — Suspicious PowerShell Encoded Command Execution

## Alert Overview

| Field | Value |
|---|---|
| **Playbook ID** | PB-001 |
| **MITRE ATT&CK** | T1059.001 — Command and Scripting Interpreter: PowerShell |
| **Wazuh Rule** | 100001 (Level 10 — High) |
| **Log Source** | Sysmon Event ID 1 (Process Creation) |
| **Platform** | Windows |
| **Agent** | WIN11-SOC-Endpoint (Agent 001 — 192.168.56.103) |

**What the analyst sees:** An alert fires for Rule 100001 indicating PowerShell was launched with the `-EncodedCommand` parameter. This parameter accepts Base64-encoded instructions, commonly used by attackers to obfuscate malicious payloads and evade basic string-matching defences.

**Why this matters:** PowerShell encoded command alerts are the single most common alert type in real SOC environments. Attackers use encoding to hide everything from download cradles to reverse shells. Every L1 analyst must be able to triage these confidently.

---

## Triage Checklist

Work through these in order. Stop at the first "Escalate" decision if reached.

**Step 1 — Is this a known scheduled task or automation?**
- Check `data.win.eventdata.parentImage` — was PowerShell spawned by a legitimate automation tool (Task Scheduler, SCCM, Ansible)?
- If YES → likely false positive. Verify with system owner, close as FP if confirmed.
- If NO or UNKNOWN → continue.

**Step 2 — What is the parent process?**
- Check `data.win.eventdata.parentImage`
- Expected (lower risk): `explorer.exe`, `cmd.exe` (user-initiated)
- Suspicious (higher risk): `winword.exe`, `excel.exe`, `outlook.exe` (macro execution), `wmiprvse.exe` (WMI lateral movement), `w3wp.exe` (web shell)
- If parent is an Office application → **Escalate immediately** — this is likely a macro-based attack chain.

**Step 3 — Can you decode the Base64 payload?**
- Extract the Base64 string from `data.win.eventdata.commandLine`
- Decode it: `echo "<Base64_string>" | base64 -d`
- Look for: download cradles (`IEX`, `DownloadString`, `Invoke-WebRequest`), reverse shells, credential theft tools (`Mimikatz`, `Invoke-Kerberoast`)
- If payload is clearly malicious → **Escalate to Tier 2**

**Step 4 — Check the user context**
- `data.win.eventdata.user` — is this a service account, admin, or regular user?
- Regular users rarely have legitimate reasons to run encoded PowerShell
- Service accounts running encoded commands should be verified against known automation

**Decision:** If any step above indicates malicious activity → proceed to Investigation. If clearly benign → document reasoning and close.

---

## Investigation Procedure

### Extract Key Artifacts from the Alert

Open the Wazuh alert and record these fields:

| Artifact | Wazuh Field | What to Record |
|---|---|---|
| Timestamp | `timestamp` | Exact time of execution |
| Command line | `data.win.eventdata.commandLine` | Full command including Base64 string |
| Process image | `data.win.eventdata.image` | Should be `powershell.exe` or `pwsh.exe` |
| Parent process | `data.win.eventdata.parentImage` | What launched PowerShell |
| Process ID | `data.win.eventdata.processId` | For process tree correlation |
| Process GUID | `data.win.eventdata.processGuid` | Unique identifier for this process |
| User | `data.win.eventdata.user` | Account context |
| Hashes | `data.win.eventdata.hashes` | SHA256 of the executing binary |

### Decode the Payload

On any Linux machine or from Wazuh Manager SSH:
```bash
echo "<Base64_string_from_commandLine>" | base64 -d
```

Record the decoded output. Look for:
- URLs (potential C2 or download staging)
- File paths (where payloads are being written)
- Known tool names (Mimikatz, PowerSploit, Empire, Cobalt Strike)
- Network connections (IP addresses, port numbers)

### Check for Related Activity

In Wazuh dashboard, search for all events from the same agent within ±15 minutes of the alert:

```
agent.id: 001 AND @timestamp:[alert_time - 15m TO alert_time + 15m]
```

Look for:
- Rule 100004 (registry persistence) — attacker establishing persistence after execution
- Rule 100008 (file dropped in Temp) — payload being written to disk
- Rule 100005 (new user created) — attacker creating backdoor account
- Rule 100006 (log cleared) — attacker covering tracks
- Multiple Rule 100001 alerts — attacker running multiple encoded commands

### Verify Binary Integrity

Take the SHA256 hash from `data.win.eventdata.hashes` and check:
- Is this the legitimate `powershell.exe`? Compare hash against known-good Microsoft hashes
- In production: submit to VirusTotal or internal threat intel platform

---

## Containment & Response

**If confirmed malicious — take these actions in order:**

1. **Isolate the endpoint** — remove from network immediately. In production: disable network adapter or trigger EDR isolation. In lab: disconnect Host-Only adapter in VirtualBox settings.

2. **Kill the process** — if still running:
   ```powershell
   Stop-Process -Id <processId> -Force
   ```

3. **Check for persistence** — examine common persistence locations:
   ```powershell
   # Registry Run keys
   Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
   Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
   
   # Scheduled tasks
   Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"}
   
   # Startup folder
   Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
   ```

4. **Check for dropped files** — look in common staging directories:
   ```powershell
   Get-ChildItem $env:TEMP -Recurse | Where-Object {$_.Extension -match "\.(exe|dll|bat|ps1|vbs)"}
   ```

5. **Preserve evidence** — before remediation, capture:
   - Full Wazuh alert JSON (export from dashboard)
   - Process memory dump if available
   - Relevant Windows Event Logs
   - Any files dropped by the payload

6. **Escalate to Tier 2** with: alert details, decoded payload, timeline of related events, containment actions taken.

---

## Evidence Collection

Document the following for the incident record:

| Evidence Item | Source | Format |
|---|---|---|
| Wazuh alert (full JSON) | Dashboard → expand alert → export | JSON |
| Decoded Base64 payload | Manual decode output | Text |
| Process tree screenshot | Wazuh alert expanded view | PNG |
| Related alerts (±15 min) | Dashboard filtered search | Screenshot + JSON |
| Persistence check results | PowerShell commands above | Text output |
| Dropped file listing | PowerShell commands above | Text output |
| Hash verification results | VirusTotal / internal TI | Screenshot |

---

## Post-Incident

**Detection tuning recommendations:**
- If the encoded command was a known legitimate automation, add a whitelist exception in the rule using `<match negate="yes">` for the specific parent process
- Consider adding Rule 100012 for `IEX (Invoke-Expression)` with `DownloadString` — a different T1059.001 execution method discovered during Project 1 Phase C testing
- Monitor for PowerShell v2 downgrade attacks (`powershell -Version 2`) which bypass Script Block Logging

**Metrics to record:**
- Time from execution to alert (MTTD)
- Time from alert to investigation start (MTTR)
- True positive or false positive classification
- Technique variant (encoded command, download cradle, obfuscated script, etc.)
