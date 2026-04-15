# PB-003 — Registry Run Key Persistence

## Alert Overview

| Field | Value |
|---|---|
| **Playbook ID** | PB-003 |
| **MITRE ATT&CK** | T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys |
| **Wazuh Rule** | 100004 (Level 10 — High) |
| **Log Source** | Sysmon Event ID 13 (Registry Value Set) |
| **Platform** | Windows |
| **Agent** | WIN11-SOC-Endpoint (Agent 001 — 192.168.56.103) |

**What the analyst sees:** An alert fires for Rule 100004 indicating a modification to a Windows Registry Run or RunOnce key. These keys specify programs that execute automatically at user login — one of the most common persistence mechanisms used by attackers.

**Why this matters:** Persistence is the tactic that separates a nuisance from a real compromise. If an attacker has persistence, they survive reboots and maintain long-term access. Identifying and removing persistence mechanisms is a core L1 investigation skill. Registry Run keys are the most frequently abused persistence location in Windows environments.

---

## Triage Checklist

**Step 1 — What registry path was modified?**
- Check `data.win.eventdata.targetObject`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\` = all users affected
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\` = current user only
- `RunOnce` variants = executes once then self-deletes (common for malware installers)
- HKLM modifications are higher severity — they affect every user on the system

**Step 2 — What value was set?**
- Check `data.win.eventdata.details` — this shows the executable path being registered
- Known legitimate software? (antivirus, VPN client, cloud sync, Windows Update)
- Unknown executable? → suspicious
- Path in `%TEMP%`, `%APPDATA%`, `C:\Users\Public\`? → **highly suspicious** — legitimate software doesn't run from temp directories

**Step 3 — What process made the modification?**
- Check `data.win.eventdata.image` — what process wrote to the registry
- `reg.exe` = command-line registry edit — could be legitimate admin or attacker using living-off-the-land
- `regedit.exe` = GUI registry editor — usually manual/admin
- `powershell.exe` = scripted modification — check parent process
- Unknown or unusual process → **Escalate**

**Step 4 — Was this preceded by other suspicious activity?**
- Check for Rule 100001 (encoded PowerShell) or Rule 100008 (file dropped in Temp) from the same agent within the past 30 minutes
- If YES → this is likely part of an attack chain: execution → file drop → persistence
- **Escalate immediately**

**Decision:** If the value points to a known legitimate application and the modifying process is expected → close as FP. If anything is suspicious → proceed to full investigation.

---

## Investigation Procedure

### Extract Key Artifacts from the Alert

| Artifact | Wazuh Field | What to Record |
|---|---|---|
| Timestamp | `timestamp` | When the registry modification occurred |
| Registry path | `data.win.eventdata.targetObject` | Full key path + value name |
| Value data | `data.win.eventdata.details` | The executable path being registered |
| Modifying process | `data.win.eventdata.image` | What wrote to the registry |
| Process GUID | `data.win.eventdata.processGuid` | For process tree correlation |
| User | `data.win.eventdata.user` | Account context |
| Event type | `data.win.eventdata.eventType` | Should be `SetValue` |

### Verify the Registered Executable

**On the Windows 11 endpoint (PowerShell as Administrator):**

```powershell
# Check if the file exists at the registered path
Test-Path "<executable_path_from_details_field>"

# If it exists, get its hash
Get-FileHash "<executable_path_from_details_field>" -Algorithm SHA256

# Check file properties
Get-Item "<executable_path_from_details_field>" | Select-Object Name, CreationTime, LastWriteTime, Length

# Check if the file is digitally signed
Get-AuthenticodeSignature "<executable_path_from_details_field>"
```

In production: submit the SHA256 hash to VirusTotal or your internal threat intel platform.

### Review Current Run Key Contents

```powershell
# All HKLM Run entries
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Format-List

# All HKCU Run entries
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Format-List

# RunOnce keys
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue | Format-List
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue | Format-List
```

Compare against a known-good baseline. Any entry that doesn't match expected software is suspicious.

### Check for Related Attack Chain Activity

In Wazuh dashboard:
```
agent.id: 001 AND @timestamp:[alert_time - 30m TO alert_time + 10m]
```

Look for the attack chain pattern:
1. Rule 100001 (PowerShell execution) → initial execution
2. Rule 100008 (file dropped in Temp) → payload staging
3. Rule 100004 (registry persistence) → establishing persistence ← **you are here**
4. Rule 100006 (log cleared) → covering tracks

If you see 2 or more of these from the same agent in the same time window → confirmed multi-stage attack.

### Examine Process Tree

Using the `processGuid` from the alert, search Wazuh for all events with the same parent:
```
agent.id: 001 AND data.win.eventdata.parentProcessGuid: <processGuid>
```

This reveals what else the modifying process did — did it also create files, make network connections, or spawn other processes?

---

## Containment & Response

**If confirmed malicious:**

1. **Remove the registry entry:**
   ```powershell
   # Remove specific value from Run key
   Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "<value_name>"
   ```

2. **Delete the registered executable:**
   ```powershell
   Remove-Item "<executable_path>" -Force
   ```

3. **Check for additional persistence mechanisms** — attackers rarely use just one:
   ```powershell
   # Scheduled tasks
   Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Format-Table TaskName, TaskPath, State
   
   # Startup folder
   Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
   Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
   
   # Services (look for unusual ones)
   Get-Service | Where-Object {$_.StartType -eq "Automatic"} | Format-Table Name, DisplayName, Status
   ```

4. **Scan the endpoint** — run a full antivirus/EDR scan

5. **Monitor for re-creation** — the attacker may have a secondary mechanism that recreates the Run key. Watch for Rule 100004 firing again within the next 24 hours.

6. **Escalate to Tier 2** with full timeline, removed artifacts, and any additional persistence found.

---

## Evidence Collection

| Evidence Item | Source | Format |
|---|---|---|
| Wazuh alert for Rule 100004 (full JSON) | Dashboard export | JSON |
| Registry key contents (before removal) | PowerShell output | Text |
| Executable file hash | `Get-FileHash` output | Text |
| Executable signature check | `Get-AuthenticodeSignature` output | Text |
| Related alerts (±30 min) | Dashboard filtered search | Screenshot + JSON |
| Process tree events | Wazuh search by processGuid | Screenshot |
| Current Run key baseline | PowerShell output | Text |

---

## Post-Incident

**Detection tuning recommendations:**
- Consider adding a whitelist for known legitimate Run key values (antivirus, VPN, cloud sync) to reduce false positives
- Add a rule for `RunOnce` key modifications specifically — these are more suspicious as they self-delete after execution
- Consider a higher severity rule for Run key values pointing to `%TEMP%`, `%APPDATA%`, or `C:\Users\Public\` paths

**Hardening recommendations:**
- Restrict registry write permissions on HKLM Run keys to administrators only
- Use Group Policy to control which applications are allowed in Run keys
- Enable Windows AppLocker or WDAC to prevent unauthorized executables from running regardless of registry configuration

**Metrics to record:**
- Time from persistence creation to detection (MTTD)
- Whether persistence was part of a larger attack chain
- Classification: true positive (malicious persistence) or false positive (legitimate software)
- Whether the registered executable was already known to threat intelligence
