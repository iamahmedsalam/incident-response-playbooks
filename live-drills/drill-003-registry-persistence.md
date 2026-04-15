# Drill 003 — Registry Run Key Persistence

## Alert Summary

| Field | Value |
|---|---|
| **Drill ID** | Drill-003 |
| **Date** | April 13, 2026 |
| **Playbook Used** | PB-003 — Registry Run Key Persistence |
| **Rule Triggered** | 100004 (Level 10 — High) |
| **MITRE ATT&CK** | T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys |
| **Agent** | WIN11-SOC-Endpoint (Agent 001 — 192.168.56.103) |
| **Verdict** | True Positive — malicious persistence entry detected, removed, and additional persistence mechanisms investigated |
| **MTTD** | < 3 seconds |

---

## Investigation Timeline

| Time (UTC) | Event |
|---|---|
| 2026-04-13 15:24:01 | `reg.exe` adds "SOC-Lab-Backdoor" value to HKLM Run key |
| 2026-04-13 15:24:01 | Sysmon Event ID 13 (Registry Value Set) logged |
| 2026-04-13 15:24:01 | Rule 100004 fired — registry persistence detected |
| 2026-04-13 15:24:02 | Rule 92200 fired — scripting file created under Windows Temp/User folder |
| 2026-04-13 15:24:03 | Investigation initiated following PB-003 |
| 2026-04-13 ~15:30:00 | Containment: malicious registry entry removed |
| 2026-04-13 ~15:35:00 | Additional persistence check completed — no other mechanisms found |

---

## Artifacts Extracted

| Artifact | Value |
|---|---|
| Timestamp | Apr 13, 2026 @ 15:24:01.134 |
| Registry Path | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SOC-Lab-Backdoor` |
| Value Data | `C:\Users\Public\Downloads\backdoor.exe` |
| Modifying Process | `C:\WINDOWS\system32\reg.exe` |
| Process GUID | `{6aabac00-4354-69dd-0e02-000000001800}` |
| Process ID | 9364 |
| User | `WIN11-SOC-ENDPO\Jackal` |
| Event Type | SetValue |
| Rule Level | 10 (High) |
| Rule Description | Registry persistence detected — Run key modification (T1547.001) |

---

## Registry Analysis

### Suspicious Entry Identified

| Field | Analysis |
|---|---|
| **Registry location** | `HKLM\...\Run` — affects ALL users on the system (higher severity than HKCU) |
| **Value name** | `SOC-Lab-Backdoor` — not matching any known legitimate software |
| **Executable path** | `C:\Users\Public\Downloads\backdoor.exe` — `C:\Users\Public\Downloads\` is writable by all users, a common attacker staging directory |
| **Modifying process** | `reg.exe` — legitimate Windows binary, living-off-the-land technique |

### File Existence Check

```powershell
Test-Path "C:\Users\Public\Downloads\backdoor.exe"
# Result: False
```

The registered executable does not exist on disk. This could indicate:
- The attacker hasn't deployed the payload yet (persistence planted before tool transfer)
- The payload was already executed and self-deleted
- The payload download failed

In a production investigation, the absence of the file would prompt checking Sysmon Event 11 (FileCreate) and Event 23 (FileDelete) logs for any file activity at that path.

### Full Run Key Contents at Time of Investigation

```
SecurityHealth   : C:\WINDOWS\system32\SecurityHealthSystray.exe    ← Legitimate (Windows Security)
VBoxTray         : C:\WINDOWS\system32\VBoxTray.exe                 ← Legitimate (VirtualBox Guest)
MalwareTest      : C:\Windows\Temp\malware.exe                      ← Suspicious (Atomic Red Team leftover from Project 1)
SOC-Lab-Backdoor : C:\Users\Public\Downloads\backdoor.exe           ← MALICIOUS (investigation target)
```

**Additional finding:** A pre-existing `MalwareTest` entry pointing to `C:\Windows\Temp\malware.exe` was identified during the Run key review. This is a residual artifact from Project 1 Atomic Red Team testing. In a real investigation, this would be flagged as a second suspicious persistence entry requiring separate investigation.

---

## Related Activity — Attack Chain Check

**Wazuh query:** `agent.id: 001 AND @timestamp:[now-15m TO now]`

Alerts observed in the same time window:

| Rule | Description | Relation to Attack |
|---|---|---|
| 100004 | Registry persistence — Run key modification (T1547.001) | **Primary alert — investigation target** |
| 92200 | Scripting file created under Windows Temp or User folder | Triggered seconds after 100004 — related system activity |
| 61618 | Sysmon — Suspicious Process — svchost.exe | Normal system activity (scheduled task execution) |
| 92154 | Process loaded taskschd.dll module | Normal system activity (task scheduler) |
| 60642 | Software protection service scheduled successfully | Normal system activity (Windows licensing) |

**Custom rule correlation check:** `rule.id: 100008 OR rule.id: 100006 OR rule.id: 100001` — No results.

**Assessment:** No coordinated attack chain detected. Rules 92200, 61618, 92154, and 60642 are normal Windows background activity unrelated to the registry modification. The persistence was an isolated action — no preceding execution phase (100001) or file staging (100008) was observed, and no post-persistence log clearing (100006) was attempted.

---

## Containment Actions Performed

### 1. Removed Malicious Registry Entry

```powershell
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SOC-Lab-Backdoor"
```

**Verification:** Re-queried the Run key — `SOC-Lab-Backdoor` entry no longer present.

### 2. Additional Persistence Mechanism Check

| Location | Check | Result |
|---|---|---|
| HKCU Run key | `Get-ItemProperty HKCU:\...\Run` | Only `OneDrive` — legitimate |
| HKLM RunOnce | `Get-ItemProperty HKLM:\...\RunOnce` | Empty — clean |
| User Startup folder | `Get-ChildItem $env:APPDATA\...\Startup` | Empty — clean |
| System Startup folder | `Get-ChildItem C:\ProgramData\...\Startup` | Empty — clean |
| Scheduled Tasks (non-Microsoft) | `Get-ScheduledTask` filtered | MicrosoftEdge + OneDrive only — all legitimate |

**Result:** No additional persistence mechanisms found. The SOC-Lab-Backdoor entry was the only malicious modification.

---

## Verdict & Classification

| Field | Value |
|---|---|
| Classification | True Positive — malicious registry persistence detected correctly |
| Attack Technique | Living-off-the-land (reg.exe used for malicious registry modification) |
| Registry Scope | HKLM (all users affected) |
| File on Disk | Not present (payload not deployed or already removed) |
| Compromise Status | Persistence planted but payload absent — early-stage detection |
| Disposition | Remediated — malicious entry removed, additional persistence checked |
| Containment | Registry entry removed, no additional persistence found |

---

## Containment Recommendations (Production)

1. **Remove the registry entry** — completed
2. **Run full antivirus/EDR scan** — check for any payloads the attacker may have staged elsewhere
3. **Monitor for re-creation** — attacker may attempt to re-establish persistence; watch for Rule 100004 firing again within 24 hours
4. **Investigate the MalwareTest entry** — pre-existing `MalwareTest : C:\Windows\Temp\malware.exe` in the Run key should be investigated separately as a potential prior compromise
5. **Check how reg.exe was launched** — trace the parent process tree to determine what initiated the registry modification
6. **Review user activity** — determine if the `Jackal` account was compromised or if this was an insider action

---

## Performance Metrics

| Metric | Value |
|---|---|
| Mean Time to Detect (MTTD) | < 3 seconds |
| Mean Time to Investigate (MTTI) | ~15 minutes (full playbook walkthrough) |
| Mean Time to Contain (MTTC) | ~5 minutes (registry removal + persistence sweep) |
| True Positive / False Positive | True Positive |
| Persistence removed | Yes |
| Additional persistence found | No (MalwareTest entry noted for separate investigation) |
| Playbook followed | PB-003 — all steps completed |

---

## Detection Improvements Identified

1. **MalwareTest residual** — the pre-existing `MalwareTest` Run key entry from Atomic Red Team testing should have been cleaned up after Project 1. In production, post-exercise cleanup checklists prevent residual artifacts from confusing future investigations.

2. **Path-based severity escalation** — consider a higher severity rule (Level 12+) when the registered executable path contains `C:\Users\Public\`, `%TEMP%`, or `%APPDATA%` — these staging directories are almost never used by legitimate auto-start programs.

3. **HKLM vs HKCU differentiation** — the current rule catches both. Consider separate rules or severity levels: HKLM modifications affect all users and are higher severity than HKCU modifications which only affect the current user.

---

## Simulation Context

This drill was executed as part of the Home SOC Lab v2.0 Project 2 — Incident Response Playbook + Live Drill. A simulated persistence entry was added to the HKLM Run key using `reg.exe` to test the detection pipeline and validate the PB-003 investigation workflow.

**What was tested:**
- Rule 100004 detection of Run key modification via Sysmon Event 13
- PB-003 triage checklist — registry path analysis, value data review, modifying process identification
- File existence verification at the registered executable path
- Full containment workflow — registry entry removal + additional persistence sweep
- Living-off-the-land technique identification (reg.exe)

**What was validated:**
- Detection latency under 3 seconds
- Sysmon Event 13 captures full registry path, value data, and modifying process
- Containment procedure is clear and effective
- Additional persistence checks cover Run, RunOnce, Startup folders, and Scheduled Tasks
- Pre-existing suspicious entries (MalwareTest) are surfaced during investigation
