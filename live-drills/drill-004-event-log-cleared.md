# Drill 004 — Windows Event Log Cleared

## Alert Summary

| Field | Value |
|---|---|
| **Drill ID** | Drill-004 |
| **Date** | April 14, 2026 |
| **Playbook Used** | PB-004 — Windows Event Log Cleared |
| **Rule Triggered** | 100006 (Level 14 — Critical) |
| **MITRE ATT&CK** | T1070.001 — Indicator Removal on Host: Clear Windows Event Logs |
| **Agent** | WIN11-SOC-Endpoint (Agent 001 — 192.168.56.103) |
| **Verdict** | True Positive — log cleared after account creation + registry persistence, all activity recovered from SIEM |
| **MTTD** | < 3 seconds |

---

## Investigation Timeline

This drill simulated a multi-stage attack: the attacker creates a backdoor account, establishes registry persistence, then clears logs to cover their tracks. The SIEM preserved the entire timeline.

| Time (UTC) | Event | Rule |
|---|---|---|
| 2026-04-14 16:51:30 | Attacker creates local account `SOCLabHacker` via `net user /add` | 100005 |
| 2026-04-14 16:51:45 | Attacker adds `HackerBackdoor` to HKLM Run key via `reg add` | 100004 |
| 2026-04-14 16:51:45 | PowerShell script policy test file created in Temp | 100008 |
| 2026-04-14 16:52:51 | Attacker clears System event log via `wevtutil cl System` | **100006** |
| 2026-04-14 16:52:51 | Windows Event ID 104 generated — log file cleared | Built-in |
| 2026-04-14 16:52:52 | Local System log is now empty — forensic evidence destroyed locally | — |
| 2026-04-14 16:52:52 | **All events preserved in Wazuh Elasticsearch index** | — |
| 2026-04-14 16:53:00 | Investigation initiated following PB-004 | — |

---

## Artifacts Extracted

| Artifact | Value |
|---|---|
| Timestamp | Apr 14, 2026 @ 16:52:51.098 |
| Event ID | 104 (Log Cleared) |
| Log Channel Cleared | System |
| User Who Cleared | Jackal |
| Agent Name | WIN11-SOC-Endpoint |
| Rule ID | 100006 |
| Rule Level | 14 (Critical — highest severity in custom rule set) |
| Rule Description | CRITICAL: Windows event log cleared — attacker covering tracks (T1070.001) |

---

## Local Log Verification

After the clearing, the local System log was examined:

```powershell
Get-WinEvent -LogName System -MaxEvents 5
```

**Result:** Only 3 events remained — two `Kernel-Power` events from session transitions and Event ID 104 (the clearing event itself). All prior System log entries were destroyed. An investigator examining only the local endpoint would find virtually no forensic evidence.

---

## SIEM Recovery — Centralised Log Forwarding in Action

**This is the core architectural lesson of this drill.**

Despite the local System log being emptied, the Wazuh SIEM preserved the complete attack timeline. Every event was forwarded and indexed before the attacker could destroy it.

### Custom Rule Alerts Recovered

Search query: `rule.id: 100005 OR rule.id: 100004 OR rule.id: 100006 OR rule.id: 100008`

| Order | Rule | Description | MITRE | What It Proves |
|---|---|---|---|---|
| 1 | 100005 | New local user created via net user command | T1136.001 | Attacker created backdoor account `SOCLabHacker` |
| 2 | 100004 | Registry persistence — Run key modification | T1547.001 | Attacker planted `HackerBackdoor` auto-start entry |
| 3 | 100008 | File dropped in Temp/AppData folder | T1105 | Script policy test file created during attack execution |
| 4 | 100006 | **Windows event log cleared** | T1070.001 | Attacker attempted to destroy evidence of steps 1–3 |

### Additional Built-in Alerts Recovered

Beyond the custom rules, Wazuh's built-in detection captured additional attacker footprints:

| Rule | Description | Significance |
|---|---|---|
| 60160 | Domain Users Group Changed | Account `SOCLabHacker` was added to user groups |
| 60109 | User account enabled or created | Confirms the account creation event from a different log source |
| 92041 | Value added to registry key has Base64-like pattern | Registry modification with encoded data detected |

**Total alerts in the attack window:** 16 hits across custom and built-in rules — a complete forensic picture of the attacker's actions, recovered entirely from centralised SIEM data.

### What This Proves

The attacker's `wevtutil cl System` command successfully destroyed the local System event log. If an investigator only had access to the endpoint, they would find an empty log with no evidence of the account creation, registry persistence, or any preceding activity.

However, the Wazuh agent forwarded every event to the Manager in near-real-time. By the time the attacker cleared the local log, all evidence was already indexed in Elasticsearch and could not be retroactively deleted from the SIEM. The attacker would need to compromise the SIEM infrastructure itself to destroy this evidence — a significantly harder target.

**This is the fundamental value proposition of centralised SIEM monitoring.**

---

## Containment Actions Performed

### 1. Removed Backdoor Account
```powershell
net user SOCLabHacker /delete
# Verified: "The user name could not be found" — confirmed deleted
```

### 2. Removed Registry Persistence
```powershell
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "HackerBackdoor"
# Verified: Run key now contains only SecurityHealth and VBoxTray (both legitimate)
```

### 3. Verification Results
- `SOCLabHacker` account — deleted, no longer exists
- `HackerBackdoor` Run key entry — removed, Run key clean
- Run key final state: `SecurityHealth` + `VBoxTray` only (both legitimate)

---

## Reconstructed Attack Chain

Based on SIEM recovery, the complete attack chain was:

```
T1136.001 — Account Creation (net user SOCLabHacker /add)
    → T1547.001 — Registry Persistence (reg add HackerBackdoor)
        → T1105 — File Staging (script policy test in Temp)
            → T1070.001 — Log Clearing (wevtutil cl System)
```

This follows a classic attack pattern: **establish access → ensure persistence → cover tracks**. The attacker created a backdoor account for future access, added a registry entry to survive reboots, then attempted to destroy evidence of their activity. All four stages were detected and preserved by the SIEM.

---

## Verdict & Classification

| Field | Value |
|---|---|
| Classification | True Positive — multi-stage attack detected and fully recovered from SIEM |
| Attack Stages | 4 (Account Creation → Persistence → File Staging → Log Clearing) |
| Local Evidence Status | Destroyed (System log cleared) |
| SIEM Evidence Status | Fully preserved — complete timeline recovered |
| Compromise Status | Attacker actions fully reversed (account deleted, persistence removed) |
| Disposition | Remediated — all attacker artifacts removed |
| Key Lesson | Centralised SIEM forwarding preserves evidence that local log clearing cannot destroy |

---

## Performance Metrics

| Metric | Value |
|---|---|
| Mean Time to Detect (MTTD) | < 3 seconds |
| Mean Time to Investigate (MTTI) | ~20 minutes (full playbook + SIEM recovery) |
| Mean Time to Contain (MTTC) | ~5 minutes (account deletion + registry removal) |
| True Positive / False Positive | True Positive |
| Attack stages detected | 4/4 (100%) |
| Evidence recovered from SIEM | Complete timeline — all stages |
| Custom rules fired | 100004, 100005, 100006, 100008 |
| Built-in rules fired | 60109, 60160, 92041 |
| Playbook followed | PB-004 — all steps completed |

---

## Detection Improvements Identified

1. **Multi-log clearing detection** — current Rule 100006 detects System log clearing. Consider adding detection for Security log clearing (Event ID 1102) and Sysmon log clearing, which would indicate a more thorough attacker attempting to wipe all evidence.

2. **Automated correlation** — when Rule 100006 fires, automatically search for all custom rule alerts from the same agent in the preceding 60 minutes. This SIEM recovery step should be automated, not manual, to reduce investigation time.

3. **Attack chain scoring** — when Rules 100005 + 100004 + 100006 fire from the same agent within a short window, the combined severity should be elevated beyond any individual rule. This pattern (create account → persist → clear logs) is a high-confidence indicator of real compromise.

---

## Simulation Context

This drill was executed as part of the Home SOC Lab v2.0 Project 2 — Incident Response Playbook + Live Drill. A multi-stage attack was simulated: account creation, registry persistence, and log clearing — then the full SIEM recovery workflow was demonstrated.

**What was tested:**
- Rule 100006 detection of log clearing (Level 14 — Critical)
- PB-004 triage and investigation workflow
- Centralised SIEM evidence preservation after local log destruction
- Multi-rule attack chain correlation (100005 → 100004 → 100008 → 100006)
- Full containment cycle (account deletion + registry removal + verification)

**What was validated:**
- Wazuh preserved all attacker activity despite local log clearing
- 4 custom rules and 3 built-in rules captured different aspects of the same attack
- Attack timeline fully reconstructable from SIEM data alone
- Containment procedures are effective and verifiable
- This drill demonstrated the single most important architectural principle in SIEM deployment
