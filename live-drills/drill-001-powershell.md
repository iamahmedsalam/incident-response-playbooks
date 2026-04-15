# Drill 001 — Suspicious PowerShell Encoded Command Execution

## Alert Summary

| Field | Value |
|---|---|
| **Drill ID** | Drill-001 |
| **Date** | April 11, 2026 |
| **Playbook Used** | PB-001 — Suspicious PowerShell Encoded Command Execution |
| **Rule Triggered** | 100001 (Level 10 — High) |
| **MITRE ATT&CK** | T1059.001 — Command and Scripting Interpreter: PowerShell |
| **Agent** | WIN11-SOC-Endpoint (Agent 001 — 192.168.56.103) |
| **Verdict** | True Positive (simulated attack) — benign payload confirmed |
| **MTTD** | < 3 seconds |

---

## Investigation Timeline

| Time (UTC) | Event |
|---|---|
| 2026-04-11 17:26:08 | PowerShell.exe launched with `-EncodedCommand` parameter |
| 2026-04-11 17:26:08 | Sysmon Event ID 1 (Process Creation) logged |
| 2026-04-11 17:26:08 | Rule 100001 fired — alert visible in Wazuh dashboard |
| 2026-04-11 17:26:08 | Rule 100008 also fired — `.ps1` temp file created by PowerShell |
| 2026-04-11 17:26:09 | Investigation initiated following PB-001 |

---

## Artifacts Extracted

| Artifact | Value |
|---|---|
| Timestamp | Apr 11, 2026 @ 17:26:08.983 |
| Command Line | `powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAUwBPAEMALQBMAGEAYgAtAFQAZQBzAHQALQBUADEAMAA1ADkALgAwADAAMQAiAA==` |
| Process Image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Parent Image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Process ID | 6916 |
| Process GUID | `{6aabac00-bc70-69da-fc01-000000001700}` |
| User | `WIN11-SOC-ENDPO\Jackal` |
| SHA256 | `0FF6F2C94BC7E2833A5F7E16DE1622E5DBA70396F31C7D5F56381870317E8C46` |
| SHA1 | `EB42621654E02FAF2DE940442B6DEB1A77864E5B` |
| MD5 | `A97E6573B97B44C96122BFA543A82EA1` |
| Rule Level | 10 (High) |
| Rule Description | Suspicious PowerShell: Encoded command detected — possible malware execution (T1059.001) |

---

## Payload Analysis

**Base64 encoded string:**
```
VwByAGkAdABlAC0ASABvAHMAdAAgACIAUwBPAEMALQBMAGEAYgAtAFQAZQBzAHQALQBUADEAMAA1ADkALgAwADAAMQAiAA==
```

**Decoded output (UTF-16LE → UTF-8):**
```
Write-Host "SOC-Lab-Test-T1059.001"
```

**Assessment:** The decoded payload is a benign `Write-Host` command that prints text to the console. No download cradles, no reverse shells, no credential theft tools, no file system modifications. The payload itself is harmless.

---

## Triage Walkthrough (Following PB-001)

**Step 1 — Known scheduled task or automation?**
No. The command was executed manually from an interactive PowerShell session. The parent process is `powershell.exe` (user-initiated), not Task Scheduler or an automation tool.

**Step 2 — Parent process analysis:**
Parent image is `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` — PowerShell spawned by PowerShell. This indicates the encoded command was run from within an existing PowerShell session. In a real incident, this chain would be traced further back to determine what initiated the first PowerShell instance.

**Step 3 — Payload decoded:**
The Base64 payload decodes to `Write-Host "SOC-Lab-Test-T1059.001"` — a benign console output command. No malicious indicators.

**Step 4 — User context:**
Executed by `WIN11-SOC-ENDPO\Jackal` — a local user account with administrative privileges. In production, this would be cross-referenced with identity records to verify the user had a legitimate reason for running encoded PowerShell.

---

## Related Activity — Attack Chain Correlation

**Rule 100008 (T1105 — Ingress Tool Transfer)** also fired at the same timestamp from the same agent.

| Field | Value |
|---|---|
| Rule ID | 100008 |
| Description | Executable or script dropped in Temp/AppData folder — possible malware staging (T1105) |
| File | `C:\Users\Jackal\AppData\Local\Temp\__PSScriptPolicyTest_*.ps1` |
| Creating Process | `powershell.exe` |

**Correlation analysis:** PowerShell automatically creates a temporary `.ps1` script policy test file in `%TEMP%` when executing encoded commands. This is normal PowerShell behaviour — not a second-stage payload. However, the fact that two custom rules (100001 + 100008) fired simultaneously from the same agent demonstrates that attack chain detection is working correctly. In a real incident involving a malicious encoded command, this dual alert pattern would be a strong indicator of a multi-stage attack (execution + staging).

**No other custom rules fired** in the ±15 minute window — no registry persistence (100004), no account creation (100005), no log clearing (100006).

---

## Verdict & Classification

| Field | Value |
|---|---|
| Classification | True Positive — encoded PowerShell execution detected correctly |
| Payload Assessment | Benign (test payload, no malicious capability) |
| Disposition | Closed — no containment required |
| Escalation | Not required |

The detection was accurate — Rule 100001 correctly identified PowerShell executing with the `-EncodedCommand` parameter. The alert is a true positive in terms of detection logic. The payload happened to be benign, but the detection pattern would be identical for a malicious payload. No containment actions were necessary.

---

## Performance Metrics

| Metric | Value |
|---|---|
| Mean Time to Detect (MTTD) | < 3 seconds |
| Mean Time to Investigate (MTTI) | ~10 minutes (full playbook walkthrough) |
| True Positive / False Positive | True Positive (detection accurate, payload benign) |
| Related alerts correlated | 1 (Rule 100008 — temp file creation) |
| Playbook followed | PB-001 — all steps completed |

---

## Detection Improvements Identified

1. **IEX/DownloadString gap** — Rule 100001 catches `-EncodedCommand` but would miss `IEX (New-Object Net.WebClient).DownloadString()` which is an equally common T1059.001 variant. Consider adding Rule 100012 for this pattern.

2. **PowerShell Script Policy Test filtering** — The `__PSScriptPolicyTest_*.ps1` temp file triggers Rule 100008 every time an encoded command runs. In a production environment, this specific filename pattern could be whitelisted in Rule 100008 to reduce noise from legitimate PowerShell activity.

3. **Parent process depth** — PB-001 checks the immediate parent process but doesn't trace the full process tree. In a real incident with `powershell.exe` spawning `powershell.exe`, the investigation should trace back further to determine what initiated the chain.

---

## Simulation Context

This drill was executed as part of the Home SOC Lab v2.0 Project 2 — Incident Response Playbook + Live Drill. The encoded command was deliberately crafted with a benign payload (`Write-Host`) to test the detection pipeline and validate the PB-001 investigation workflow.

**What was tested:**
- Rule 100001 detection of `-EncodedCommand` parameter
- PB-001 triage checklist effectiveness
- Base64 payload decode procedure
- Attack chain correlation (100001 + 100008)
- Artifact extraction from Wazuh alerts
- End-to-end investigation documentation

**What was validated:**
- Detection latency under 3 seconds
- All required forensic fields present in the alert
- Playbook steps are clear and actionable
- Multi-rule correlation works as designed
