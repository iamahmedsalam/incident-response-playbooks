# PB-004 — Windows Event Log Cleared

## Alert Overview

| Field | Value |
|---|---|
| **Playbook ID** | PB-004 |
| **MITRE ATT&CK** | T1070.001 — Indicator Removal on Host: Clear Windows Event Logs |
| **Wazuh Rule** | 100006 (Level 14 — Critical) |
| **Log Source** | Windows Event ID 104 (Log Cleared), chains off built-in Rule 60106 |
| **Platform** | Windows |
| **Agent** | WIN11-SOC-Endpoint (Agent 001 — 192.168.56.103) |

**What the analyst sees:** A Level 14 (Critical) alert fires for Rule 100006 indicating that a Windows event log was cleared. This is the highest severity level in the custom rule set. Log clearing is a defence evasion technique — attackers destroy forensic evidence after completing their objectives.

**Why this matters:** Log clearing is almost never legitimate in a monitored environment. When this alert fires, it means either an active attacker is covering tracks or something is seriously misconfigured. Either way, it demands immediate investigation. Critically, centralised SIEM forwarding means the clearing event itself — and all events that preceded it — are preserved in Wazuh's Elasticsearch index even after the local log is wiped.

---

## Triage Checklist

**Step 1 — This is Critical severity. Treat as true positive until proven otherwise.**
- Level 14 alerts skip the "is this a false positive?" question. Investigate first, classify after.
- Legitimate log clearing in a monitored environment should be pre-approved through change management.

**Step 2 — Which log was cleared?**
- Check `data.win.eventdata.channel` — System, Security, Application, or Sysmon?
- Security log cleared = **highest concern** — this is where authentication, privilege escalation, and policy change events live
- Sysmon log cleared = attacker specifically targeting endpoint visibility
- System/Application = may be less targeted but still suspicious

**Step 3 — Who cleared the log?**
- Check `data.win.eventdata.user` — what account performed the clearing?
- Was this an expected admin action? (Check change management tickets)
- If the clearing user is the same account seen in other alerts → confirmed attacker activity

**Step 4 — What happened BEFORE the log was cleared?**
- This is the most important question. Attackers clear logs AFTER their activity.
- Everything that happened before the clearing is likely the actual attack.
- Proceed to full investigation immediately.

**Decision:** Log clearing at Level 14 always warrants full investigation. The only path to closing as FP is confirmed, documented, pre-approved maintenance activity.

---

## Investigation Procedure

### Extract Key Artifacts from the Alert

| Artifact | Wazuh Field | What to Record |
|---|---|---|
| Timestamp | `timestamp` | Exact time the log was cleared |
| Log channel cleared | `data.win.eventdata.channel` | Which log was wiped |
| User who cleared | `data.win.eventdata.user` | Account that performed the action |
| Agent name | `agent.name` | Target system |
| Event ID | `data.win.system.eventID` | Should be 104 |
| Computer | `data.win.system.computer` | Hostname confirmation |

### Recover Pre-Clearing Activity from SIEM

**This is the key advantage of centralised log forwarding.** The local log is gone, but Wazuh already has everything indexed.

In Wazuh dashboard, search for all events from this agent BEFORE the log clearing:
```
agent.id: 001 AND @timestamp:[clearing_time - 60m TO clearing_time]
```

Sort by timestamp (oldest first). Build a complete timeline of what happened in the 60 minutes before the attacker cleared the logs. Look for:

- Rule 100001 — PowerShell execution (initial access or payload delivery)
- Rule 100004 — Registry persistence (attacker establishing foothold)
- Rule 100005 — New account created (backdoor account)
- Rule 100003 — LSASS access (credential theft)
- Rule 100008 — Files dropped in Temp (tools or payloads staged)
- Rule 100007 — Process injection (defence evasion)
- Any unusual process creation, network connections, or authentication events

**Record every alert in chronological order.** This becomes the attack timeline.

### Check if Multiple Logs Were Cleared

Search for all log clearing events from the same agent:
```
agent.id: 001 AND rule.id: 100006
```

If multiple log channels were cleared in rapid succession (System, Security, Application) → the attacker systematically wiped all evidence. This indicates a more sophisticated adversary.

Also check for Sysmon log clearing:
```
agent.id: 001 AND full_log: *"Microsoft-Windows-Sysmon"* AND full_log: *clear*
```

### Check for Tool Usage

Common tools used to clear logs:
- `wevtutil cl <logname>` — command-line utility
- `Clear-EventLog` — PowerShell cmdlet
- Event Viewer GUI — right-click → Clear Log

Search for these in Sysmon process creation events:
```
agent.id: 001 AND (data.win.eventdata.commandLine: *wevtutil* OR data.win.eventdata.commandLine: *Clear-EventLog*)
```

### Assess Scope of Compromise

Based on the pre-clearing timeline, determine:
1. How did the attacker gain access? (initial access vector)
2. What did they do? (execution, persistence, credential access)
3. How long were they active? (dwell time)
4. Did they move to other systems? (lateral movement)
5. What data could they have accessed? (impact assessment)

---

## Containment & Response

**Immediate actions (take all of these):**

1. **Isolate the endpoint** — remove from network immediately. Log clearing is late-stage attacker activity — they may be actively exfiltrating data or moving laterally.

2. **Preserve SIEM evidence** — export ALL indexed events from this agent for the past 72 hours:
   ```
   agent.id: 001 AND @timestamp:[now - 72h TO now]
   ```
   Export as JSON or CSV — this is now the only forensic record since local logs were destroyed.

3. **Check other endpoints** — search for alerts from any agent triggered by the same source IP or user account:
   ```
   data.srcip: <attacker_IP> OR data.win.eventdata.user: <attacker_account>
   ```

4. **Credential reset** — change passwords for:
   - The account that cleared the logs
   - Any admin accounts active on the endpoint
   - Any accounts observed in the pre-clearing alert timeline

5. **Memory capture** — if possible, take a memory dump of the endpoint before powering off. Attackers may have tools loaded in memory that aren't on disk.

6. **Full disk image** — in production, create a forensic image of the endpoint for detailed analysis.

7. **Escalate to IR team** — this is a confirmed incident. Provide:
   - Complete pre-clearing timeline from SIEM
   - All alerts from the affected agent
   - Evidence of any lateral movement
   - Containment actions already taken

---

## Evidence Collection

| Evidence Item | Source | Format |
|---|---|---|
| Rule 100006 alert (full JSON) | Dashboard export | JSON |
| Pre-clearing timeline (all events -60m) | Dashboard filtered export | JSON + Screenshot |
| All Rule 100006 alerts (check for multiple clears) | Dashboard search | JSON |
| Tool usage evidence (wevtutil/Clear-EventLog) | Sysmon process creation logs | JSON |
| Related alerts from other agents | Dashboard cross-agent search | JSON |
| Full 72-hour event export | Dashboard export | JSON/CSV |

---

## Post-Incident

**Detection tuning recommendations:**
- Rule 100006 at Level 14 is correctly calibrated — do not lower the severity
- Consider adding a separate rule for Security log clearing (Event ID 1102) if not already covered by built-in rules — Security log clearing is even more suspicious than System log clearing
- Consider adding automated response: when Rule 100006 fires, automatically trigger endpoint isolation via SOAR integration (future Project 3/4 enhancement)

**Architecture insight documented during Project 1:**
Centralised log forwarding to Wazuh preserves all events before an attacker can clear local Windows logs. The clearing event itself is captured in the Elasticsearch index before the local log is deleted. This was proven during the T1070.001 simulation — the Wazuh alert for the clearing event was indexed within 3 seconds, before the local System log was actually wiped. This is the fundamental value of centralised SIEM monitoring.

**Hardening recommendations:**
- Restrict log clearing permissions — only specific admin accounts should have `SeSecurityPrivilege`
- Enable audit policy for log management events (Event ID 1102, 104)
- Consider making event logs append-only via Group Policy where supported
- Implement log backup to a separate, immutable storage location

**Metrics to record:**
- Time from log clearing to alert (MTTD)
- Time from alert to endpoint isolation (MTTR)
- Completeness of pre-clearing timeline recovery from SIEM
- Number of log channels cleared
- Dwell time (time between first attacker activity and log clearing)
