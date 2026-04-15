# Lessons Learned — Project 2: IR Playbooks + Live Drills

---

## The Difference Between Detection and Response

Project 1 proved I can build a detection environment and write rules that fire. Project 2 proved I can work the alerts those rules generate — triage, investigate, contain, and document. A SIEM that detects everything but has no response playbooks is just a very expensive log viewer. These playbooks are what turn detections into actionable incident response.

---

## Playbook Design

### Structure Matters

Every playbook follows the same professional format: Alert Overview → Triage Checklist → Investigation Procedure → Containment & Response → Evidence Collection → Post-Incident. This mirrors the NIST Incident Response Lifecycle adapted for alert-level response. Consistency means any analyst can pick up any playbook and follow it without learning a new format.

### Triage Decision Trees Save Time

Each playbook starts with a triage checklist — a step-by-step decision tree that helps determine TP/FP within 2–3 minutes for clear-cut cases. In real SOC environments, alert fatigue happens when every alert requires 30 minutes of investigation. Good triage checklists cut that to under 5 minutes for obvious cases and focus investigation time on genuinely suspicious alerts.

### Cross-Playbook Correlation

The playbooks reference each other. PB-003 (registry persistence) tells you to check for PB-001 (PowerShell execution) and PB-005 (file in Temp) in the same time window. PB-004 (log cleared) tells you to reconstruct everything that happened before the clearing. This cross-referencing reflects how real attacks work — they're multi-stage, and individual alerts are puzzle pieces.

---

## Investigation Skills Developed

### Living-off-the-Land Binary (LOLBIN) Identification

Drills 003 and 005 involved `reg.exe` and `certutil.exe` — legitimate Windows tools used for malicious purposes. The key insight: you can't block these tools because Windows needs them. Detection must focus on what the tool is doing (modifying Run keys, creating files in Temp) rather than whether the tool itself is suspicious. This is the fundamental challenge of LOLBIN-based attacks and why behavioral detection rules are more valuable than signature-based blocks.

### SIEM Evidence Recovery

Drill 004 demonstrated the most important architectural principle in SIEM deployment: centralised log forwarding preserves evidence that local log clearing cannot destroy. The attacker successfully emptied the local System log, but the complete attack timeline (account creation → registry persistence → log clearing) was fully recoverable from Wazuh's Elasticsearch index. This is why organisations invest in SIEM platforms.

### Multi-Alert Correlation

In Drill 001, Rule 100008 fired alongside Rule 100001 — PowerShell's script policy test file triggered the Temp folder detection. In Drill 004, four custom rules (100004, 100005, 100006, 100008) plus three built-in rules (60109, 60160, 92041) fired for the same multi-stage attack. The ability to correlate alerts across rules and recognise attack chain patterns is what separates an L1 analyst from an alert monkey.

### Evidence-Preserving Containment

Drill 005 taught the quarantine-vs-delete decision. Deleting a suspicious file removes the threat but destroys the evidence. Moving it to a quarantine folder preserves the file for malware analysis, hash submission to threat intel platforms, and legal/compliance requirements — while still removing it from the staging location.

---

## Technical Troubleshooting

### NTP Clock Drift Across VMs

The most significant technical challenge during Project 2 was VM clock synchronisation. VirtualBox VMs drifted from real time after sleep/resume cycles, causing alerts to appear under incorrect timestamps. This made dashboard time-range queries ("Last 15 minutes") miss alerts that were actually generated seconds ago.

**Root cause:** VirtualBox pauses VM clocks when the host machine sleeps. When VMs resume, they continue from the paused timestamp rather than syncing to current time. NTP was configured but couldn't correct large offsets quickly enough.

**Fix:** Manual time correction via `sudo date -u -s` on Linux VMs and `Set-Date` on Windows, followed by restarting the Wazuh Manager and Filebeat.

**Real-world relevance:** Time synchronisation is one of the most common operational issues in production SIEM environments. If endpoint clocks drift from the SIEM server, alert correlation breaks down — you can't build accurate attack timelines if systems disagree on what time it is. Production environments solve this with centralised NTP servers that all systems sync to.

### Wazuh Indexer Pipeline Stall

After VM reboots, the Filebeat → Wazuh Indexer pipeline occasionally stalled. Alerts were being generated in `alerts.json` but not appearing in the dashboard. Diagnosis through Filebeat logs revealed "connection refused" and "OpenSearch Security not initialized" errors.

**Fix:** Restarting services in correct dependency order: Indexer first (wait 30 seconds) → Manager → Filebeat → Dashboard. The Indexer needs full initialisation before Filebeat can ship events to it.

**Real-world relevance:** Understanding the service dependency chain (Indexer → Manager → Filebeat → Dashboard) is essential for SIEM operations. In production, monitoring the health of each pipeline component is as important as monitoring the alerts themselves.

### Rule 100011 XML Placement Error

During Phase A, Rule 100011 was accidentally placed after the `</group>` closing tag instead of before it. `xmllint` caught the syntax error, but a second issue — `<same_source_ip />` incompatible with `if_sid` — passed XML validation but failed Wazuh's logic validation.

**Lesson:** XML syntax validation (`xmllint`) and Wazuh logic validation (analysisd) are two different checks. A rule can be syntactically perfect XML but logically invalid for Wazuh. Always check `ossec.log` after restart failures — the actual error message is there.

---

## Investigation Pattern Recognition

Across all 5 drills, the investigation workflow follows a consistent pattern regardless of the specific attack:

1. **Information gathering** — extract artifacts from the alert itself
2. **Analysis** — understand what the artifacts mean (decode payloads, identify LOLBINs, check file signatures)
3. **Verification** — deeper investigation (execution checks, process trees, download chains)
4. **Decision** — TP or FP based on evidence, not assumption
5. **Containment** — if malicious, remove/quarantine/block while preserving evidence
6. **Documentation** — capture the 5 Ws (what, when, who, where, how) with exact artifacts
7. **Escalation** — pass findings to Tier 2 with context and recommendations
8. **Metrics** — record MTTD, MTTR, classification for performance tracking

This pattern holds whether you're investigating a PowerShell alert, an SSH brute force, or a log clearing event. The specific commands change; the methodology doesn't.

---

## Performance Summary

| Metric | Across All 5 Drills |
|---|---|
| Mean Time to Detect (MTTD) | < 3 seconds (consistent) |
| Mean Time to Investigate (MTTI) | 10–20 minutes per drill |
| True Positive Rate | 5/5 (100%) |
| Containment Actions Performed | Registry removal, account deletion, file quarantine |
| Attack Chain Correlations Identified | 2 (Drills 001 and 004) |
| LOLBINs Identified | 2 (reg.exe, certutil.exe) |
| Platforms Investigated | Windows (Sysmon) + Linux (auth.log) |
| Detection Improvements Documented | 12 recommendations across rules and architecture |
