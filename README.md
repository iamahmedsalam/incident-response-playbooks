# 🔰 Incident Response Playbooks + Live Drills

**Professional SOC L1 incident response playbooks with real-world validation — 5 attack scenarios simulated, investigated, and documented using a production-grade Wazuh SIEM lab.**

> Built by [Ahmed Salam](https://iamahmedsalam.com) — Aspiring AI-Augmented SOC Analyst | CompTIA Security+ | TryHackMe Top 2%

---

## What This Project Proves

A detection rule that fires is only half the job. What happens next — triage, investigation, containment, documentation — is what separates a SOC analyst from a dashboard watcher.

This project contains 5 reusable incident response playbooks and 5 corresponding live drill reports where each playbook was executed against real attacks in a home lab. Every drill uses real Wazuh alerts, real forensic artifacts, and real containment actions.

---

## Playbooks

Standardised response procedures — the runbooks an analyst follows when a specific alert fires.

| Playbook | MITRE Technique | Alert Rule | Platform |
|---|---|---|---|
| [PB-001 — PowerShell Encoded Command](playbooks/PB-001-powershell-execution.md) | T1059.001 | 100001 (Level 10) | Windows |
| [PB-002 — SSH Brute Force](playbooks/PB-002-ssh-brute-force.md) | T1110.001 | 100011 (Level 12) | Linux |
| [PB-003 — Registry Run Key Persistence](playbooks/PB-003-registry-persistence.md) | T1547.001 | 100004 (Level 10) | Windows |
| [PB-004 — Windows Event Log Cleared](playbooks/PB-004-event-log-cleared.md) | T1070.001 | 100006 (Level 14) | Windows |
| [PB-005 — Malware Dropper in Temp Folder](playbooks/PB-005-malware-dropper-temp.md) | T1105 | 100008 (Level 10) | Windows |

Each playbook includes: Alert Overview, Triage Checklist (decision tree), Investigation Procedure (exact commands and queries), Containment & Response, Evidence Collection, and Post-Incident recommendations.

---

## Live Drills

Real attack simulations executed in the lab, investigated following the playbooks above, documented with actual Wazuh alert data.

| Drill | Attack Method | Detection | Outcome |
|---|---|---|---|
| [Drill 001 — PowerShell](live-drills/drill-001-powershell.md) | `-EncodedCommand` with Base64 payload | ✅ Rule 100001 | Payload decoded, attack chain correlated (100001 + 100008) |
| [Drill 002 — SSH Brute Force](live-drills/drill-002-ssh-bruteforce.md) | Hydra from Kali (15 attempts, 4 threads) | ✅ Rule 100011 | No successful login, full compromise assessment performed |
| [Drill 003 — Registry Persistence](live-drills/drill-003-registry-persistence.md) | `reg.exe` adds Run key (LOLBIN) | ✅ Rule 100004 | Entry removed, persistence sweep completed |
| [Drill 004 — Log Cleared](live-drills/drill-004-event-log-cleared.md) | `wevtutil cl System` after multi-stage attack | ✅ Rule 100006 | Full attack timeline recovered from SIEM despite local log destruction |
| [Drill 005 — Malware Dropper](live-drills/drill-005-malware-dropper.md) | `certutil -encode` drops `.exe` in Temp (LOLBIN) | ✅ Rule 100008 | File caught before execution, quarantined with hash preserved |

---

## Key Findings Across All Drills

**Detection Performance:**
- Mean Time to Detect (MTTD) across all 5 drills: **< 3 seconds**
- All 5 attacks detected by custom Wazuh rules
- Multi-rule correlation observed in Drills 001 and 004

**Investigation Skills Demonstrated:**
- Base64 payload decode and analysis (Drill 001)
- Brute force pattern identification with automated tool signature detection (Drill 002)
- Living-off-the-land binary (LOLBIN) identification — `reg.exe` and `certutil.exe` (Drills 003, 005)
- Centralised SIEM evidence recovery after local log destruction (Drill 004)
- File hash extraction, signature verification, and evidence-preserving quarantine (Drill 005)

**Containment Actions Performed:**
- Registry persistence entries removed and verified (Drills 003, 004)
- Backdoor user account deleted (Drill 004)
- Malicious file quarantined to evidence folder (Drill 005)
- Additional persistence mechanism sweep across Run keys, RunOnce, Startup folders, and Scheduled Tasks (Drills 003, 004)

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Playbook | Drill |
|---|---|---|---|
| Execution | T1059.001 — PowerShell | PB-001 | Drill 001 |
| Credential Access | T1110.001 — Brute Force | PB-002 | Drill 002 |
| Persistence | T1547.001 — Registry Run Keys | PB-003 | Drill 003 |
| Defence Evasion | T1070.001 — Clear Event Logs | PB-004 | Drill 004 |
| Command & Control | T1105 — Ingress Tool Transfer | PB-005 | Drill 005 |

Five different tactics, two platforms (Windows + Linux), three different log sources (Sysmon Events 1/11/13, Windows Event 104, auth.log).

---

## Repository Structure

```
incident-response-playbooks/
├── README.md
├── playbooks/
│   ├── PB-001-powershell-execution.md
│   ├── PB-002-ssh-brute-force.md
│   ├── PB-003-registry-persistence.md
│   ├── PB-004-event-log-cleared.md
│   └── PB-005-malware-dropper-temp.md
├── live-drills/
│   ├── drill-001-powershell.md
│   ├── drill-002-ssh-bruteforce.md
│   ├── drill-003-registry-persistence.md
│   ├── drill-004-event-log-cleared.md
│   └── drill-005-malware-dropper.md
├── detection-improvements/
│   └── rule-tuning-log.md
├── screenshots/
│   ├── drill-001/
│   ├── drill-002/
│   ├── drill-003/
│   ├── drill-004/
│   └── drill-005/
└── docs/
    └── lessons-learned.md
```

---

## Lab Environment

This project uses the [Home SOC Lab v2.0](https://github.com/iamahmedsalam/home-soc-lab) infrastructure:

| VM | IP | Role |
|---|---|---|
| Wazuh Manager | 192.168.56.101 | SIEM (Wazuh 4.14.4 all-in-one) |
| Windows 11 | 192.168.56.103 | Monitored endpoint (Agent 001, Sysmon v15.15) |
| Ubuntu Agent | 192.168.56.104 | Monitored endpoint (Agent 002, auditd) |
| Kali Linux | 192.168.56.50 | Attack machine |

Detection rules used: 11 custom rules (100001–100011) mapped to MITRE ATT&CK. Full rule set available at [home-soc-lab/detection-rules](https://github.com/iamahmedsalam/home-soc-lab/tree/main/detection-rules).

---

## Relationship to Project 1

| | Project 1 — Home SOC Lab v2.0 | Project 2 — IR Playbooks + Live Drills |
|---|---|---|
| **Focus** | Build the detection environment | Respond to what it detects |
| **Proves** | Can you detect threats? | Can you investigate and contain them? |
| **Deliverables** | Detection rules, simulation results, architecture docs | Playbooks, drill reports, containment procedures |
| **Repo** | [home-soc-lab](https://github.com/iamahmedsalam/home-soc-lab) | This repo |

---

## About

**Ahmed Salam** — Aspiring AI-Augmented SOC Analyst

- 🏆 TryHackMe Top 2% Globally (132 rooms, 30 badges)
- 🎓 CompTIA Security+ Certified
- 📜 SOC Level 1 — TryHackMe (April 2026)
- 🌐 Portfolio: [iamahmedsalam.com](https://iamahmedsalam.com)
- 💼 LinkedIn: [Ahmed Salam](https://www.linkedin.com/in/ahmedsalamnyc)
- 🐙 GitHub: [iamahmedsalam](https://github.com/iamahmedsalam)

---

## License

MIT License — see [LICENSE](LICENSE) for details.
