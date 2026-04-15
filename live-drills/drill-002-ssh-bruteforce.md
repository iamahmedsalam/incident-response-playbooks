# Drill 002 — SSH Brute Force Attack

## Alert Summary

| Field | Value |
|---|---|
| **Drill ID** | Drill-002 |
| **Date** | April 13, 2026 |
| **Playbook Used** | PB-002 — SSH Brute Force Attack |
| **Rule Triggered** | 100011 (Level 12 — High), built-in 5710 (Level 5) |
| **MITRE ATT&CK** | T1110.001 — Brute Force: Password Guessing |
| **Agent** | ubuntu-soc-agent (Agent 002 — 192.168.56.104) |
| **Attack Tool** | Hydra (THC) from Kali Linux (192.168.56.50) |
| **Verdict** | True Positive — brute force detected, no successful login, system not compromised |
| **MTTD** | < 3 seconds |

---

## Investigation Timeline

| Time (UTC) | Event |
|---|---|
| 2026-04-13 17:02:17 | First failed SSH login attempt from 192.168.56.50 |
| 2026-04-13 17:02:17–17:02:26 | Hydra executes 15 password attempts across 4 parallel threads |
| 2026-04-13 17:02:23 | Rule 5710 fires — individual failed login for non-existent user |
| 2026-04-13 17:02:23 | Rule 100011 fires — brute force pattern confirmed (8+ failures from same source IP) |
| 2026-04-13 17:02:27 | All SSH connections closed — Hydra exhausts wordlist |
| 2026-04-13 17:02:30 | Investigation initiated following PB-002 |

---

## Artifacts Extracted

| Artifact | Value |
|---|---|
| Timestamp | Apr 13, 2026 @ 13:01:57.281 (local) / 17:02:23 UTC |
| Source IP | 192.168.56.50 (Kali Linux — attack machine) |
| Target Username | fakeuser (non-existent account) |
| Agent Name | ubuntu-soc-agent |
| Full Log | `Failed password for invalid user fakeuser from 192.168.56.50 port 37752 ssh2` |
| Rule ID | 100011 (custom) chaining off 5712 (built-in) |
| Rule Level | 12 (High) |
| Rule Description | CRITICAL: SSH brute force attack confirmed — repeated failed login attempts from same source IP (T1110.001) |
| Frequency Threshold | 8 failed attempts within 120 seconds (inherited from built-in Rule 5712) |

### Previous Output — Failed Attempt Chain

The `previous_output` field captured 7 preceding failed attempts, confirming automated rapid-fire brute force:

```
Apr 13 17:02:23 sshd[3450]: Failed password for invalid user fakeuser from 192.168.56.50 port 37742 ssh2
Apr 13 17:02:20 sshd[3451]: Failed password for invalid user fakeuser from 192.168.56.50 port 37748 ssh2
Apr 13 17:02:20 sshd[3453]: Failed password for invalid user fakeuser from 192.168.56.50 port 37766 ssh2
Apr 13 17:02:20 sshd[3452]: Failed password for invalid user fakeuser from 192.168.56.50 port 37752 ssh2
Apr 13 17:02:20 sshd[3450]: Failed password for invalid user fakeuser from 192.168.56.50 port 37742 ssh2
Apr 13 17:02:17 sshd[3450]: Failed password for invalid user fakeuser from 192.168.56.50 port 37742 ssh2
Apr 13 17:02:17 sshd[3452]: Failed password for invalid user fakeuser from 192.168.56.50 port 37752 ssh2
```

**Indicators of automated attack:**
- Multiple different source ports (37742, 37748, 37752, 37766) — parallel connections
- Sub-second intervals between attempts — faster than human typing
- Same username across all attempts — wordlist-driven password spray

---

## Successful Login Check

**Wazuh query:** `agent.id: 002 AND data.srcip: 192.168.56.50 AND rule.groups: authentication_success`

**Result:** No results. Zero successful authentications from the attacker IP. The brute force failed completely — no password in the wordlist matched any account.

---

## Attack Timeline Analysis

**Wazuh query:** `agent.id: 002 AND data.srcip: 192.168.56.50`

| Metric | Value |
|---|---|
| Total alerts from attacker IP | 25 |
| First attempt | Apr 13, 2026 @ 13:01:49.277 |
| Last attempt | Apr 13, 2026 @ 13:02:01.284 |
| Attack duration | ~12 seconds |
| Rules fired | 5710 (individual failures) + 100011 (brute force pattern) |
| Rule 5712 (built-in brute force) | Fired — Rule 100011 chained off it |

**Assessment:** The attack was automated (Hydra) with 4 parallel threads, executing 15 password attempts in approximately 12 seconds. The velocity and parallelism confirm this is a tool-driven attack, not a manual login attempt.

---

## Source IP Analysis

**nslookup 192.168.56.50:**
```
;; Got SERVFAIL reply from 127.0.0.53
** server can't find 50.56.168.192.in-addr.arpa: SERVFAIL
```

**Assessment:** Internal lab IP with no reverse DNS record. In a production environment, this step would include AbuseIPDB reputation check, VirusTotal lookup, geographic location query, and cross-reference against known Tor exit nodes and VPN endpoints. An internal source IP performing brute force would indicate a potentially compromised host conducting lateral movement — higher severity than an external attack.

---

## Compromise Assessment

Comprehensive checks performed on the Ubuntu endpoint via SSH from the Wazuh Manager (not from the attacker machine):

**Login history (`last -10`):**
- No successful logins from 192.168.56.50 at any point in history
- Only legitimate logins from 192.168.56.101 (Manager) and 192.168.56.102 (host)
- System is clean

**User account review (`/etc/passwd`):**
- Three accounts present: `root`, `sync`, `analyst`
- All expected — no rogue accounts created by attacker

**SSH authorized_keys check:**
- `find /home -name "authorized_keys" -mtime -1` returned empty
- No SSH keys planted by attacker

**Process review (`ps aux`):**
- All running processes are legitimate system services and Wazuh agent components
- No suspicious or unknown processes

**Auth.log verification:**
- `sudo grep "192.168.56.50" /var/log/auth.log | tail -10` shows only failed attempts
- Every entry is either "Failed password for invalid user" or "PAM authentication failure"
- Final entry: "Connection closed by invalid user" — Hydra terminated cleanly

**Verdict: System is NOT compromised.** All brute force attempts failed. No persistence mechanisms planted. No unauthorized access achieved.

---

## Verdict & Classification

| Field | Value |
|---|---|
| Classification | True Positive — SSH brute force attack detected correctly |
| Attack Outcome | Failed — no successful authentication |
| System Status | Not compromised |
| Disposition | Closed — attack blocked by authentication controls |
| Containment Recommendation | Block source IP at firewall, update network blocklist, deploy fail2ban |

---

## Containment Actions (Production Recommendations)

1. **Block source IP** — `sudo iptables -A INPUT -s 192.168.56.50 -j DROP` (immediate) and update perimeter firewall rules (permanent)
2. **Deploy fail2ban** — auto-block IPs after configurable failed attempt threshold
3. **Harden SSH configuration:**
   - `PermitRootLogin no`
   - `PasswordAuthentication no` (enforce key-based auth)
   - `MaxAuthTries 3`
4. **Update blocklist** — add source IP to organizational blocklist at firewalls and proxy servers
5. **Monitor for repeat attacks** — watch for the same source IP targeting other systems

---

## Performance Metrics

| Metric | Value |
|---|---|
| Mean Time to Detect (MTTD) | < 3 seconds |
| Mean Time to Investigate (MTTI) | ~15 minutes (full playbook walkthrough including compromise checks) |
| True Positive / False Positive | True Positive |
| Attack outcome | Failed — all attempts blocked |
| Successful login from attacker | None |
| Compromise indicators found | None |
| Playbook followed | PB-002 — all steps completed |

---

## Detection Improvements Identified

1. **Rule 5712 vs Rule 100011 overlap** — Both fire for the same brute force event. Rule 100011 adds elevated severity (Level 12 vs Level 10) and custom MITRE tagging. In production, consider suppressing the built-in 5712 alert when 100011 fires to reduce duplicate noise.

2. **Username enumeration detection** — The current rule detects brute force against a single username. Consider adding a separate rule for attacks that cycle through multiple usernames (username enumeration + password spray), which indicates higher attacker sophistication.

3. **Geographic alerting** — In production, any SSH attempt from outside expected geographic regions should trigger a separate high-severity alert regardless of volume.

---

## Simulation Context

This drill was executed as part of the Home SOC Lab v2.0 Project 2 — Incident Response Playbook + Live Drill. Hydra was used from Kali Linux (192.168.56.50) to simulate a real SSH brute force attack against the Ubuntu SOC Agent (192.168.56.104).

**What was tested:**
- Rule 100011 detection of brute force pattern (chaining off built-in 5712)
- PB-002 triage checklist and investigation workflow
- Successful login verification procedure
- Full compromise assessment on target endpoint
- Multi-source log correlation (Wazuh alerts + auth.log + login history)

**What was validated:**
- Detection latency under 3 seconds for brute force pattern
- `previous_output` field captures the chain of failed attempts — valuable for timeline reconstruction
- Compromise checks confirm clean system state
- Cross-platform detection coverage (Linux log source via auth.log, not just Windows/Sysmon)
- Investigation from Manager SSH (not attacker machine) follows proper operational security
