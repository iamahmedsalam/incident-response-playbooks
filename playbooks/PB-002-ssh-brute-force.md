# PB-002 — SSH Brute Force Attack

## Alert Overview

| Field | Value |
|---|---|
| **Playbook ID** | PB-002 |
| **MITRE ATT&CK** | T1110.001 — Brute Force: Password Guessing |
| **Wazuh Rule** | 100011 (Level 12 — High), chains off built-in 5712 (Level 10) |
| **Log Source** | auth.log (SSH authentication events) |
| **Platform** | Linux |
| **Agent** | ubuntu-soc-agent (Agent 002 — 192.168.56.104) |

**What the analyst sees:** An alert fires for Rule 100011 indicating multiple failed SSH login attempts from the same source IP within a short time window. The built-in Rule 5712 detected the brute force pattern (8+ failures in 120 seconds), and Rule 100011 escalated it as a confirmed attack.

**Why this matters:** SSH brute force is the most common attack against any internet-facing Linux system. Automated tools like Hydra, Medusa, and Ncrack can attempt thousands of passwords per minute. Every SOC analyst must be able to identify, investigate, and contain this attack pattern.

---

## Triage Checklist

**Step 1 — Identify the source IP**
- Check `data.srcip` — where is the attack coming from?
- Is it an internal IP (lab/corporate network) or external?
- Internal source = potentially compromised host performing lateral movement — **higher severity**
- External source = internet-facing brute force — common but still requires response

**Step 2 — Check the target username**
- `data.srcuser` — what username is being attacked?
- `root` = most common automated target
- Valid username = attacker may have performed prior reconnaissance — **higher severity**
- Non-existent username = likely automated scan with default wordlists — lower sophistication

**Step 3 — Check if any attempt succeeded**
- In Wazuh dashboard, search for successful authentication from the same source IP:
  ```
  agent.id: 002 AND data.srcip: <attacker_IP> AND rule.groups: authentication_success
  ```
- If ANY successful login exists → **Escalate immediately** — the attacker is inside

**Step 4 — Check the volume and velocity**
- How many failed attempts? Check `rule.firedtimes` on Rule 5710 alerts
- Over what time period?
- High volume (100+) in seconds = automated tool (Hydra, Medusa)
- Low volume (10-20) over hours = slow-and-low brute force attempting to evade detection

**Decision:** If any login succeeded → immediate escalation. If all attempts failed → proceed to investigation to assess risk and implement blocking.

---

## Investigation Procedure

### Extract Key Artifacts from the Alert

| Artifact | Wazuh Field | What to Record |
|---|---|---|
| Timestamp | `timestamp` | When the brute force was detected |
| Source IP | `data.srcip` | Attacker's IP address |
| Target username | `data.srcuser` | Account being attacked |
| Agent name | `agent.name` | Target system |
| Full log entry | `full_log` | Raw SSH log line |
| Previous output | `previous_output` | Earlier failed attempts in the same chain |
| Built-in rule | `rule.id: 5712` | Confirms brute force pattern |
| Custom rule | `rule.id: 100011` | Confirmed escalated detection |

### Analyse the Source IP

**On the Wazuh Manager or any Linux machine:**
```bash
# Reverse DNS lookup
nslookup <attacker_IP>

# Geolocation (if external IP)
curl -s "http://ip-api.com/json/<attacker_IP>" | python3 -m json.tool
```

**In production, also check:**
- AbuseIPDB — has this IP been reported for abuse?
- VirusTotal — is this IP associated with known malware?
- Internal threat intel — is this IP in any blocklist?
- Is this IP a known Tor exit node or VPN endpoint?

### Review Full Attack Timeline

In Wazuh dashboard, search for all events from the attacking IP:
```
agent.id: 002 AND data.srcip: <attacker_IP>
```

Sort by timestamp (oldest first). Document:
- When did the first attempt occur?
- When did the last attempt occur?
- Total number of attempts
- Were multiple usernames tried? (indicates username enumeration + brute force)
- Time between attempts (reveals whether attack is automated)

### Check for Successful Login After Brute Force

This is the most critical check:
```
agent.id: 002 AND data.srcip: <attacker_IP> AND (rule.id: 5715 OR rule.groups: authentication_success)
```

If any result appears → the attacker gained access. Skip directly to Containment.

### Check Target System for Compromise Indicators

**SSH into the Ubuntu agent (only if no successful login from attacker was found):**
```bash
# Check for new or modified user accounts
cat /etc/passwd | grep -v nologin | grep -v false

# Check for recently modified SSH authorized_keys
find /home -name "authorized_keys" -mtime -1

# Check for suspicious running processes
ps aux | grep -v '\[' | sort -k3 -rn | head -20

# Check for recent cron jobs added
for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null; done

# Check last successful logins
last -10
```

---

## Containment & Response

**If brute force failed (no successful login):**

1. **Block the source IP** on the target system:
   ```bash
   sudo iptables -A INPUT -s <attacker_IP> -j DROP
   ```

2. **Consider fail2ban** — in production, install and configure fail2ban to auto-block IPs after failed attempts:
   ```bash
   sudo apt install fail2ban -y
   ```

3. **Verify SSH hardening:**
   ```bash
   # Check current SSH config
   sudo grep -E "^(PermitRootLogin|PasswordAuthentication|MaxAuthTries)" /etc/ssh/sshd_config
   ```
   Recommended production settings:
   - `PermitRootLogin no`
   - `PasswordAuthentication no` (use key-based auth only)
   - `MaxAuthTries 3`

4. **Document and close** — record all findings, IP blocked, alert classified as True Positive (attack detected, no compromise).

**If brute force succeeded (attacker logged in):**

1. **Isolate the endpoint immediately** — disconnect from network
2. **Capture evidence** — memory dump, auth logs, process listing, cron jobs, authorized_keys
3. **Reset all credentials** — change passwords for all accounts on the system
4. **Check for persistence** — SSH keys, cron jobs, systemd services, modified binaries
5. **Check for lateral movement** — did the attacker SSH from this system to others?
6. **Escalate to Tier 2 / IR team** with full timeline and evidence

---

## Evidence Collection

| Evidence Item | Source | Format |
|---|---|---|
| Wazuh alert for Rule 100011 (full JSON) | Dashboard export | JSON |
| Wazuh alert for Rule 5712 (full JSON) | Dashboard export | JSON |
| All Rule 5710 individual failure alerts | Dashboard filtered export | JSON |
| Source IP reputation check | AbuseIPDB / VirusTotal | Screenshot |
| auth.log relevant entries | `sudo grep <attacker_IP> /var/log/auth.log` | Text |
| Timeline of all attempts | Wazuh dashboard sorted by timestamp | Screenshot |
| Successful login check results | Dashboard search results | Screenshot |
| SSH config review | `sshd_config` contents | Text |

---

## Post-Incident

**Detection tuning recommendations:**
- Current threshold: 8 failures in 120 seconds. Consider lowering to 5 in 60 seconds for higher-sensitivity environments
- Consider adding a separate rule for brute force against **valid** usernames (chain off Rule 5710 equivalent for valid users — Rule 5716 or similar)
- Add geographic alerting — if your environment is US-only, any SSH attempt from outside the US is suspicious regardless of volume

**Hardening recommendations:**
- Deploy fail2ban on all Linux endpoints
- Disable password authentication in favour of SSH key-based auth
- Restrict SSH access to specific source IPs where possible
- Move SSH to a non-standard port (reduces automated scan volume, doesn't replace other controls)

**Metrics to record:**
- Total attack duration
- Number of unique usernames attempted
- Whether attack was automated (tool signature) or manual
- Time from detection to containment (MTTR)
- True positive confirmation
