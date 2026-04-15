# Detection Improvements — Rule Tuning Log

Aggregated detection improvement recommendations identified during all 5 live drills. Each improvement was discovered through real investigation, not theoretical analysis.

---

## New Rules Recommended

### Rule 100012 — IEX/DownloadString Detection (T1059.001)
**Source:** Drill 001
**Gap:** Rule 100001 catches `-EncodedCommand` but misses `IEX (New-Object Net.WebClient).DownloadString()` — an equally common T1059.001 execution method. This gap was originally discovered during Project 1 Phase C when Atomic Red Team Test 1 used DownloadString instead of EncodedCommand.
**Priority:** High — this is a common real-world execution pattern.

### LOLBIN-Specific Rules (certutil, bitsadmin)
**Source:** Drill 005
**Gap:** Rule 100008 detects any executable created in Temp, but dedicated rules for `certutil -urlcache` (network download) and `certutil -decode` (payload extraction) would provide higher-confidence detections specific to known LOLBIN abuse patterns.
**Priority:** Medium — adds specificity to existing broad detection.

### Username Enumeration + Password Spray Detection
**Source:** Drill 002
**Gap:** Rule 100011 detects brute force against a single username. Attacks that cycle through multiple usernames indicate higher sophistication and should trigger a separate, higher-severity alert.
**Priority:** Medium — distinguishes targeted attacks from automated scanning.

### Multi-Log Clearing Detection
**Source:** Drill 004
**Gap:** Rule 100006 detects System log clearing (Event ID 104). Security log clearing (Event ID 1102) and Sysmon log clearing should have separate detections — an attacker clearing all log channels is more dangerous than clearing one.
**Priority:** High — Security log clearing is the highest-severity anti-forensics action.

### File Extension Mismatch Detection
**Source:** Drill 005
**Gap:** The dropped file had a `.exe` extension but contained Base64/certificate text, not a PE binary. A rule detecting extension-content mismatch would catch disguised payloads.
**Priority:** Low — requires more complex detection logic than field-matching rules.

---

## Existing Rule Tuning

### Rule 100008 — PowerShell Script Policy Test Filtering
**Source:** Drills 001, 004
**Issue:** PowerShell creates `__PSScriptPolicyTest_*.ps1` files in Temp every time an encoded command runs. This triggers Rule 100008 alongside the actual attack alert (100001), creating duplicate noise.
**Recommendation:** Add a whitelist exclusion for filenames matching `__PSScriptPolicyTest_*` pattern in Rule 100008 to reduce false positives from legitimate PowerShell activity.

### Rule 100011 — Built-in Rule 5712 Overlap
**Source:** Drill 002
**Issue:** Both built-in Rule 5712 (Level 10) and custom Rule 100011 (Level 12) fire for the same SSH brute force event. This creates duplicate alerts in the dashboard.
**Recommendation:** In production, consider suppressing the built-in 5712 alert when 100011 fires, or adjust Rule 100011 to replace rather than supplement 5712.

### Rule 100004 — Severity Escalation by Path
**Source:** Drill 003
**Issue:** All Run key modifications trigger at Level 10 regardless of the registered executable path. Paths in `C:\Users\Public\`, `%TEMP%`, or `%APPDATA%` are almost never legitimate auto-start locations.
**Recommendation:** Create a Level 12+ variant of Rule 100004 that specifically matches Run key values pointing to known suspicious staging directories.

### Rule 100004 — HKLM vs HKCU Differentiation
**Source:** Drill 003
**Issue:** The current rule matches both HKLM and HKCU Run keys at the same severity. HKLM modifications affect all users and are higher impact.
**Recommendation:** Consider separate rules or severity levels: HKLM modifications at Level 12, HKCU at Level 10.

---

## Architectural Improvements

### Automated Attack Chain Correlation
**Source:** Drill 004
**Finding:** When Rule 100006 (log clearing) fires, the analyst must manually search for preceding alerts from the same agent. This SIEM recovery step should be automated.
**Recommendation:** Implement automated correlation — when 100006 fires, automatically query all custom rule alerts from the same agent in the preceding 60 minutes and surface them in the alert context.

### Attack Chain Scoring
**Source:** Drill 004
**Finding:** When Rules 100005 + 100004 + 100006 fire from the same agent within a short window, the combined severity should be elevated beyond any individual rule. This pattern (create account → persist → clear logs) is a high-confidence indicator of real compromise.
**Recommendation:** Implement composite scoring rules that trigger at Level 15 when multiple attack-stage rules fire from the same agent within a configurable time window.

### Sysmon Event 11 Hash Logging
**Source:** Drill 005
**Finding:** The `hashes` field was not present in the Rule 100008 alert for file creation events. Having the hash at detection time eliminates the need for a separate `Get-FileHash` step during investigation.
**Recommendation:** Verify that the Sysmon configuration (Olaf Hartong modular config) includes hash logging for FileCreate (Event 11) events. Update config if needed.

---

## New Rule Written During This Project

### Rule 100011 — SSH Brute Force Detection (Enhanced)
**Phase:** Phase A
**Chains off:** Built-in Rule 5712
**Level:** 12
**MITRE:** T1110.001

This rule was written specifically for Project 2 to provide SSH brute force detection on the Ubuntu endpoint. It chains off the built-in Wazuh rule 5712 (which handles the frequency counting) and adds elevated severity and custom MITRE tagging. Total custom rule count: 10 → 11.
