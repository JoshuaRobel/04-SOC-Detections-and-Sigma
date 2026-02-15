# SIGMA-001: Excessive Failed Logons

**Detection ID:** SIGMA-001  
**MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing  
**Data Source:** Windows Security Event Log (Event ID 4625)  
**Severity:** Medium  
**Status:** ✅ Production

---

## Detection Logic

### Sigma Rule
```yaml
title: Excessive Failed Logon Attempts
status: stable
description: Detects multiple failed logon attempts in short timeframe (possible brute force)
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    LogonType:
      - 2  # Interactive
      - 10 # RemoteInteractive (RDP)
  timeframe: 5m
  condition: selection | count() by TargetUserName > 5
falsepositives:
  - Forgotten passwords (legitimate users)
  - Service accounts with expired credentials
  - Penetration testing
level: medium
tags:
  - attack.t1110.001
  - attack.credential_access
```

### Splunk SPL Conversion
```spl
index=wineventlog source="WinEventLog:Security" EventCode=4625 LogonType IN (2, 10)
| bin _time span=5m
| stats count by _time, TargetUserName, ComputerName, src_ip
| where count > 5
| eval severity="medium"
| table _time, TargetUserName, count, ComputerName, src_ip
```

---

## Tuning Notes

| Parameter | Original | Tuned | Rationale |
|-----------|----------|-------|-----------|
| Threshold | >3 attempts | >5 attempts | Reduced FPs from typo passwords |
| Timeframe | 1 minute | 5 minutes | Better pattern recognition |
| LogonType | All | 2, 10 only | Focus on interactive/RDP attacks |

**False Positive Rate:** ~2% after tuning (down from 15%)

---

## Investigation Guidance

When this alert fires:

1. **Check source IP** — Single IP = brute force; Multiple IPs = possible spray
2. **Check target accounts** — Generic accounts (admin, guest) = attack; Named user = possible legit
3. **Check timing** — Business hours = possible FP; Off-hours = suspicious
4. **Correlate successes** — Any Event ID 4624 after 4625 = possible success

**Escalate if:**
- Same IP targeting multiple accounts
- Success followed by rapid lateral movement
- Privileged account targeted

---

## Testing Results

| Test Case | Expected | Result | Status |
|-----------|----------|--------|--------|
| 10 failed logons from single IP | Alert | ✅ Alerted | Pass |
| 3 failed logons from single IP | No alert | ✅ Silent | Pass |
| Failed logon from service account | Alert | ✅ Alerted | Pass |
| Legitimate user (1 failure) | No alert | ✅ Silent | Pass |

---

## Related Detections

- **SIGMA-003** — Domain Admin Group Addition (post-exploitation)
- **SIGMA-007** — Successful Logon After Brute Force (correlation)

---

**Created:** 2026-01-15  
**Last Modified:** 2026-02-10  
**Analyst:** Joshua Robel
