# EDR (Endpoint Detection and Response) Alert Response

**Version:** 1.2  
**Last Updated:** 2026-02-19  
**Classification:** Internal Use

---

## EDR Alert Types & Response

### Alert 1: Suspicious Process Execution

```
ALERT: Suspicious Process Tree
├─ Parent: WINWORD.EXE (Microsoft Word)
├─ Child: powershell.exe (PowerShell)
└─ Command: powershell.exe -nop -w hidden -enc JABzAD0...

ANALYSIS:
├─ Office → PowerShell = Classic exploitation pattern
├─ Hidden window = Attacker evasion
├─ Encoded command = Obfuscated payload
└─ Verdict: LIKELY MALWARE (macro exploitation)

RESPONSE:
├─ IMMEDIATE: Kill powershell.exe process
├─ IMMEDIATE: Isolate endpoint from network
├─ IMMEDIATE: Preserve memory dump
├─ ALERT: Escalate to incident response
└─ INVESTIGATE: Check for lateral movement
```

### Alert 2: Malware Detection

```
ALERT: Known Malware Detected
├─ File: C:\Users\john.smith\Downloads\invoice.exe
├─ Hash: a1b2c3d4e5f6g7h8i9j0
├─ Verdict: Emotet Banking Trojan (100% confidence)
└─ Action: EDR can auto-quarantine

RESPONSE:
├─ IMMEDIATE: Quarantine file
├─ IMMEDIATE: Isolate endpoint
├─ IMMEDIATE: Kill process if running
├─ INVESTIGATE: How did it get there?
├─ SCAN: Full system antivirus scan
└─ ESCALATE: Security incident
```

### Alert 3: C2 Communication Blocked

```
ALERT: Command & Control Connection Blocked
├─ Process: explorer.exe
├─ Destination: 203.0.113.42:8080
├─ Verdict: Known C2 server (threat intelligence match)
├─ Action: EDR blocked connection

RESPONSE:
├─ CRITICAL: System likely infected
├─ IMMEDIATE: Isolate endpoint
├─ IMMEDIATE: Collect forensic image
├─ THREAT LEVEL: CRITICAL
├─ RESPONSE: Full incident response activation
└─ TIMELINE: Prepare for ransomware encryption within hours
```

---

## EDR Response Playbook

```
ALERT RECEIVED
│
├─ Is alert real? (Not false positive?)
│  ├─ YES → Continue to assessment
│  └─ NO → Close, tune rule
│
├─ Severity assessment
│  ├─ CRITICAL (malware, C2) → IMMEDIATE response
│  ├─ HIGH (suspicious process) → Response within 1 hour
│  └─ MEDIUM (suspicious behavior) → Response within 4 hours
│
├─ Isolate endpoint? 
│  ├─ YES → Disconnect from network (if CRITICAL)
│  └─ NO → Monitor closely
│
├─ Preserve evidence
│  ├─ Memory dump
│  ├─ Process list
│  └─ Network connections
│
├─ Kill malicious process?
│  ├─ YES → Terminate (if safe)
│  └─ NO → Monitor
│
└─ Escalate to IR team
   ├─ Incident ticket created
   ├─ Team activated
   └─ Investigation begins
```

---

## References

- CrowdStrike Falcon EDR Documentation
- Sentinel One EDR Platform
- Carbon Black EDR Response Guide

---

*Document Maintenance:*
- Update alert rules monthly
- Review EDR effectiveness quarterly
- Test response procedures every month
