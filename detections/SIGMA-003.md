# SIGMA-003: Domain Admin Group Addition

**Detection ID:** SIGMA-003  
**MITRE ATT&CK:** T1098 — Account Manipulation  
**Data Source:** Windows Security Event Log (Event ID 4728, 4732)  
**Severity:** High  
**Status:** ✅ Production

---

## Detection Logic

### Sigma Rule
```yaml
title: Privileged Group Modification — Domain Admins
description: Detects additions to Domain Admins or other privileged groups
status: stable
logsource:
  product: windows
  service: security
detection:
  selection_event:
    EventID:
      - 4728  # Member added to global group
      - 4732  # Member added to local group
  selection_group:
    TargetUserName:
      - 'Domain Admins'
      - 'Enterprise Admins'
      - 'Schema Admins'
      - 'Administrators'
      - 'Account Operators'
  condition: selection_event and selection_group
falsepositives:
  - Legitimate IT provisioning
  - Service account onboarding
level: high
tags:
  - attack.t1098
  - attack.persistence
  - attack.privilege_escalation
```

### Splunk SPL Conversion
```spl
index=wineventlog source="WinEventLog:Security" EventCode IN (4728, 4732)
| where TargetUserName IN ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators")
| eval severity="high"
| table _time, ComputerName, SubjectUserName, TargetUserName, MemberName, TargetDomainName
| rename SubjectUserName as "Added By", TargetUserName as "Group", MemberName as "New Member"
```

---

## Critical Context

This detection fires on **ANY** privileged group modification. Context determines if it's an attack:

| Context | Assessment |
|---------|------------|
| Added by IT service account during business hours | Likely legitimate |
| Added by user account to Domain Admins | **CRITICAL** — escalate immediately |
| Added outside change window | Suspicious — verify with IT |
| New account added (created same day) | High risk — possible backdoor |

---

## Response Playbook

**Immediate Actions (within 5 minutes):**
1. Verify with Change Management — approved change ticket?
2. If NO ticket → **CRITICAL ESCALATION**
3. Check if "Added By" user is authorized for privilege management
4. Check if "New Member" account is legitimate

**Investigation Steps:**
- Who created the new member account? (Event ID 4720)
- When was the account created? (if new)
- Has the new account logged in? (Event ID 4624)
- What did the "Added By" user do before/after? (correlate activity)

---

## Tuning: Approved Change Windows

To reduce FPs, correlate with ServiceNow change tickets:

```spl
index=wineventlog EventCode IN (4728, 4732) TargetUserName="Domain Admins"
| eval change_ticket=if(match(SubjectUserName, "svc_provision"), "AUTO-APPROVED", "MANUAL_REVIEW")
| where change_ticket="MANUAL_REVIEW"
```

**FP Rate:** ~5% with change management correlation

---

## Real Alert Example

**Alert Details:**
- **Time:** 2026-02-05 03:17:42 UTC (after hours)
- **Group:** Domain Admins
- **New Member:** jservice (new account, created 03:15 UTC)
- **Added By:** administrator (legitimate admin account)

**Investigation:**
- Account `jservice` created 2 minutes before group addition
- No change ticket found
- Admin user `administrator` had suspicious login from VPN IP 45.77.123.45 (unusual location)
- **Result:** Compromised admin account creating backdoor. Account disabled, incident escalated.

---

## Detection Gap Analysis

| Gap | Risk | Mitigation |
|-----|------|------------|
| Local admin group changes (Event 4732) | Medium | Included in detection |
| Nested group membership | Medium | Monthly audit script |
| Direct ACL modifications | High | Separate detection needed |

---

**Created:** 2026-01-25  
**Last Modified:** 2026-02-05  
**Analyst:** Joshua Robel
