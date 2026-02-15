# 04 — SOC Detections & Sigma Rules

**Detection Engineering Repository**

This repository contains production-ready Sigma rules mapped to MITRE ATT&CK, with testing notes, tuning guidance, and Splunk SPL conversions.

---

## Detection Index

| ID | Detection | ATT&CK | Data Source | Status |
|----|-----------|--------|-------------|--------|
| [SIGMA-001](./detections/SIGMA-001.md) | Excessive Failed Logons | T1110.001 | Windows Security Log | ✅ Validated |
| [SIGMA-002](./detections/SIGMA-002.md) | Encoded PowerShell Execution | T1059.001 | Windows Sysmon | ✅ Validated |
| [SIGMA-003](./detections/SIGMA-003.md) | Domain Admin Group Addition | T1098 | Windows Security Log | ✅ Validated |
| [SIGMA-004](./detections/SIGMA-004.md) | Suspicious LSASS Access | T1003.001 | Windows Sysmon | 🚧 Testing |
| [SIGMA-005](./detections/SIGMA-005.md) | WMI Event Subscription | T1546.003 | Windows Sysmon | 🚧 Testing |

---

## Repository Structure

```
04-SOC-Detections-and-Sigma/
├── detections/           # Individual detection docs
│   ├── SIGMA-001.md
│   ├── SIGMA-002.md
│   └── ...
├── sigma-rules/          # Raw .yml files
│   ├── excessive_failed_logons.yml
│   ├── encoded_powershell.yml
│   └── ...
├── testing-notes/        # Validation results
│   ├── SIGMA-001-testing.md
│   └── ...
└── README.md            # This file
```

---

## Skills Demonstrated

- Detection rule development (Sigma format)
- MITRE ATT&CK technique mapping
- Log source identification
- False positive management
- SPL query translation
- Alert tuning and threshold optimization

---

## Quick Reference: Sigma to Splunk

| Sigma Field | Splunk Equivalent |
|-------------|-------------------|
| `logsource` | `sourcetype` or `source` |
| `selection` | `where` clause |
| `keywords` | `search` terms |
| `condition` | Boolean logic |

---

## Testing Methodology

Each detection includes:
1. **Baseline period** (7 days) — understand normal
2. **Test deployment** — alert-only mode
3. **FP analysis** — tune thresholds
4. **Production** — enforce with playbook

---

**Analyst:** Joshua Robel  
**Last Updated:** 2026-02-15
