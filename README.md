# 04 — SOC Detections & Sigma
## Detection Engineering Simulation (Sigma + Splunk)

This repository demonstrates enterprise detection engineering practices using Sigma rules aligned with MITRE ATT&CK.

Each detection includes:

- Sigma rule logic
- ATT&CK technique mapping
- False positive considerations
- Tuning strategy
- SPL conversion for Splunk
- Testing and validation notes

---

# 🎯 Objectives

- Demonstrate understanding of rule-based detection
- Show ability to reduce false positives
- Map detections to MITRE ATT&CK
- Translate Sigma logic into Splunk SPL
- Document testing and validation process

---

# 🔎 Detection Index

| ID | Detection | ATT&CK | Status |
|----|----------|--------|--------|
| SIGMA-001 | Excessive Failed Logons | T1110 | Validated |
| SIGMA-002 | Encoded PowerShell Execution | T1059 | Validated |
| SIGMA-003 | Domain Admin Group Addition | T1078 | Validated |

---

# 🧠 Skills Demonstrated

- Detection rule development
- ATT&CK mapping
- Enterprise alert tuning
- SOC alert lifecycle awareness
- SPL query validation
