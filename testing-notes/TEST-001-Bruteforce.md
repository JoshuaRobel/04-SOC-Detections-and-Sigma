# TEST-001 — Excessive Failed Logons

## Objective
Validate Sigma rule detects burst of Event ID 4625 entries.

## Testing Method
- Simulated multiple failed logons
- Generated 30 failed authentication attempts within 3 minutes
- Verified detection triggered

## SPL Equivalent Query

index=wineventlog EventCode=4625
| stats count by TargetUserName
| where count > 20

## Result
Detection successfully triggered.

## Tuning Notes
- Threshold adjusted to 20 to reduce noise
- Added exclusion for known vulnerability scanner IP
