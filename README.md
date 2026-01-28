# 04 — SOC Detections and Sigma (Detection Engineering)

> **Goal:** Build SOC Level 1 job-ready evidence — alert triage, investigation, documentation, and escalation decisions.

## What this repo shows
- Practical SOC workflow (monitor → triage → investigate → enrich → document → escalate/close)
- Repeatable templates/playbooks
- Evidence artifacts (screenshots, logs, queries, timelines)

## Quick links
- 📁 Investigations: `./investigations/`
- 🧭 Playbooks: `./playbooks/`
- 🧾 IOC Lists: `./iocs/`

## Scope
- Build and document Sigma rules aligned to SOC detection needs
- Map each rule to MITRE ATT&CK
- Provide: required log sources, expected false positives, and tuning notes
- Include investigation guidance for analysts

## Rule format (per rule)
Each rule should include:
- Purpose + threat description
- Required telemetry
- ATT&CK mapping
- Example triggering event (or test log)
- Common false positives
- Tuning ideas
- Investigation steps

## Folder guide
- `./rules/` → Sigma rules
- `./samples/` → example events/log snippets
- `./investigation-guides/` → “what to do when it fires”

