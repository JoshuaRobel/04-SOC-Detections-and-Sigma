# Endpoint Security Monitoring

Windows and endpoint telemetry analysis for threat detection and investigation.

## Windows Event Logs

Security, System, and Application log analysis for threat hunting and incident response.

### Critical Event IDs

**Authentication Events:**
| Event ID | Description | Detection Use Case |
|----------|-------------|-------------------|
| 4624 | Successful logon | Account usage validation |
| 4625 | Failed logon | Brute force detection |
| 4634 | Account logoff | Session tracking |
| 4648 | Explicit credential logon | Lateral movement |
| 4672 | Special privileges assigned | Privilege escalation |
| 4768 | Kerberos TGT requested | Golden ticket detection |
| 4769 | Kerberos service ticket | Pass-the-ticket |

**Process Execution:**
| Event ID | Description | Detection Use Case |
|----------|-------------|-------------------|
| 4688 | Process created | Malware execution |
| 4689 | Process terminated | Process chain analysis |
| 4656 | Object access | Sensitive file access |
| 4663 | Attempt to access object | Data staging detection |

**Account Management:**
| Event ID | Description | Detection Use Case |
|----------|-------------|-------------------|
| 4720 | User account created | Rogue account detection |
| 4726 | User account deleted | Cleanup activity |
| 4728 | Member added to global group | Privilege escalation |
| 4732 | Member added to local group | Admin rights abuse |
| 4738 | User account changed | Account tampering |

### Sysmon Analysis

Advanced endpoint telemetry for detailed process and network monitoring.

**Key Event Types:**
- Event ID 1: Process creation (command line logging)
- Event ID 3: Network connection
- Event ID 7: Image loaded (DLL loading)
- Event ID 8: CreateRemoteThread (injection)
- Event ID 10: ProcessAccess (LSASS access)
- Event ID 11: FileCreate
- Event ID 12/13/14: Registry events
- Event ID 15: FileCreateStreamHash (alternate data streams)

**Detection Patterns:**
```
Parent-Child Analysis:
- office_product → powershell.exe (macro execution)
- wscript.exe → powershell.exe (script chaining)
- rundll32.exe → no DLL argument (shellcode execution)
- svchost.exe → unusual child (service impersonation)

LSASS Access Detection:
- Process accessing lsass.exe with specific access rights
- Common tools: Mimikatz, Procdump, Task Manager, AV
- Filter: Exclude known good processes
```

## EDR Alerts

Endpoint Detection and Response platform alert triage.

**Common Alert Types:**
| Alert | Severity | Typical Cause |
|-------|----------|---------------|
| Malware detected | High | Signature match on known malware |
| Suspicious script | Medium | Obfuscated PowerShell, encoded commands |
| Credential theft | Critical | LSASS access, SAM dump |
| Lateral movement | High | PsExec, WMI, RDP to multiple hosts |
| Persistence created | Medium | Registry run keys, scheduled tasks |
| Suspicious injection | High | Process hollowing, APC injection |

**Triage Process:**
1. Validate alert — true positive vs false positive
2. Gather context — user, time, process tree
3. Check prevalence — single host vs widespread
4. Correlate with other alerts
5. Determine containment needs

## Endpoint Investigations

Structured investigation workflows for endpoint-centric incidents.

**Investigation Types:**
- Malware infection and containment
- Insider threat detection
- Privilege escalation analysis
- Lateral movement tracing
- Data exfiltration detection

**Data Sources:**
- Windows Event Logs
- Sysmon telemetry
- EDR logs
- Prefetch files
- ShimCache/AppCompatCache
- AmCache.hve
- RecentFileCache.bcf
- Registry hives

## Key Skills

- **Process Analysis:** Parent-child relationships, command line inspection
- **Memory Forensics:** Basic concepts and indicators
- **Persistence Detection:** Registry, scheduled tasks, services, WMI events
- **Credential Access:** LSASS access detection, SAM/database extraction
- **Defence Evasion:** Injection techniques, process hollowing, masquerading

## Artifacts of Interest

| Artifact | Location | Investigative Value |
|----------|----------|---------------------|
| Prefetch | C:\Windows\Prefetch | Program execution history |
| ShimCache | SYSTEM registry | Program execution evidence |
| AmCache | C:\Windows\appcompat\Programs | Installation artifacts |
| RecentFiles | NTUSER.DAT | User file access |
| Jump Lists | AppData\Roaming\Microsoft\Windows\Recent | Application usage |
| Browser History | Various | Web activity, C2 evidence |
| Event Logs | C:\Windows\System32\winevt\Logs | System activity |

---

*Endpoints are where attacks execute. Understanding endpoint telemetry is essential for detection and response.*
