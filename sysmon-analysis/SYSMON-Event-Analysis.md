# Sysmon Event Analysis & Threat Detection

**Document Purpose:** Event ID reference and detection use cases for Sysmon telemetry  
**Last Updated:** 2026-02-18  
**Coverage:** Event IDs 1-28  

---

## Sysmon Event 1: Process Creation (CRITICAL for Detection)

**When:** Every time a process is created  
**Captured Data:**
- Parent/Child process relationship
- Command line arguments
- User executing process
- Image path and MD5 hash
- Integrity level

**Detection Use Cases:**

### 1.1 Office Document → PowerShell (Macro Execution)
```
ParentImage: WINWORD.EXE OR EXCEL.EXE OR POWERPNT.EXE
Image: powershell.exe OR cmd.exe
Detection: Macro execution via Office
Real Case: CASE-004 (Emotet malware delivery)
```

### 1.2 System Process with Unusual Child
```
ParentImage: svchost.exe
Image: powershell.exe OR cmd.exe OR whoami.exe
Detection: Privilege escalation attempt
Filter Out: Service-related PowerShell updates
```

### 1.3 Suspicious Rundll32 (Shellcode Execution)
```
Image: rundll32.exe
CommandLine NOT contains: ".dll"
Detection: Shellcode injection (Process Hollowing)
Real Case: SIEM-001 (malware installation)
```

### 1.4 Encoded PowerShell Commands
```
Image: powershell.exe
CommandLine contains: "-enc" OR "-EncodedCommand"
Detection: Obfuscated malware
Splunk SPL:
  index=sysmon EventCode=1 Image="*powershell.exe"
  | where match(CommandLine, "(?i)(-enc|-encodedcommand)")
  | table Computer, User, CommandLine
```

---

## Sysmon Event 3: Network Connection (Detect C2 & Exfiltration)

**When:** Process initiates network connection  
**Captured Data:**
- Source/destination IP and port
- Protocol (TCP, UDP)
- Process initiating connection
- Source and destination ports
- Bytes sent/received

**Detection Use Cases:**

### 3.1 Unexpected Outbound HTTPS
```
SourcePort: > 1024 (ephemeral)
DestinationPort: 443
Image: NOT browser
Detection: Potential C2 or exfiltration
Real Case: NET-2026-003 (Cobalt Strike C2)
  - 10.0.50.15 → 185.220.101.45:443
  - Interval: 60 seconds (beacon pattern)
```

### 3.2 DNS Tunneling Detection
```
DestinationPort: 53
Image: NOT svchost.exe OR nslookup.exe
QueryName length: > 100
Detection: Potential data exfiltration via DNS
Splunk:
  index=sysmon EventCode=3 DestinationPort=53
  | where Image NOT IN ("svchost.exe", "nslookup.exe")
  | stats count by Computer, Image, DestinationIp
```

---

## Sysmon Event 8: CreateRemoteThread (Process Injection Detection)

**When:** Process creates thread in another process  
**Captured Data:**
- Source process (injecting)
- Target process (being injected)
- Thread ID
- API name (usually NtCreateThreadEx)

**Detection Use Cases:**

### 8.1 Malware Injection into LSASS
```
TargetImage: C:\Windows\System32\lsass.exe
SourceImage: powershell.exe OR cmd.exe OR unknown
Detection: Credential dumping attempt
Real Case: CASE-005 (credential theft)
Splunk:
  index=sysmon EventCode=8 TargetImage="*lsass.exe"
  | stats count by SourceImage, Computer
  | where count >= 1
```

### 8.2 Process Hollowing Detection
```
SourceImage: Any process
TargetImage: svchost.exe OR explorer.exe OR legitimate_service
Detection: Process replacement/hollowing
Alert: If SourceImage is suspicious (rundll32, cmd, powershell)
```

---

## Sysmon Event 10: ProcessAccess (LSASS Protection)

**When:** Process accesses another process memory  
**Captured Data:**
- Source/target process
- Access mask (read, write, execute)
- Granted access rights

**Detection Use Cases:**

### 10.1 LSASS Memory Access (Credential Dumping)
```
TargetImage: C:\Windows\System32\lsass.exe
GrantedAccess: 0x1fffff (full access) OR 0x1010 (read)
SourceImage NOT IN: taskmgr.exe, svchost.exe, csrss.exe
Detection: Mimikatz or credential dumping tool
Alert Severity: CRITICAL
Real Case: CASE-005 (credential dumping)

Splunk Query:
  index=sysmon EventCode=10 TargetImage="*lsass.exe"
  | where SourceImage NOT IN ("taskmgr.exe", "svchost.exe")
  | eval risk_score=100
  | search risk_score > 0
```

---

## Sysmon Event 11: FileCreate (Malware Detection)

**When:** File is created or first written to  
**Captured Data:**
- File path
- File name
- Process creating file
- Hash of file

**Detection Use Cases:**

### 11.1 Executable Creation in Temp Directory
```
TargetFilename: C:\Windows\Temp\*.exe OR C:\Users\*\AppData\*.exe
Detection: Malware staging (executables shouldn't be in Temp)
Real Case: SIEM-001 (malware in C:\Windows\Temp\updates.exe)
Risk Score: 90 (executables in user-writable locations)
```

### 11.2 File Creation Rate Spike (Ransomware)
```
ParentImage: powershell.exe OR cmd.exe OR unknown
TargetFilename contains: common_data_extensions
Events per minute: > 100
Detection: Potential ransomware encryption
Real Case: CASE-002 (Hive ransomware created 50K files in 97 min)

Splunk:
  index=sysmon EventCode=11
  | stats count as file_count by Computer, ParentImage
  | where file_count > 1000
  | eval risk_score=file_count/10
```

---

## Sysmon Event 12/13/14: Registry Events (Persistence Detection)

**Event 12:** Registry key created or deleted  
**Event 13:** Registry value set  
**Event 14:** Registry object renamed  

**Detection Use Cases:**

### 13.1 Run Key Persistence
```
EventCode: 13
TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\Run
OR
TargetObject: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Details: *.exe
Detection: Malware persistence mechanism
Real Case: SIEM-001 (malware added Run key "Windows Update Service")

Splunk:
  index=sysmon EventCode=13
  | where TargetObject="*CurrentVersion\\Run*"
  | where Details contains ".exe" OR Details contains ".dll"
  | stats count by Computer, User, TargetObject
```

### 13.2 Disable Windows Defender
```
EventCode: 13
TargetObject: HKLM\Software\Policies\Microsoft\Windows Defender*
Details: 0 (disabled) OR "DisableRealtimeMonitoring"
Detection: Ransomware disabling AV
Real Case: CASE-002 (Hive ransomware disabled Defender)
Alert: CRITICAL
```

---

## Sysmon Event 22: DNS Query (C2 & Phishing Detection)

**When:** DNS query is made  
**Captured Data:**
- Source IP
- Query name (domain)
- Query result (A record result)
- Query status (success/failure)

**Detection Use Cases:**

### 22.1 DNS Query to Suspicious Domain
```
QueryName: Matches threat intelligence list
Detection: C2 communication attempt
Real Case: NET-2026-003 (DNS query for C2 domain)
Splunk:
  index=sysmon EventCode=22
  | where QueryName IN (
      "185.220.101.45", 
      "malicious-domain.com",
      "phish-site.net"
    )
  | stats count by Computer, User
  | where count >= 1
```

### 22.2 DGA (Domain Generation Algorithm) Detection
```
QueryName: Unusual character patterns
QueryResult: NXDOMAIN (no DNS response)
Alert: If >100 failed queries to random-looking domains
Detection: Botnet C2 communication via DGA
```

---

## Detection Rules Summary

| Event ID | Primary Use | Critical Indicator | Risk Level |
|----------|------------|-------------------|-----------|
| 1 | Process execution | Child of Office → PowerShell | HIGH |
| 3 | Network connection | Outbound to unknown IP:443 | HIGH |
| 8 | Process injection | Injection into lsass.exe | CRITICAL |
| 10 | Memory access | LSASS access with 0x1fffff | CRITICAL |
| 11 | File creation | .exe in Temp directory | HIGH |
| 12/13 | Registry persistence | Run key created | HIGH |
| 22 | DNS query | Query to C2 domain | HIGH |

---

## Real Investigation Examples

**SIEM-001 (Brute Force Detection):**
- Event 1: PowerShell execution detected
- Event 11: Malware file created in Temp
- Event 13: Registry Run key created
- Event 3: Outbound to C2 server

**CASE-002 (Ransomware):**
- Event 1: Process creation by service account
- Event 11: 50K file creations in 97 minutes (spike alert)
- Event 13: Windows Defender disabled
- Event 13: Registry modified to disable recovery

**CASE-005 (Credential Dumping):**
- Event 8: CreateRemoteThread into lsass.exe
- Event 10: LSASS memory access with suspicious rights
- Event 3: Exfiltration to C2 server

---

## Sysmon Configuration Best Practices

**Tuning for SOC:**
- Log all Event 1 (process creation)
- Log all Event 3 from critical systems
- Log all Event 8, 10 (process injection)
- Log all Event 11, 12, 13, 14 (file/registry changes)
- Filter out known good tools (Microsoft Update, AV updates)
- Reduce noise by excluding system processes

---

*Sysmon telemetry is the most valuable source for endpoint detection. Ensure it's deployed, properly tuned, and forwarded to SIEM immediately.*
