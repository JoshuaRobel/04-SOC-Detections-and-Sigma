# Windows Event Log Analysis for SOC

**Version:** 1.7  
**Last Updated:** 2026-02-19  
**Classification:** Internal Use

---

## Windows Event Log Fundamentals

Windows Event Logs are critical for detecting security incidents. SOC analysts must understand key event IDs and their implications.

---

## Critical Security Event IDs

### Authentication Events

```
EVENT 4624: Successful Logon
├─ When: User/service successfully authenticates
├─ Key fields:
│  ├─ TargetUserName: Who logged in
│  ├─ LogonType: How they logged in (3=Network, 10=RDP)
│  ├─ WorkstationName: From which computer
│  ├─ SourceIPAddress: From which IP
│  └─ TargetUserName: Account used
├─ Normal: Business hours, expected users/systems
├─ Suspicious: Off-hours, service account, unknown IP
└─ Hunting: Look for failed logon (4625) followed by success

EVENT 4625: Failed Logon Attempt
├─ When: User/service fails to authenticate
├─ Key fields:
│  ├─ TargetUserName: Attempted account
│  ├─ FailureReason: Why it failed
│  ├─ FailureCode: 0xC000006D (unknown username)
│  │                0xC000006E (wrong password)
│  │                0xC0000234 (account locked)
│  ├─ SourceIPAddress: Attack source
│  └─ WorkstationName: Attack origination
├─ Alert trigger: >10 in 15 minutes = brute force
├─ Normal baseline: <5 per day per account
└─ Hunting: Identify attacker IP, blocked account

EVENT 4648: Logon with Explicit Credentials
├─ When: User/service used explicit credentials (RunAs)
├─ Example: "runas /user:domain\\admin cmd.exe"
├─ Key fields:
│  ├─ SubjectUserName: Who initiated (current user)
│  ├─ AccountNameWhoseCredentialsWereUsed: Target account
│  └─ SourceIPAddress: From which system
├─ Normal: Admins running commands as different account
├─ Suspicious: Off-hours, non-admin running as admin
└─ Hunting: Find lateral movement using stolen credentials

EVENT 4720: User Account Created
├─ When: New user account created
├─ Key fields:
│  ├─ TargetUserName: New account name
│  ├─ TargetDomainName: Which domain
│  └─ CallerUserName: Who created it
├─ Normal: IT creates accounts (during business hours)
├─ Suspicious: After-hours creation, attacker-created
└─ Hunting: Look for unauthorized account creation + usage
```

### Privilege & Group Changes

```
EVENT 4728: Group Member Added
├─ When: User added to security group
├─ Alert on: User added to "Domain Admins"
├─ Key fields:
│  ├─ TargetGroupName: Which group
│  ├─ MemberName: Who was added
│  └─ CallerUserName: Who added them
├─ Normal: IT adds users to groups (business hours)
├─ Suspicious: Unauthorized privilege escalation
└─ Hunting: Attacker persistence (new domain admin account)

EVENT 4731: Security Group Created
├─ When: New security group created
├─ Key fields:
│  ├─ TargetGroupName: New group name
│  └─ CallerUserName: Who created it
├─ Red flag: Attacker-created groups for persistence
└─ Hunting: Look for unusual group names

EVENT 4732: Member Added to Security Group
├─ Similar to 4728 but different event number
├─ Use both events in hunting queries

EVENT 4735: Security Group Modified
├─ When: Group properties changed
├─ Example: Changing group membership rules
└─ Hunting: Unusual group modifications
```

### Process & Command Execution

```
EVENT 4688: Process Created
├─ When: New process starts
├─ Key fields:
│  ├─ NewProcessName: Path to executable
│  ├─ CommandLine: Full command with arguments
│  ├─ CreatorProcessName: Parent process
│  ├─ CreatorProcessID: PID of parent
│  └─ TargetUserName: Which account ran it
├─ Normal: Expected applications during work
├─ Suspicious: PowerShell with -enc flag, rundll32 from temp
└─ Hunting: Process parent-child relationships

Critical Suspicious Patterns:
├─ Office (winword.exe) → PowerShell (exploitation)
├─ Services.exe → cmd.exe (lateral movement)
├─ Legitimate app → svchost.exe (DLL injection)
├─ Explorer → cmd.exe (file share enumeration)
└─ Any process from C:\Temp\ (malware)

EVENT 4697: Service Installed
├─ When: New service installed
├─ Key fields:
│  ├─ ServiceName: New service name
│  ├─ ServiceFileName: Path to executable
│  └─ CallersName: Who installed it
├─ Red flag: Service with obfuscated name
├─ Red flag: Service in Temp directory
├─ Normal: IT creates services (update time)
└─ Hunting: Malware persistence via services
```

### Account Changes

```
EVENT 4723: Password Change
├─ When: User changes their own password
├─ Key fields:
│  ├─ SubjectUserName: Who changed password
│  └─ TargetUserName: Which account
├─ Normal: Users changing passwords (prompted)
├─ Suspicious: Service account password changed
└─ Hunting: Attacker changing victim's password

EVENT 4724: Password Reset Attempt
├─ When: Password reset attempted (admin resets user)
├─ Key fields:
│  ├─ SubjectUserName: Who reset password
│  └─ TargetUserName: Which account
├─ Normal: Help desk resetting user passwords
├─ Suspicious: Unauthorized reset by attacker
└─ Hunting: Password resets preceding privilege escalation

EVENT 4738: User Account Changed
├─ When: User account properties modified
├─ Examples:
│  ├─ Full name changed
│  ├─ Email changed
│  ├─ User description changed
│  └─ Profile path changed
├─ Normal: HR updates, user self-service
└─ Hunting: Account properties changed before attack
```

### Object Access

```
EVENT 4656: File/Object Access Requested
├─ When: Object (file, registry) access attempted
├─ Key fields:
│  ├─ ObjectName: Which file/object
│  ├─ AccessMask: What access was tried
│  │  ├─ 0x20089 = Read (common)
│  │  ├─ 0x10081 = Write
│  │  └─ 0x100001 = Execute
│  ├─ AccessReason: Why access allowed/denied
│  └─ SubjectUserName: Who accessed
├─ Volume: Extremely high (noisy!)
├─ Use with filter: Only log sensitive files
└─ Example: Monitor access to C:\HR\Payroll.xlsx

EVENT 4663: Object Access Occurred
├─ Similar to 4656 but after access completed
├─ Key fields: Same as 4656
└─ Use: Track successful file access
```

---

## Real-World Hunting Scenarios

### Scenario 1: Detect Brute Force Attack

```
INVESTIGATION: Identify brute force attack from Event 4625

Query Approach:

Step 1: Find failed logon spike
PowerShell query:
Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=4625]]' |
  Where-Object {$_.TimeCreated -gt (Get-Date).AddMinutes(-15)} |
  Group-Object { $_.Properties[6].Value } |
  Where-Object { $_.Count -gt 10 }

Result:
Target account: svc_admin
Failed attempts: 47 in 15 minutes
Source IPs: 203.0.113.42, 203.0.113.55, 203.0.113.66

Step 2: Extract failure codes
Filter for Event 4625 by target account "svc_admin"
Group by FailureCode:
├─ 0xC000006E: 2,100 attempts (wrong password) ← Most common
├─ 0xC000006D: 47 attempts (invalid username)
└─ 0xC0000234: 0 attempts (account locked - NOT triggered!)

RED FLAG: Account lockout NOT enabled!
└─ Attacker can brute force indefinitely

Step 3: Identify success
Search for Event 4624 (successful logon):
├─ TargetUserName: svc_admin
├─ LogonType: 3 (Network)
├─ SourceIPAddress: 203.0.113.42
├─ Time: 20:18:32 UTC (after 2,100+ failed attempts)

CONFIRMATION: Brute force succeeded!

IMPACT:
├─ Account compromised: svc_admin
├─ Access achieved: Network logon (credential-based)
├─ Attacker can now: Access file shares, databases
└─ Next step: Lateral movement to domain controller

RESPONSE:
├─ IMMEDIATE: Disable svc_admin account
├─ Lock: Services using svc_admin (check what services)
├─ Change: Reset svc_admin password
├─ Block: Source IPs (203.0.113.x range)
├─ Hunt: Check for lateral movement after 20:18
└─ Implement: Account lockout policy (5 attempts, 30 min)
```

### Scenario 2: Detect Privilege Escalation

```
INVESTIGATION: Identify privilege escalation via Event 4728

Query Approach:

Step 1: Find group membership changes
PowerShell:
Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=4728]]' |
  Where-Object {$_.TimeCreated -gt (Get-Date).AddDays(-1)} |
  Select TimeCreated, @{N='TargetGroup'; E={$_.Properties[2].Value}},
         @{N='MemberAdded'; E={$_.Properties[4].Value}},
         @{N='AddedBy'; E={$_.Properties[1].Value}}

Result:
Event 4728 detected:
├─ Time: 2026-02-18 03:45:23 (OFF-HOURS!)
├─ Target Group: Domain Admins
├─ Member Added: svc_backup
├─ Added By: svc_admin (compromised account!)

RED FLAG: Service account added to Domain Admins!

Step 2: Context investigation
├─ Who is svc_admin?
│  └─ Service account for backup application
│
├─ Who is svc_backup?
│  └─ Doesn't exist! (New account created recently)
│
├─ Who authorized this?
│  └─ NO ONE - this was unauthorized!

Step 3: Timeline correlation
Look for Event 4720 (account creation):
├─ svc_backup created: 2026-02-18 03:30 (by svc_admin)
├─ svc_backup added to Domain Admins: 2026-02-18 03:45
├─ Timeline: Create account → Immediately add to admins

CONCLUSION: Attacker persistence tactic
└─ Goal: Maintain access via domain admin account
   if original compromise revoked

Step 4: Check for usage
Search Event 4624 (logon) with svc_backup:
├─ svc_backup first logon: 2026-02-18 04:00 (15 min after creation)
├─ Source: 10.0.50.5 (domain controller RDP)
├─ LogonType: 10 (RDP)
└─ Attacker now has domain admin RDP access!

IMPACT:
├─ Attacker created persistence account
├─ Account has Domain Admins privileges
├─ Attacker has RDP access to domain controller
├─ Full domain compromise = CRITICAL

RESPONSE:
├─ IMMEDIATE: Disable svc_backup account
├─ IMMEDIATE: Disable svc_admin account
├─ Review: All logons with these accounts (extent of damage)
├─ Rebuild: Domain controller (clean state)
├─ Change: All domain admin passwords
├─ Hunt: Other persistence mechanisms
└─ Reset: All domain admin credentials
```

### Scenario 3: Detect Lateral Movement

```
INVESTIGATION: Identify lateral movement using Event 4648

Query Approach:

Step 1: Find explicit credential usage
PowerShell:
Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=4648]]' |
  Where-Object {$_.TimeCreated -gt (Get-Date).AddDays(-1)} |
  Select TimeCreated, 
         @{N='InitiatingUser'; E={$_.Properties[1].Value}},
         @{N='TargetAccount'; E={$_.Properties[5].Value}},
         @{N='TargetServer'; E={$_.Properties[9].Value}}

Result:
Event 4648 detected (unusual credentials):
├─ Time: 2026-02-18 15:30:45
├─ From: john.smith@TARGETCO (normal user account)
├─ Using: domain\administrator credentials
├─ Target: \\fileserver01 (SMB connection)

RED FLAG: User running as admin!

Step 2: Check if legitimate
├─ Is john.smith an admin? NO
├─ Does IT allow users to run as admin? NO
├─ Does john.smith have file server access normally? NO
├─ Conclusion: UNAUTHORIZED

Step 3: Identify how credentials obtained
Search for:
├─ How did john.smith get admin credentials?
├─ Was john.smith's computer compromised?
├─ Search Event 4625 (failed logons) for john.smith:
│  └─ Found: Multiple failed admin logon attempts
│     15 minutes before successful Event 4648
│
└─ Conclusion: john.smith's system was compromised
   Attacker attempted brute force, succeeded, used credentials

Step 4: Identify scope
Search for all Event 4648 from john.smith's system:
├─ Multiple attempts to connect as administrator
├─ Targets: fileserver01, fileserver02, domain-controller
├─ Attempts: Copy files from each (lateral movement)

IMPACT:
├─ john.smith's computer compromised
├─ Administrator credentials compromised
├─ Access to file servers (all data accessible)
├─ Access to domain controller (full domain possible)
└─ Severity: CRITICAL

RESPONSE:
├─ Isolate: john.smith's computer
├─ Reset: Administrator password (all admins change)
├─ Review: All logons with admin account (last 7 days)
├─ Rebuild: john.smith's computer
├─ Disable: Compromised admin account temporarily
└─ Activate: Incident response procedures
```

---

## Event Log Forwarding Configuration

```
Enable Event Log Forwarding (Central SIEM):

1. Create Forwarder Subscription:
   wecutil cs -cn:siem-server -i:subscription_file.xml

2. Subscription XML Example:
<?xml version="1.0" encoding="UTF-8"?>
<Subscription xmlns="http://schemas.microsoft.com/windows/events/2004/08/events">
  <SubscriptionId>Critical-Security-Events</SubscriptionId>
  <SubscriptionType>SourceInitiated</SubscriptionType>
  <Description>Forward critical security events</Description>
  <Enabled>true</Enabled>
  <Uri>http://siem-server.company.com:5985/wsman/SubscriptionManager/WEC</Uri>
  <ConfigurationMode>MinLatency</ConfigurationMode>
  <Delivery Mode="Push">
    <Batching>
      <MaxItems>100</MaxItems>
      <MaxLatencyTime>30000</MaxLatencyTime>
    </Batching>
  </Delivery>
  <Query>
    <Select Path="Security">
      *[System[(EventID=4624 or EventID=4625 or EventID=4728 
        or EventID=4720 or EventID=4688)]]
    </Select>
  </Query>
  <LogFile>ForwardedEvents</LogFile>
  <ContentFormat>Events</ContentFormat>
  <Locale Language="en-US"/>
</Subscription>

3. Verify forwarding:
   wecutil gr Critical-Security-Events
   (Shows subscription status, subscribed computers)
```

---

## Critical Event IDs Summary Table

| Event ID | Event Name | Alert Trigger | Severity |
|----------|-----------|---|---|
| 4624 | Logon Success | Non-business hours, unknown IP | Medium |
| 4625 | Logon Failed | >10 in 15 min = brute force | High |
| 4720 | User Created | After-hours, unusual username | High |
| 4728 | User Added to Admin | Any addition to Domain Admins | Critical |
| 4688 | Process Created | Office→PowerShell, Temp files | High |
| 4697 | Service Installed | Service in Temp, odd names | High |
| 4723 | Password Changed | Service account change | Medium |
| 4656 | Object Access | Sensitive file access (HR, Finance) | Medium |

---

## References

- Microsoft Event Log Documentation
- SANS Windows Logging Cheat Sheet
- Windows Security Event Details

---

*Document Maintenance:*
- Update event IDs as Windows versions change
- Test Event Log Forwarding quarterly
- Monitor Event Log disk usage (can grow rapidly)
- Archive old logs (compliance requirement)
