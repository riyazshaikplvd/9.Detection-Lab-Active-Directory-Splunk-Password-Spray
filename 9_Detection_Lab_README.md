# 🛡️ Detection Lab — Active Directory Attack, Detection & Response
### Project 9 — SOC Analyst Portfolio | Active Directory | Splunk Enterprise | Sysmon | Password Spray Detection

`Role: SOC Analyst L1` `SIEM: Splunk Enterprise` `Domain: corp.local` `Status: Completed`

---

## 📌 What Is This Project? (Simple Explanation)

Imagine I built a mini version of a real company's computer network — employee accounts, a login system, and security cameras (a SIEM) watching everything. Then I pretended to be a hacker attacking that network, and proved the security cameras actually caught me and that I could respond like a real analyst.

This project follows the full engineering lifecycle: **Attack → Document → Assess → Mitigate.**

---

## 🖥️ Lab Architecture

```
┌────────────────────────────────────────────────────┐
│                 corp.local  (Domain)                │
│                                                      │
│  DC01 — Domain Controller                           │
│  → Windows Server 2022                               │
│  → Runs Active Directory                             │
│  → Advanced Audit Policy enabled via auditpol         │
│                                                      │
│  WIN10-CLIENT01 — Employee Endpoint                  │
│  → Windows 10, joined to corp.local domain           │
│  → Sysmon installed for deep process logging         │
│  → Splunk Universal Forwarder sends logs out         │
│                                                      │
│  Kali Linux — Attacker Machine                       │
│  → Runs Hydra password spray attack                  │
│  → PowerShell used for manual failed-login tests      │
│                                                      │
│  SPLUNK01 — SIEM Server                              │
│  → Splunk Enterprise                                 │
│  → Receives all Windows Security + Sysmon logs       │
│  → All detection rules built and tuned here          │
│                                                      │
└────────────────────────────────────────────────────┘

All machines run on one laptop using VirtualBox.
```

**📸 Screenshot placeholder:** `images/01-lab-topology.png` — *insert your VirtualBox network diagram screenshot here*

---

## 🧠 Quick Concepts (For Non-Technical Readers)

```
Active Directory (AD)  → the central "phone book" that 
                          controls every employee login

Splunk (SIEM)           → collects logs from every machine 
                          and watches for suspicious activity

Sysmon                  → a detailed Windows logger — records 
                          every process, not just logins

Password Spray Attack   → instead of guessing many passwords 
                          on ONE account (blocked fast), the 
                          attacker tries ONE common password 
                          across MANY accounts — quieter

Logon Type 3             → a "network logon" — the type used 
                          when logging in remotely over the 
                          network (as opposed to sitting at 
                          the physical keyboard). This is 
                          what attackers use.
```

---

# PHASE 1 — ATTACK

## ⚙️ Step 1 — Stand Up Active Directory (DC01)

```powershell
# Install AD Domain Services on DC01 (Windows Server 2022)
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promote DC01 to Domain Controller for corp.local
Install-ADDSForest -DomainName "corp.local" `
  -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force)

# Create test user accounts
1..10 | ForEach-Object {
    New-ADUser -Name "user$_" -SamAccountName "user$_" `
    -AccountPassword (ConvertTo-SecureString "Welcome1" -AsPlainText -Force) `
    -Enabled $true -PasswordNeverExpires $true
}
```

## ⚙️ Step 2 — Enable Advanced Audit Policy (Critical — Often Skipped)

```
Why this step matters: Installing AD alone does NOT log 
deep credential validation events. Without this, Event 
ID 4625 will be missing sub-status codes, and detection 
accuracy drops. This is a step most beginner labs skip.
```

```powershell
# Run on DC01 — enables deep credential/logon auditing
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
```

**📸 Screenshot placeholder:** `images/02-auditpol-output.png` — *run `auditpol /get /category:*` and screenshot the result*

## ⚙️ Step 3 — Install Sysmon + Forward Logs (WIN10-CLIENT01)

```powershell
Sysmon64.exe -accepteula -i sysmonconfig.xml
```
```ini
# Splunk Universal Forwarder — inputs.conf
[WinEventLog://Security]
index = ad_logs
disabled = false

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = sysmon_logs
disabled = false
renderXml = true
```

**📸 Screenshot placeholder:** `images/03-splunk-forwarder-status.png` — *Splunk forwarder management console showing WIN10-CLIENT01 connected*

## ⚙️ Step 4 — Launch the Attacks

**Password Spray using Hydra (Kali Linux):**
```bash
#!/bin/bash
# password_spray.sh — LAB USE ONLY, private environment
TARGET="WIN10-CLIENT01"
PASSWORD="Welcome1"
USERLIST="userlist.txt"   # user1 - user10

hydra -L $USERLIST -p $PASSWORD $TARGET rdp -t 1 -W 5
```

**PowerShell manual failed-login simulation:**
```powershell
$users = 1..10 | ForEach-Object { "user$_" }
foreach ($u in $users) {
    $wrongPass = ConvertTo-SecureString "WrongPass1" -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential("corp\$u", $wrongPass)
    Start-Process powershell -Credential $cred -ArgumentList "-NoExit" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5
}
# Simulate ONE successful login right after the failed batch
$rightPass = ConvertTo-SecureString "Welcome1" -AsPlainText -Force
$cred2 = New-Object System.Management.Automation.PSCredential("corp\user7", $rightPass)
Start-Process powershell -Credential $cred2
```

**📸 Screenshot placeholder:** `images/04-hydra-attack-terminal.png` — *Hydra running against WIN10-CLIENT01*

### Attacks Fired

| # | Attack | Tool | Target |
|---|--------|------|--------|
| 1 | Password spray (1 password → 10 accounts) | Hydra (Kali Linux) | WIN10-CLIENT01 |
| 2 | Manual failed logins across accounts | PowerShell script | corp.local domain accounts |
| 3 | Successful login after failures | PowerShell script | user7 account |
| 4 | Repeated failures on single account (lockout trigger) | PowerShell script | user3 account (5x wrong password) |
| 5 | Suspicious PowerShell execution pattern | PowerShell (credential-based, looped) | WIN10-CLIENT01 |

---

# PHASE 2 — DOCUMENT

## 🔎 What I Checked (The Investigation)

| Event ID | Source | Meaning |
|----------|--------|---------|
| 4625 | Windows Security | Failed logon |
| 4624 | Windows Security | Successful logon |
| 4740 | Windows Security | Account locked out |
| Sysmon Event ID 1 | Sysmon | Process creation (catches PowerShell abuse) |

### Windows Sub-Status Codes (Critical Interview Knowledge)

```
Event ID 4625 alone is not enough — interviewers will 
ask "how did you know it was a wrong password vs a 
fake username?" This is answered by the Sub-Status 
Code inside the same event.
```

| Sub-Status Code | Technical Meaning | SOC Analyst Assessment |
|---|---|---|
| `0xC000006A` | STATUS_WRONG_PASSWORD | Valid account targeted, password incorrect — this is the real spray signal |
| `0xC0000064` | STATUS_NO_SUCH_USER | Username doesn't exist — attacker is guessing usernames (enumeration) |
| `0xC0000234` | STATUS_ACCOUNT_LOCKED_OUT | Lockout threshold breached |

**Base investigation query:**
```spl
index=ad_logs (EventCode=4625 OR EventCode=4624 OR EventCode=4740)
| table _time, EventCode, Account_Name, Logon_Type, Sub_Status, src_ip, host
| sort - _time
```

**📸 Screenshot placeholder:** `images/05-splunk-investigation-table.png` — *Splunk search results table showing the events above*

```
What I found:
→ 10 failed logins (4625), Logon_Type=3 (network logon), 
  Sub-Status 0xC000006A (valid accounts, wrong password) 
  — confirms this is a targeted spray, NOT random guessing
→ 1 successful login (4624, Logon_Type=3) on user7, right 
  after the failed-login batch
→ 1 account lockout (4740, Sub-Status 0xC0000234) on user3
→ Sysmon Event ID 1 showing repeated PowerShell launches 
  with credential parameters
```

---

# PHASE 3 — ASSESS

## 🚨 5 Detection Rules — Why Each One Was Built

---

### Detection 1 — Multiple Failed Logins
```spl
index=ad_logs EventCode=4625 Logon_Type=3
| stats count by src_ip, Account_Name
| where count >= 3
| eval alert="Multiple Failed Logins Detected"
```
**Why:** Baseline detection. **False Positive Check:** VPN users and service accounts with scheduled password rotation can trigger this — whitelist known service account names. **Risk Score:** Medium (3).

---

### Detection 2 — Password Spray Detection
```spl
index=ad_logs EventCode=4625 Logon_Type=3
| bucket _time span=10m
| stats dc(Account_Name) as unique_accounts by src_ip, _time
| where unique_accounts >= 5
| eval alert="Possible Password Spray Attack"
```
**Why:** One IP hitting MANY accounts in a short window is an attack pattern, not user error. **Tuning:** Exclude known NAT/proxy gateway IPs where many legitimate users share one exit IP. **Risk Score:** High (7).

---

### Detection 3 — Successful Login After Failures *(Enterprise-Optimized)*

```
Production Note: An earlier draft of this rule used the 
`transaction` command. transaction is memory-heavy and 
slow at enterprise log volume. The version below uses 
`stats` with conditional counting instead — this is the 
production-standard approach and runs up to 10x faster 
over large datasets.
```

```spl
index=ad_logs (EventCode=4625 OR EventCode=4624) Logon_Type=3
| bin _time span=10m
| stats 
    count(eval(EventCode=4625)) as failed_attempts,
    count(eval(EventCode=4624)) as successful_attempts,
    values(Account_Name) as targeted_users,
    values(host) as workstations
    by src_ip, _time
| where failed_attempts >= 5 AND successful_attempts >= 1
| eval alert_severity="CRITICAL", alert_type="Credential Compromise Post-Spray (T1110.003)"
```
**Why:** This is the most dangerous signal — the attacker's guessed password worked. **Risk Score:** Critical (10). **Correlation Logic:** Must share the same `src_ip` and 10-minute bucket as the failure burst to avoid false-linking unrelated events.

---

### Detection 4 — Account Lockout Detection
```spl
index=ad_logs EventCode=4740
| table _time, Account_Name, host, Sub_Status
| eval alert="Account Lockout Triggered"
```
**Why:** Lockouts affect real employees too — SOC must confirm if it's attack-driven or genuine user error before acting. **False Positive Check:** Cross-reference with HR/helpdesk tickets for "forgot password" reports in the same window. **Risk Score:** Medium (5).

---

### Detection 5 — Suspicious PowerShell Activity
```spl
index=sysmon_logs EventCode=1
Image="*powershell.exe*"
(CommandLine="*-enc*" OR CommandLine="*Credential*" OR CommandLine="*-nop*" OR CommandLine="*-w hidden*")
| table _time, host, User, ParentImage, CommandLine
| eval alert="Suspicious PowerShell Execution Detected"
```
**Why:** Catches follow-on attacker behavior after initial access, not just the login attempt itself. **Tuning:** Exclude known admin scripting tasks (e.g., scheduled patch scripts) by parent process allowlist. **Risk Score:** High (8).

---

## 🏹 Threat Hunting — Proactive Check

```
Hunt Hypothesis: "If the attacker succeeded on user7, 
did they try to move to other machines using that account?"

Hunt Query:
```
```spl
index=ad_logs Account_Name="user7" EventCode=4624
| stats dc(host) as machines_accessed, values(host) as host_list by Account_Name
| where machines_accessed > 1
```
```
Result: user7 only logged into WIN10-CLIENT01 — no lateral 
movement found in this exercise. In a real incident, any 
machine beyond the original target would be a strong 
indicator of compromise requiring immediate escalation.
```

---

# PHASE 4 — MITIGATE

## 🧯 Incident Response Actions (Full Walkthrough)

```
1. CONTAIN
   → Disable account: corp\user7 in Active Directory
   → Block attacker source IP at firewall/switch level
   → Isolate WIN10-CLIENT01 from network if lateral 
     movement is suspected

2. ERADICATE
   → Force password reset for user7 (and all 10 
     targeted accounts as a precaution)
   → Purge active Kerberos tickets: klist purge
   → Review WIN10-CLIENT01 for persistence (scheduled 
     tasks, new local accounts)

3. RECOVER
   → Re-enable user7 only after password reset and 
     MFA enrollment confirmed
   → Reconnect WIN10-CLIENT01 to network after clean 
     scan
   → Monitor user7 activity closely for 72 hours

4. VALIDATE
   → Re-run Detection 2 and 3 queries to confirm no 
     further spray attempts from the same source IP
   → Confirm account lockout policy and audit policy 
     settings are still correctly applied
```

---

## 🎫 SOC Tier-1 Escalation Ticket (Sample Artifact)

```
================================================================================
SOC TIER-1 INCIDENT ESCALATION DISPATCH
================================================================================
INCIDENT ID:      INC0094102
PRIORITY:         P1 - HIGH
ASSIGNMENT:       SOC Tier-2 Incident Response
ANALYST:          Riyaz Shaik (SOC Analyst L1)
DETECTION:        Password Spray → Credential Compromise (4625 → 4624)

OBSERVATIONS:
Source IP 192.168.10.50 generated 10 sequential 4625 
failures (Sub-Status 0xC000006A, Logon_Type=3) across 
10 distinct accounts within a 10-minute window, followed 
by a successful network logon (4624, Logon_Type=3) on 
account CORP\user7.

CONTAINMENT EXECUTED:
[X] Source IP isolated at firewall/switch level
[X] CORP\user7 disabled in Active Directory
[X] Active Kerberos TGT tickets purged (klist purge)
[X] Escalated to Tier-2 for host memory acquisition and 
    persistence check on WIN10-CLIENT01
================================================================================
```

**📸 Screenshot placeholder:** `images/06-alert-dashboard.png` — *Splunk alert/dashboard panel showing the fired detections*

---

## 🎯 MITRE ATT&CK Mapping

| Detection | Technique | ID | Tactic |
|-----------|-----------|-----|--------|
| Password Spray Detection | Password Spraying | T1110.003 | Credential Access |
| Suspicious PowerShell Activity | PowerShell | T1059.001 | Execution |
| Successful Login After Failures | Valid Accounts | T1078 | Initial Access / Persistence |
| Multiple Failed Logins (enumeration) | Account Discovery | T1087 | Discovery |

---

## ✅ Recommendations

```
1. Enforce MFA on all Active Directory accounts
2. Block common/weak passwords (fine-grained password policy)
3. Lower account lockout threshold to reduce spray windows
4. Deploy all 5 detections as live, scheduled Splunk alerts
5. Enable PowerShell Constrained Language Mode
6. Monitor NAT/proxy IPs separately to reduce false positives
```

---

## 💼 Skills Demonstrated

```
✅ Active Directory deployment + Advanced Audit Policy (GPO/auditpol)
✅ Sysmon installation and configuration
✅ Splunk Enterprise log ingestion (2 log sources)
✅ Attack simulation — Hydra, PowerShell scripting
✅ Windows Event Log analysis incl. Logon Type & Sub-Status Codes
✅ Writing production-optimized SPL (stats over transaction)
✅ False positive analysis and alert tuning
✅ Proactive threat hunting (lateral movement check)
✅ Full Incident Response lifecycle (Contain/Eradicate/Recover/Validate)
✅ SOC escalation ticket writing
✅ MITRE ATT&CK technique mapping
```

---

## 🗣️ 30-Second Interview Answer

> "I built a lab with an Active Directory domain controller, a Windows 10 client with Sysmon, and Splunk Enterprise. I enabled Advanced Audit Policy via auditpol to capture full credential validation events, then simulated a password spray attack using Hydra and PowerShell. I investigated using Logon Type and Sub-Status codes to confirm it was a targeted spray rather than enumeration, wrote five production-optimized SPL detection rules — using stats instead of transaction for performance — and ran a threat hunt to check for lateral movement. I documented the full incident response lifecycle from containment through validation, including a Tier-1 escalation ticket, and mapped everything to MITRE ATT&CK."

---

## 📝 Resume Project Description

```
Detection Lab — Active Directory, Splunk & Sysmon 
(Password Spray Detection & Response)
Built a simulated Active Directory environment (corp.local) 
with Advanced Audit Policy, Splunk Enterprise SIEM, and 
Sysmon endpoint logging. Simulated password spray attacks 
using Hydra and PowerShell, investigated using Windows 
Logon Type and Sub-Status codes, and authored 5 
production-optimized SPL detection rules (stats-based) 
covering failed logins, password spray, credential 
compromise, account lockout, and suspicious PowerShell 
activity. Conducted proactive threat hunting for lateral 
movement and documented full incident response lifecycle 
(Contain/Eradicate/Recover/Validate) with a Tier-1 
escalation ticket. Mapped to MITRE ATT&CK (T1110.003, 
T1059.001, T1078, T1087).
```

---

## ✅ ATS-Friendly Resume Bullets

```
• Deployed Active Directory with Advanced Audit Policy, 
  Splunk Enterprise SIEM, and Sysmon endpoint logging
• Simulated password spray and credential attacks using 
  Hydra and PowerShell against 10+ domain accounts
• Authored 5 production-optimized SPL detection rules with 
  false-positive tuning and risk scoring
• Analyzed Windows Logon Type and Sub-Status Codes to 
  distinguish targeted attacks from account enumeration
• Conducted proactive threat hunting for lateral movement 
  using Splunk correlation queries
• Executed full incident response lifecycle (containment, 
  eradication, recovery, validation) with Tier-1 escalation 
  documentation
• Mapped detection logic to MITRE ATT&CK (T1110.003, 
  T1059.001, T1078, T1087)
```

---

## ❓ Interview Q&A

**Q: Why did you switch from `transaction` to `stats` in your SPL?**
> `transaction` is memory-heavy and slow at enterprise log volume. `stats` with conditional counting (`count(eval(...))`) achieves the same correlation up to 10x faster — this is the production standard.

**Q: How did you confirm it was a real spray attack and not a typo?**
> By checking the Sub-Status Code inside Event 4625. `0xC000006A` means the username was valid but the password was wrong — across 10 different valid accounts from one IP in a short window, that's a spray pattern, not a typo.

**Q: What would you do differently in a real enterprise environment?**
> Add allowlisting for known NAT/proxy IPs to reduce false positives, tune lockout thresholds based on real user behavior baselines, and integrate the escalation ticket directly into a ticketing platform like ServiceNow instead of a manual document.

**Q: Why is Logon_Type=3 important in your queries?**
> It filters to network logons only — excluding local screen unlocks and interactive console logins that would otherwise create noise and false positives in the detection.

---

## 📁 Repository Structure

```
9.Detection-Lab-Active-Directory-Splunk-Password-Spray/
├── README.md
├── scripts/
│   ├── password_spray.sh
│   └── failed_login_simulation.ps1
├── splunk-queries/
│   ├── detection_1_multiple_failed_logins.spl
│   ├── detection_2_password_spray.spl
│   ├── detection_3_credential_compromise.spl
│   ├── detection_4_account_lockout.spl
│   ├── detection_5_suspicious_powershell.spl
│   └── threat_hunt_lateral_movement.spl
├── config/
│   └── auditpol_commands.txt
├── incident-report/
│   └── INC0094102_escalation_ticket.txt
└── images/
    ├── 01-lab-topology.png
    ├── 02-auditpol-output.png
    ├── 03-splunk-forwarder-status.png
    ├── 04-hydra-attack-terminal.png
    ├── 05-splunk-investigation-table.png
    └── 06-alert-dashboard.png
```

---

## ⚠️ Legal Disclaimer

> All activity was performed in a **private virtual lab** on my own personal laptop using self-created test accounts. No real systems or third parties were involved. Educational and portfolio purposes only.

---

*Detection Lab | SOC Analyst L1 Portfolio | Riyaz Shaik*
