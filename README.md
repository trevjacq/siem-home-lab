SIEM Home Lab — Elastic Stack on Windows 10
A home security operations lab built on Elastic Stack (Elasticsearch + Kibana + Winlogbeat), ingesting real-time Windows Security event logs and detecting attacker behaviors mapped to MITRE ATT&CK.

Architecture
Windows 10 Host
│
├── Winlogbeat 9.3.3
│   └── Collects: Security, System, Application event logs
│
├── Elasticsearch 9.3.3
│   └── Indexes and stores all log data locally
│
└── Kibana 9.3.3
    └── Dashboards, KQL search, detection rules, alerting

Environment
ComponentVersionRoleOSWindows 10Log source + hostElasticsearch9.3.3Log storage and indexingKibana9.3.3SIEM UI, dashboards, alertingWinlogbeat9.3.3Log collection agent

Log Sources Ingested

Windows Security log — authentication, privilege use, account changes, process creation
Windows System log — service starts/stops, system events
Windows Application log — application errors and events

Key event IDs collected:
Event IDDescriptionMITRE ATT&CK4624Successful logonT1078 Valid Accounts4625Failed logonT1110 Brute Force4634LogoffT1078 Valid Accounts4672Special privileges assignedT1078.0024688Process creationT1059 Command Execution4728User added to global groupT1098 Account Manipulation4732User added to local groupT1098 Account Manipulation4776NTLM credential validationT1110 Brute Force

Detection Rules (KQL)
1. Brute Force Detection
Detects repeated failed logon attempts from the same source.
kqlevent.code: 4625
What it catches: Multiple failed login attempts indicating a password spray or brute force attack. In a production environment this would be tuned with a threshold (5+ failures in 2 minutes from the same source IP).

2. Privilege Escalation — User Added to Admin Group
Detects when any account is added to a privileged local group.
kqlevent.code: 4732
What it catches: Unauthorized privilege escalation, persistence via admin group membership. In a home lab with no legitimate admin changes, any alert here warrants immediate investigation.

3. Process Creation Monitoring
Detects all new process creation events on the host.
kqlevent.code: 4688
Refined version — suspicious reconnaissance commands:
kqlevent.code: 4688 AND process.command_line: ("whoami" OR "ipconfig" OR "net user" OR "net localgroup")
What it catches: Attacker reconnaissance activity post-compromise — commands commonly run immediately after gaining access to enumerate users, network config, and group membership.

4. Special Privilege Logon
Detects when a user logs on with sensitive privileges (admin equivalent).
kqlevent.code: 4672 AND NOT winlog.event_data.SubjectUserName: "SYSTEM"
What it catches: Non-SYSTEM accounts being granted special privileges, a key indicator of privilege escalation or lateral movement.

Test Activity Generated
The following commands were used to simulate attacker behavior and verify detection rules:
Simulate brute force (10 failed logons):
powershellfor ($i=1; $i -le 10; $i++) {
  $cred = New-Object System.Management.Automation.PSCredential("fakeuser", (ConvertTo-SecureString "wrongpassword" -AsPlainText -Force))
  Start-Process cmd -Credential $cred -ErrorAction SilentlyContinue
}
Result: 10 x Event ID 4625 captured in Kibana
Simulate privilege escalation:
powershellnet user testuser Password123! /add
net localgroup administrators testuser /add
net user testuser /delete
Result: 2 x Event ID 4732 captured in Kibana
Enable process creation auditing:
powershellauditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
Simulate post-compromise reconnaissance:
powershellStart-Process powershell -ArgumentList "-Command whoami; ipconfig; net user" -WindowStyle Hidden
Result: 11 x Event ID 4688 captured in Kibana

Setup Instructions
Prerequisites

Windows 10 with 8GB+ RAM
50GB free disk space

1. Install Elasticsearch
Download from elastic.co/downloads, extract to C:\elastic, run:
powershellcd C:\elastic\elasticsearch-9.3.3
.\bin\elasticsearch.bat
Save the auto-generated elastic user password on first run.
2. Install Kibana
Extract to C:\elastic, add encryption keys to kibana.yml, run:
powershellcd C:\elastic\kibana-9.3.3
.\bin\kibana.bat
Access at http://localhost:5601
3. Install Winlogbeat
Extract to C:\elastic, configure winlogbeat.yml with Elasticsearch credentials, run:
powershellcd C:\elastic\winlogbeat-9.3.3-windows-x86_64
.\winlogbeat.exe setup -e
.\winlogbeat.exe -e
4. Verify data ingestion
In Kibana → Discover, select winlogbeat-* data view. Logs should appear within 30 seconds.

Key Findings

Windows machines generate continuous authentication and privilege events even at idle — establishing a baseline is critical before tuning detection thresholds
Event ID 4688 (process creation) requires manual audit policy enablement via auditpol — not on by default
Winlogbeat ships logs in near-real-time (~15 second delay), making it viable for live threat detection in a home lab context


Certifications & Context
This project was built as a hands-on supplement to CompTIA Security+ (SY0-701) certification, specifically covering domains:

Domain 1 — Threats, Attacks and Vulnerabilities (brute force, privilege escalation)
Domain 2 — Technologies and Tools (SIEM configuration, log analysis)
Domain 4 — Identity and Access Management (Event ID mapping)


Next Steps

 Add Packetbeat for network traffic ingestion
 Build Kibana alerting rules with email notifications
 Integrate MITRE ATT&CK Navigator overlay
 Add Linux VM with auth log ingestion
 Build a custom detection dashboard combining all three event types


References

Elastic Security Documentation
MITRE ATT&CK Framework
Windows Security Event IDs — Microsoft Docs
CompTIA Security+ SY0-701
