# MITRE ATT&CK Mapping — GF-INC-2026-0704

| Tactic | Technique | ID | Evidence | Source Doc |
|---|---|---|---|---|
| Initial Access | Valid Accounts (Cloud) | T1078 | Compromised Azure Service Principal `5deb2a08...` via Run Command | C02 |
| Execution | Command & Scripting Interpreter (PowerShell) | T1059 | `script49.ps1` run with `-ExecutionPolicy Unrestricted` | C02 |
| Persistence | Create Account (Local) | T1136 | `sancadmin` local admin account created | C02 |
| Privilege Escalation / Defense Evasion | Access Token Manipulation | T1134 | Token stolen from `StoreDesktopExtension.exe`, assigned to `CollectGuestLogs.exe` | C05 |
| Persistence / Defense Evasion | Hijack Execution Flow | T1574 | `CollectGuestLogs.exe` abused to spawn SYSTEM `cmd.exe` | C05 |
| Credential Access | Credentials from Password Stores | T1555 | `cmdkey` stored credentials + KeePass vault access | C07 |
| Credential Access | OS Credential Dumping (preparation) | T1003 | `tasklist \| findstr lsass` staging for LSASS dump | C07 |
| Discovery | Account Discovery | T1087 | `Get-ADUser svc_backup -Properties ...` | C07 |
| Lateral Movement | Pass-the-Hash | T1550.002 | `GF-SRV01$` computer-account auth from 10.1.0.169 | C09 |
| Lateral Movement | Overpass-the-Hash / Kerberos | T1550.003 | EventID 4768/4769 TGT/TGS from both routes into GF-DC01 | C09 |
