# Timeline (Structured) — GF-INC-2026-0704

| Timestamp | Host | Phase | Event |
|---|---|---|---|
| 2026-07-04 08:01:00 UTC | Azure (SP) | Initial Access | Azure Run Command via compromised SP 5deb2a08... from 4.153.100.221 |
| 2026-07-04 10:01:34 UTC | GF-WS01 | Execution | cmd → powershell -ExecutionPolicy Unrestricted -File script49.ps1 (SYSTEM) |
| 2026-07-04 10:01:35 UTC | GF-WS01 | Persistence | net user sancadmin ChangeThis2026fix / net user sancadmin /active:yes |
| 2026-07-04 10:01:48 UTC | GF-SRV01 | Lateral Movement (R1) | GF-SRV01$ computer account, Pass-the-Hash, from 10.1.0.169 |
| 2026-07-04 09:15:01 UTC | GF-SRV01 | Credential Access | cmdkey /add:GF-SRV01 /user:GREENFIELD\m.smith |
| 2026-07-04 10:04:50 UTC | GF-SRV01 | Credential Access | KeePass.exe --preload |
| 2026-07-04 11:10:00 UTC | GF-SRV01 | Lateral Movement (R2) | t.harris domain user, from 10.1.0.120 |
| 2026-07-04 11:10:04 UTC | GF-DC01 | Lateral Movement | EventID 4768/4769 Kerberos TGT/TGS, Overpass-the-Hash (both routes converge) |
| 2026-07-04 11:10:49 UTC | GF-SRV01 | Lateral Movement | t.harris SMB file open attempts (Defender XDR) |
| 2026-07-04 11:25:03 UTC | GF-SRV01 | Credential Access | cmdkey /list (enumeration) |
| 2026-07-04 11:32:41 UTC | GF-SRV01 | Credential Access | Get-ADUser svc_backup -Properties Description,ServicePrincipalNames |
| 2026-07-04 11:57:54 UTC | GF-SRV01 | Credential Access | cmdkey /list (repeated enumeration) |
| 2026-07-04 12:08:26 UTC | GF-SRV01 | Credential Access | tasklist \| findstr lsass (LSASS dump prep) |
| 2026-07-04 21:55:00.341 PM | GF-WS01 | Privilege Escalation | ProcessPrimaryTokenModification on StoreDesktopExtension.exe (sancadmin) |
| 2026-07-04 21:55:00.412 PM | GF-WS01 | Privilege Escalation | Token assigned to CollectGuestLogs.exe |
| 2026-07-04 21:55:00.500 PM | GF-WS01 | Privilege Escalation | cmd.exe spawned as NT AUTHORITY\SYSTEM (named-pipe stdin) |
| 2026-07-04 (row 959) | GF-SRV01 | Lateral Movement | m.smith logs in from 10.1.0.133 |
| 2026-07-04 (row 973) | GF-DC01 | Lateral Movement | sancadmin backdoor accesses GF-DC01 |
| 2026-07-04 (row 1001) | GF-DC01 | Lateral Movement | EventID 4771 failed pre-auth from 10.1.0.169 (suspicious, unresolved) |

*Raw entries — not yet prose-ified for the final report. Times reconstructed from C02/C05/C07/C09 evidence sections.*
