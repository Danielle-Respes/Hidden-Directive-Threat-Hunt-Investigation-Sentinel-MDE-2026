# Evidence Log — GF-INC-2026-0704

| Finding | Source | Query/Artifact | Timestamp | Status |
|---|---|---|---|---|
| Azure Run Command from compromised Service Principal `5deb2a08...` (IP `4.153.100.221`) | LAW-Cyber-Range | `AzureActivity` query, C02 | 2026-07-04 08:01 UTC | ✓ Confirmed |
| `script49.ps1` executed via `cmd → powershell` with `-ExecutionPolicy Unrestricted` | LAW-SilentCorridor | `WindowsProcess_CL`, C02 | 2026-07-04 10:01:34.963 | ✓ Confirmed |
| Same process chain, SYSTEM privileges | Defender XDR | Device timeline, C02 | 2026-07-04 10:01:34.997 | ✓ Confirmed |
| Backdoor account `sancadmin` created + activated | LAW-SilentCorridor | `net.exe user sancadmin ...`, C02 | 2026-07-04 10:01:35.466–783 | ✓ Confirmed |
| Token theft from `StoreDesktopExtension.exe`, assigned to `CollectGuestLogs.exe` | Defender XDR | `ProcessPrimaryTokenModification`, C05 | 2026-07-04 21:55:00.341–412 | ✓ Confirmed |
| `cmd.exe` spawned as SYSTEM via named-pipe stdin | LAW-SilentCorridor | `WindowsProcess_CL`, C05 | 2026-07-04 21:55:00.500 | ✓ Confirmed |
| Stored credentials added for `GREENFIELD\m.smith` | LAW-SilentCorridor | `cmdkey /add`, C07 | 2026-07-04 09:15:01 | ✓ Confirmed |
| KeePass vault opened | LAW-SilentCorridor | `KeePass.exe --preload`, C07 | 2026-07-04 10:04:50 | ✓ Confirmed |
| Service account `svc_backup` targeted | LAW-SilentCorridor | `Get-ADUser svc_backup ...`, C07 | 2026-07-04 11:32:41 | ✓ Confirmed |
| LSASS-dump prep | LAW-SilentCorridor | `tasklist \| findstr lsass`, C07 | 2026-07-04 12:08:26 | ✓ Confirmed |
| Route 1 lateral movement: `GF-SRV01$` Pass-the-Hash from `10.1.0.169` | LAW-SilentCorridor | Logon events, C09 | 2026-07-04 10:01:48 | ✓ Confirmed |
| Route 2 lateral movement: `t.harris` from `10.1.0.120` | LAW-SilentCorridor | Logon events, C09 | 2026-07-04 11:10:00 | ✓ Confirmed |
| Both routes converge on GF-DC01 (Kerberos TGT/TGS, Overpass-the-Hash) | LAW-SilentCorridor + Defender XDR | EventID 4768/4769, C09 | 2026-07-04 11:10:04 | ✓ Confirmed |
| `t.harris` SMB file access on GF-SRV01 | Defender XDR | Device timeline, C09 | 2026-07-04 11:10:49 | ✓ Confirmed |
| Failed pre-auth from `10.1.0.169` (suspicious) | LAW-SilentCorridor | EventID 4771, C09 | 2026-07-04 (row 1001) | ⚠ Flagged, unresolved |
| `m.smith` login to GF-SRV01 from `10.1.0.133` | LAW-SilentCorridor | Logon events, C09 | 2026-07-04 (row 959) | ✓ Confirmed |
| `sancadmin` backdoor accesses GF-DC01 | LAW-SilentCorridor | Logon events, C09 | 2026-07-04 (row 973) | ✓ Confirmed |
| `keepass.zip` staged on GF-WS01 | LAW-SilentCorridor | File creation event, C07 | 2026-07-04 (post-11:57) | ✓ Confirmed — see C11 for exfil |
