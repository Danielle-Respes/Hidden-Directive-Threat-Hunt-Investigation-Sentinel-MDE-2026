# Screenshot & Query Evidence Log — GF-INC-2026-0704

Each entry: source, query run, what the screenshot/export shows, and which phase doc it updates.

**Why raw CSV exports are included here instead of screenshots:** these queries returned hundreds to thousands of rows — too many to screenshot legibly. The CSV export is the actual underlying data behind what a screenshot would show; it's included so every timestamp and finding below can be traced back to a real, re-runnable query result rather than a claim. Where a single alert or event is the finding (not a bulk export), a screenshot is used instead.

## 1. Sentinel Alert Queue Export

| Field | Detail |
|---|---|
| **Source** | LAW-SilentCorridor — ASI Scheduled Alerts |
| **File** | `query_data (1).csv` / `query_data (2).csv` (incidents) |
| **Finding** | Earliest alert "Mass File Rename (Ransomware Indicator)" at **2026-07-04 00:11:33 UTC** — over 7 hours before the previously stated 08:01 UTC start time |
| **Also shows** | `sancadmin`-attributed "CertUtil-URLCache" alert at 02:07:56 AM; "Scheduled task created... by GF-WS01\sancadmin" at 11:49:19 AM |
| **Updates** | C02 (timeline) · investigation-gaps.md (new gap) · C04 (scheduled task corroboration) |

## 2. Defender Advanced Hunting — DeviceProcessEvents (GF-WS01)

| Field | Detail |
|---|---|
| **Source** | Defender XDR Advanced Hunting |
| **File** | `New query.csv` |
| **Finding** | `sancadmin` actively running desktop-session processes (explorer.exe, OneDrive, etc.) as early as **2026-07-03 8:03:53 PM** — before the incident window entirely |
| **Updates** | C02 · C04 (sancadmin origin — reframes as pre-existing account, not new creation) |

## 3. Defender Advanced Hunting — DeviceRegistryEvents (GF-WS01)

| Field | Detail |
|---|---|
| **Source** | Defender XDR Advanced Hunting |
| **File** | `New query (1).csv` |
| **Finding** | Registry key/task cache activity tied to `sancadmin`, including RegistryValueDeleted/RegistryKeyDeleted events at **8:04:51–8:06:16 PM on 7/3** — consistent with an active, established user profile, not first-time provisioning |
| **Updates** | C04 · C06 |

## 4. LAW-SilentCorridor — WindowsProcess_CL (sancadmin command-line history)

| Field | Detail |
|---|---|
| **Source** | Microsoft Sentinel, LAW-SilentCorridor |
| **File** | `query_data (3).csv` |
| **Finding** | `C:\Users\sancadmin\AppData\Local\Temp` referenced in `cmd.exe` activity as early as **2026-07-03 12:45:57 AM UTC** — confirms the `sancadmin` user profile folder existed a full day before the attacker's 10:01:35 AM "net user sancadmin" command on July 4 |
| **Why it matters** | Strongly indicates account takeover of a pre-existing account, not new account creation |
| **Updates** | C02 (correction: "created" → "took over/reactivated") · C04 (Finding 1 correction) · Executive Summary · Incident Overview |

## 5. LAW-Cyber-Range — AzureActivity (sancadmin / GF-WS01 cross-check)

| Field | Detail |
|---|---|
| **Source** | Microsoft Sentinel, LAW-Cyber-Range |
| **Query** | `AzureActivity \| where Caller has "sancadmin" or ResourceGroup has "GF-WS01"` |
| **Finding** | No results returned — no Azure-side telemetry corroborates on-host sancadmin activity from the cloud control plane |
| **Updates** | investigation-gaps.md (documented as a real telemetry gap, not an error) |
