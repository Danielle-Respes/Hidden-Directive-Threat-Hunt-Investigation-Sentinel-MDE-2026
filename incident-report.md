# Incident Report by Danielle R

**Case Reference:** GF-INC-2026-0704
**Classification:** Internal
**Report Status:** Draft
**Report Version:** 1.0
**Analyst:** Danielle R
**Date of Report (UTC):** 2026-08-01

---

## 1. Executive Summary

Between **2026-07-04 08:01 UTC** and **2026-07-05 03:00 UTC**, an external attacker used a compromised Azure Service Principal to remotely execute code on GF-WS01, escalated to SYSTEM privileges through access-token theft, harvested credentials from multiple sources, and moved laterally into GF-SRV01 and the domain controller GF-DC01. A backdoor administrator account was created and used to maintain access throughout.

The attacker's cloud-side command was issued at 08:01 UTC; it landed and executed on GF-WS01 at 10:01:34 UTC — a **~2 hour dwell/transit gap** explained by Azure Run Command's extension queueing, not detection delay. GF-DC01, the domain controller, became the persistent authentication hub for the remainder of the intrusion, meaning the attacker's reach extended to the core of the domain, not just the initial host.

**Systems affected:** GF-WS01 (initial foothold), GF-SRV01, GF-DC01 (domain controller).
**Current status:** Investigation complete for the in-scope window; exfiltration transport unconfirmed (see Section 3).

**Priority actions:**
1. Disable/rotate the compromised Azure Service Principal (`5deb2a08...`) and review its permission scope.
2. Remove the `sancadmin` backdoor account from all three hosts and force a domain-wide credential reset for `m.smith`, `t.harris`, and `svc_backup`.
3. Onboard Defender XDR token-manipulation events into Sentinel so privilege escalation isn't invisible to the SIEM.
4. Investigate the exfiltration channel for the `keepass.zip` archive staged on GF-WS01.

---

## 2. Incident Overview

| Field | Detail |
|---|---|
| Incident reference | GF-INC-2026-0704 |
| First malicious activity (UTC) | 2026-07-04 08:01:00 |
| Incident detected (UTC) | 2026-07-04 (P1 declared same day, exact detection timestamp not in current telemetry — see Section 3) |
| Dwell time (detection minus first activity) | Not precisely computable — alert-to-declaration time not captured in available logs |
| Investigation started (UTC) | 2026-07-04 |
| Detection source | GF-WS01 alert, MSSP escalation |
| Severity | Critical (P1) |
| Incident type | Intrusion — cloud identity compromise leading to on-prem lateral movement |
| Hosts affected | GF-WS01, GF-SRV01, GF-DC01 |
| Accounts affected / compromised | Azure SP `5deb2a08...`, `sancadmin` (backdoor), `m.smith`, `t.harris`, `svc_backup` (targeted, not confirmed compromised), `GF-SRV01$` |
| Domain / environment | GREENFIELD (Greenfield Logistics) |
| Current status | Contained pending remediation actions above |
| Report prepared by | Danielle R |

---

## 3. Investigation Scope and Data Sources

**In scope:** GF-WS01, GF-SRV01, GF-DC01, window 2026-07-04 10:00 UTC – 2026-07-05 03:00 UTC (per C01 scoping query; the initial Azure-side event at 08:01 UTC falls just before this window and was pulled in via `LAW-Cyber-Range` as a fallback source).

**Data sources used:**
- Microsoft Sentinel workspace `LAW-SilentCorridor` — `WindowsProcess_CL`, `WindowsFile_CL`, `WindowsAuth_CL`, `WindowsRegistry_CL`, `WindowsNetwork_CL`, `WindowsDNS_CL`, `WindowsService_CL`, `WindowsAccountMgmt_CL`
- Microsoft Sentinel workspace `LAW-Cyber-Range` — `AzureActivity`, MDE device tables
- Defender XDR — Device Timeline, `DeviceEvents`, `DeviceProcessEvents`

**Limitations and gaps:**
- **Token-manipulation events** (`ProcessPrimaryTokenModification`) exist only in Defender XDR — `WindowsProcess_CL` has no equivalent event type, so privilege escalation is invisible to the SIEM alone (C05).
- **Command-line detail** is largely absent from Defender XDR's Device Timeline for the credential-access phase — only LAW-SilentCorridor captured full `cmdkey`/`Get-ADUser` command lines (C07).
- **Exfiltration channel unconfirmed:** `keepass.zip` staging is evidenced on GF-WS01, but no DNS or network egress was logged for the host in-window, so the actual transport off-host is not proven (C11).
- **Out-of-window artifact:** a registry modification by `aggregatorhost.exe` on GF-WS01 is timestamped 2026-07-08, four days after the core incident window — it is noted but not asserted as related pending separate scoping.
- **Precise detection timestamp** (alert fired → P1 declared) is not captured in the telemetry reviewed; dwell time in Section 2 is left unresolved rather than estimated.

---

## 4. Timeline of Events

| Time (UTC) | Host | Account | Event | MITRE | Source |
|---|---|---|---|---|---|
| 2026-07-04 08:01:00 | Azure (control plane) | SP `5deb2a08...` | Azure Run Command issued from `4.153.100.221` | T1078 | AzureActivity, LAW-Cyber-Range |
| 2026-07-04 10:01:34.963 | GF-WS01 | NT AUTHORITY\SYSTEM | `cmd /Powershell -ExecutionPolicy Unrestricted -File script49.ps1` | T1059 | WindowsProcess_CL |
| 2026-07-04 10:01:34.997 | GF-WS01 | NT AUTHORITY\SYSTEM | Process chain `cmd.exe → powershell.exe → net.exe` confirmed | T1059 | Defender XDR |
| 2026-07-04 10:01:35.466 | GF-WS01 | NT AUTHORITY\SYSTEM | `net.exe user sancadmin ChangeThis2026fix` | T1136 | WindowsProcess_CL |
| 2026-07-04 10:01:35.783 | GF-WS01 | NT AUTHORITY\SYSTEM | `net.exe user sancadmin /active:yes` | T1136 | WindowsProcess_CL |
| 2026-07-04 10:01:48 | GF-SRV01 | `GF-SRV01$` | Pass-the-Hash authentication from `10.1.0.169` | T1550.002 | WindowsAuth_CL |
| 2026-07-04 09:15:01 | GF-SRV01 | `sancadmin` | `cmdkey /add:GF-SRV01 /user:GREENFIELD\m.smith` | T1555 | WindowsProcess_CL |
| 2026-07-04 10:04:50 | GF-SRV01 | `sancadmin` | `KeePass.exe --preload` launched | T1555 | WindowsProcess_CL |
| 2026-07-04 11:10:00 | GF-SRV01 | `t.harris` | Domain-user authentication from `10.1.0.120` | T1078 | WindowsAuth_CL |
| 2026-07-04 11:10:04 | GF-DC01 | `GF-SRV01$` / `t.harris` | EventID 4768/4769 Kerberos TGT/TGS (Overpass-the-Hash), both routes converge | T1550.003 | WindowsAuth_CL, Defender XDR |
| 2026-07-04 11:10:49 | GF-SRV01 | `t.harris` | SMB file open attempts | T1550.003 | Defender XDR |
| 2026-07-04 11:25:03 | GF-SRV01 | `sancadmin` | `cmdkey /list` enumeration | T1555 | WindowsProcess_CL |
| 2026-07-04 11:32:41 | GF-SRV01 | `sancadmin` | `Get-ADUser svc_backup -Properties Description,ServicePrincipalNames` | T1087 | WindowsProcess_CL |
| 2026-07-04 11:57:54 | GF-SRV01 | `sancadmin` | `cmdkey /list` (repeated) | T1555 | WindowsProcess_CL |
| 2026-07-04 12:08:26 | GF-SRV01 | `sancadmin` | `tasklist \| findstr lsass` | T1003 | WindowsProcess_CL |
| 2026-07-04 ~12:10 [INFERRED window] | GF-WS01 | `sancadmin` | `keepass.zip` archive created | T1560/T1074 | WindowsFile_CL |
| 2026-07-04 21:55:00.341 PM | GF-WS01 | `gf-ws01\sancadmin` | `ProcessPrimaryTokenModification` on `StoreDesktopExtension.exe` | T1134 | Defender XDR |
| 2026-07-04 21:55:00.412 PM | GF-WS01 | NT AUTHORITY\SYSTEM | Token assigned to `CollectGuestLogs.exe` | T1134 | Defender XDR |
| 2026-07-04 21:55:00.500 PM | GF-WS01 | NT AUTHORITY\SYSTEM | `cmd.exe` spawned via named-pipe stdin (`CmdExecutionWithStdInNamedPipe`) | T1574 | WindowsProcess_CL |
| 2026-07-04 [row 959] | GF-SRV01 | `m.smith` | Login from `10.1.0.133` | T1078 | WindowsAuth_CL |
| 2026-07-04 [row 973] | GF-DC01 | `sancadmin` | Backdoor account accesses domain controller | T1078 | WindowsAuth_CL |
| 2026-07-04 [row 1001] | GF-DC01 | (unattributed) | EventID 4771 failed Kerberos pre-auth from `10.1.0.169` — flagged, unresolved | — | WindowsAuth_CL |

---

## 5. Technical Findings

### 5.1 Initial Access

At **2026-07-04 08:01:00 UTC**, Azure activity logs recorded a Run Command operation issued against a Greenfield virtual machine by Service Principal `5deb2a08-7269-47d6-896b-8bc52d396466`, sourced from IP `4.153.100.221` — an address not associated with known corporate egress.

*Evidence:* `AzureActivity` query filtered to `MICROSOFT.COMPUTE/VIRTUALMACHINES/DEALLOCATE/ACTION` (see C02), returning the caller ID and source IP above.

*Interpretation:* Azure Run Command executes natively through the in-guest VM Agent as `NT AUTHORITY\SYSTEM`, requiring no local credential. This bridges a cloud-identity compromise directly into full host takeover — the Service Principal's Contributor-level permissions were sufficient on their own. **Confidence: High** — directly evidenced by Azure management-plane logs and corroborated by matching host-level execution ~2 hours later.

### 5.2 Execution

At **10:01:34.963 UTC**, GF-WS01 recorded `cmd.exe` invoking PowerShell with `-ExecutionPolicy Unrestricted -File script49.ps1`, running as `NT AUTHORITY\SYSTEM`. Defender XDR independently logged the same process chain (`cmd.exe → powershell.exe → net.exe`) at 10:01:34.997 UTC.

*Evidence:* `WindowsProcess_CL` full command line (C02); Defender XDR device timeline process chain (C02).

*Interpretation:* The ~2-hour gap between the 08:01 Azure command and 10:01:34 host execution reflects normal Azure Run Command extension queueing/telemetry latency, not an additional dwell period — both timestamps describe the same action observed at different points in its path. **Confidence: High.**

### 5.3 Persistence

Immediately following payload execution, at **10:01:35 UTC**, the attacker created a local administrator account, `sancadmin`, via `net.exe user sancadmin ChangeThis2026fix` followed by `net.exe user sancadmin /active:yes`.

*Evidence:* `WindowsProcess_CL`, exact command lines and sub-second timestamps (C02).

*Interpretation:* This is textbook backdoor persistence — a locally-created admin account survives the initial exploit chain and gives the attacker standing access independent of the Run Command vector. `sancadmin` reappears in every subsequent phase of the intrusion (C05, C07, C09). **Confidence: High.**

### 5.4 Privilege Escalation

At **21:55:00.341 PM UTC** on 2026-07-04, `sancadmin` triggered a `ProcessPrimaryTokenModification` event against `StoreDesktopExtension.exe`, stealing its access token (`SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`). The stolen token was assigned to `CollectGuestLogs.exe` at 21:55:00.412 PM, which spawned `cmd.exe` as `NT AUTHORITY\SYSTEM` at 21:55:00.500 PM, using a named pipe as stdin.

*Evidence:* Defender XDR `DeviceEvents`/`DeviceProcessEvents` (C05); process chain `services.exe → WaAppAgent.exe → CollectGuestLogs.exe → cmd.exe → conhost.exe`.

*Interpretation:* This technique bypasses standard service-creation and persistence detections entirely — no new service or scheduled task was registered. The named-pipe stdin pattern (`CmdExecutionWithStdInNamedPipe`) is consistent with remote command-execution tooling rather than an interactive operator. **Confidence: High** — directly observed in MDE telemetry, though this event type has no equivalent in the SIEM (see Section 3, Limitations).

### 5.5 Defence Evasion

The privilege-escalation technique in 5.4 avoided detections built around service installation or account/group modification, since it used token theft on an already-legitimate process rather than creating new persistence artefacts. Separately, the `sancadmin` backdoor (5.3) itself represents evasion of change-management controls, since it was created outside any provisioning workflow.

*Interpretation:* The absence of alerting on either technique is itself a finding — see Section 6/11 for the corresponding detection recommendations.

### 5.6 Credential Access

Between **09:15 and 12:08 UTC**, `sancadmin` performed a sequence of credential-harvesting actions on GF-SRV01: adding stored credentials for `GREENFIELD\m.smith` (`cmdkey /add`), launching the KeePass password manager (`KeePass.exe --preload`), repeatedly enumerating stored credentials (`cmdkey /list`), targeting the `svc_backup` service account (`Get-ADUser svc_backup -Properties Description,ServicePrincipalNames`), and finally checking for the LSASS process (`tasklist | findstr lsass`) — consistent with staging for a credential dump.

*Evidence:* Full command-line telemetry from `WindowsProcess_CL` (C07); each action independently timestamped.

*Interpretation:* This is a multi-vector credential-harvesting campaign, not a single tool run — the attacker pursued stored Windows credentials, a third-party password vault, and AD service-account reconnaissance in parallel. **Confidence: High.** Defender XDR did not capture equivalent command-line detail for this phase (Section 3).

### 5.7 Discovery

The `Get-ADUser svc_backup -Properties Description,ServicePrincipalNames` query at 11:32:41 UTC (5.6) doubles as discovery — it is standard Kerberoasting-precursor reconnaissance against a service account, targeting the SPN for later ticket-based cracking. No further discovery activity (broad AD enumeration, network scanning) was identified in the reviewed telemetry.

### 5.8 Lateral Movement

Two independent routes converged on GF-SRV01: the `GF-SRV01$` computer account authenticated via Pass-the-Hash from `10.1.0.169` at 10:01:48 UTC, and the domain user `t.harris` authenticated from `10.1.0.120` at 11:10:00 UTC. Both routes reached GF-DC01 via Kerberos TGT/TGS requests (EventID 4768/4769) at 11:10:04 UTC using Overpass-the-Hash, confirmed independently in Defender XDR. `t.harris` then opened files over SMB on GF-SRV01 at 11:10:49 UTC.

*Evidence:* `WindowsAuth_CL` logon events and Kerberos event IDs; Defender XDR SMB access confirmation (C09).

*Interpretation:* GF-DC01 became the **persistent authentication pivot** for the remainder of the operation — every subsequent Kerberos ticket request from either compromised host flowed through it, and it was later accessed directly by both `m.smith` and the `sancadmin` backdoor. A failed pre-authentication event (4771) from `10.1.0.169` was also logged and remains unresolved — possibly a hash-cracking attempt preceding the successful ticket request, flagged for follow-up. **Confidence: High** on the confirmed routes; **Medium** on the significance of the 4771 failure.

### 5.9 Command and Control

No C2 domains, IPs, or beacon behaviour were identified in the telemetry reviewed for this window. This is a scope limitation, not a finding of absence — DNS logging coverage for the affected hosts is limited (Section 3).

### 5.10 Collection and Exfiltration

`sancadmin` staged harvested credential material into an archive, `keepass.zip`, on GF-WS01 shortly after the credential-enumeration sequence in 5.6 (file-creation event in `WindowsFile_CL`, no exact timestamp captured in the reviewed export).

*Interpretation:* Staging is confirmed via file telemetry; the actual exfiltration transport (DNS tunneling, HTTPS, cloud storage, etc.) is **not evidenced** in currently available logs — no DNS or network egress was found for the host in-window. **Confidence: Medium** on staging intent; **Low/unconfirmed** on whether exfiltration completed and by what channel.

### 5.11 Impact

The attacker achieved SYSTEM-level code execution on GF-WS01, established durable backdoor persistence (`sancadmin`), harvested credentials for at least one domain user (`m.smith`) and staged a password vault for likely exfiltration, and used the domain controller GF-DC01 as a standing authentication pivot. This represents domain-wide exposure, not a single-host compromise: any account with logon rights across GF-SRV01/GF-DC01 during the window should be treated as potentially exposed pending full credential rotation.

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence Reference |
|---|---|---|---|
| Initial Access | T1078 | Valid Accounts (Cloud) | 5.1, AzureActivity 08:01 UTC |
| Execution | T1059 | Command and Scripting Interpreter (PowerShell) | 5.2, WindowsProcess_CL 10:01:34.963 |
| Persistence | T1136 | Create Account | 5.3, WindowsProcess_CL 10:01:35 |
| Privilege Escalation / Defense Evasion | T1134 | Access Token Manipulation | 5.4, Defender XDR 21:55:00.341 PM |
| Persistence / Defense Evasion | T1574 | Hijack Execution Flow | 5.4, WindowsProcess_CL 21:55:00.500 PM |
| Credential Access | T1555 | Credentials from Password Stores | 5.6, WindowsProcess_CL 09:15–11:57 |
| Credential Access | T1003 | OS Credential Dumping (preparation) | 5.6, WindowsProcess_CL 12:08:26 |
| Discovery | T1087 | Account Discovery | 5.7, WindowsProcess_CL 11:32:41 |
| Lateral Movement | T1550.002 | Pass the Hash | 5.8, WindowsAuth_CL 10:01:48 |
| Lateral Movement | T1550.003 | Pass the Ticket / Overpass-the-Hash | 5.8, EventID 4768/4769 11:10:04 |
| Collection / Exfiltration | T1560 / T1074 | Archive Collected Data / Data Staged | 5.10, WindowsFile_CL, `keepass.zip` |

---

## 7. Impact Assessment

- **Systems compromised:** GF-WS01 (initial foothold, SYSTEM execution), GF-SRV01 (lateral movement target), GF-DC01 (domain controller, authentication pivot).
- **Data:** KeePass password vault contents staged for likely exfiltration (transport unconfirmed); `svc_backup` service-account SPN metadata accessed.
- **Accounts to treat as compromised:** `sancadmin` (attacker-created), Azure SP `5deb2a08...`, `m.smith` (stored credentials + login observed), `t.harris` (authenticated to GF-DC01), `GF-SRV01$` machine account. `svc_backup` was targeted for reconnaissance but not confirmed compromised — recommend precautionary rotation.
- **Persistence surviving standard remediation:** the `sancadmin` local admin account and its domain-controller access must be explicitly removed — a password reset alone will not revoke this backdoor.
- **Business/regulatory exposure:** domain-controller access and credential-vault staging suggest potential exposure of broader domain credentials; scope a legal/compliance review if regulated data is stored in the affected environment.
- **Attribution:** Unknown. Tradecraft (Azure Run Command abuse, token theft via signed LOLBins, dual-route lateral movement) suggests an operationally mature actor but is not sufficient alone to attribute to a named group.

---

## 8. Root Cause

The Azure Service Principal used for the initial Run Command held standing Contributor-level permissions without just-in-time scoping or conditional access restrictions, and its credentials were compromised by means not evidenced in the available telemetry (the compromise itself predates this investigation's scope). This single over-privileged, always-on cloud identity was sufficient to bridge directly into SYSTEM-level on-prem code execution — the root enabling condition for the entire intrusion chain that followed.

---

## 9. Indicators of Compromise

| Type | Indicator | Context |
|---|---|---|
| Azure Service Principal | `5deb2a08-7269-47d6-896b-8bc52d396466` | Compromised identity used for Run Command |
| IP address | `4.153.100.221` | Source of Azure Run Command |
| IP address | `10.1.0.169` | Source of GF-SRV01$ Pass-the-Hash |
| IP address | `10.1.0.120` | Source of t.harris authentication |
| IP address | `10.1.0.133` | Source of m.smith login |
| Account | `sancadmin` | Attacker-created backdoor local admin |
| File | `script49.ps1` | Malicious payload executed via Run Command |
| File | `keepass.zip` | Staged credential-vault archive on GF-WS01 |
| File path | `c:\windows\system32\aggregatorhost.exe` | Signed binary tied to registry modification — relevance to this incident unconfirmed (out-of-window) |

---

## 10. Containment, Eradication and Recovery

| Priority | Action | Rationale | Status |
|---|---|---|---|
| 1 | Disable/rotate Azure SP `5deb2a08...`; audit and reduce its role scope | Root-cause identity, still valid unless revoked | Recommended |
| 2 | Remove `sancadmin` account from GF-WS01, GF-SRV01, and GF-DC01 | Confirmed backdoor with domain-controller access | Recommended |
| 3 | Force credential reset for `m.smith`, `t.harris`, `GF-SRV01$` (rejoin/reset machine account), and precautionarily `svc_backup` | All observed authenticating or targeted during the intrusion | Recommended |
| 4 | Hunt for and remove any scheduled tasks/services tied to `CollectGuestLogs.exe`/`StoreDesktopExtension.exe` abuse pattern on other hosts | Confirm no other hosts were escalated via the same LOLBin technique | Recommended |
| 5 | Investigate and confirm/rule out exfiltration transport for `keepass.zip` | Currently unconfirmed — close the visibility gap | Recommended |

---

## 11. Recommendations and Lessons Learned

- **Detection gaps to close:** Azure Run Command from Service Principals outside CI/CD (unalerted); PowerShell execution-policy bypass; local admin account creation; token-manipulation events (`ProcessPrimaryTokenModification`) not onboarded from MDE into Sentinel; named-pipe stdin shell execution; credential-store/password-manager access patterns; AD service-account SPN reconnaissance; LSASS-enumeration prep; Pass-the-Hash/Overpass-the-Hash correlation; Kerberos ticket-volume baselining through GF-DC01. (Full list: remediation-draft.md.)
- **Hardening:** enforce least-privilege/JIT access for Run-Command-capable Service Principals; restrict `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege` to required service accounts only.
- **Visibility improvements:** enable DNS and proxy/network egress logging on GF-WS01 and peer hosts to close the exfiltration-confirmation gap; onboard MDE token-manipulation event types into the SIEM.
- **New detections to author:** rules described above should be implemented as Sentinel analytics rules; each ties directly to a phase in Section 5 and carries low expected false-positive risk given the specificity of the triggering command lines.

---

## 12. Appendices

### A. Queries Used
See KQL blocks embedded in C01, C02, C05, C07, C09, C11.

### B. Artefact Analysis
See artifacts-analysis.md — `aggregatorhost.exe` (signed, VirusTotal 0/69, registry modification out-of-window) and `keepass.zip` (staged archive, exfil unconfirmed).

### C. Evidence and Screenshots
Inline images referenced throughout C02, C05, C07, C09 (Defender process trees, registry-value evidence) and the Defender tamper screenshot in the project root.

---

*This report is the analyst's own investigation of GF-INC-2026-0704 conducted on the
LOG(N) Pacific Cyber Range. All findings are based on telemetry and artefacts from the
Greenfield training estate. This is a simulated incident.*

