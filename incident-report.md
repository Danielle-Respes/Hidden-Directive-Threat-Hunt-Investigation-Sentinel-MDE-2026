# Incident Final Report by Danielle R


**Case Reference:** GF-INC-2026-0704
**Classification:** Internal / Confidential
**Report Status:** Final
**Report Version:** 1.0
**Analyst:** Danielle Respes
**Date of Report (UTC):** 2026-08-01 12:00:00
**Organization:** Greenfield Logistics

Full query/screenshot evidence log: [screenshots.md](./screenshots.md)

---

## 1. Executive Summary

There was a break-in at Greenfield Logistics!

One company computer and one attacker who worked their way up to admin-level access stole passwords and then was able to control the entire company's system. This all happened between **2026-07-04 08:01 UTC** and **2026-07-05 03:00 UTC**.

Once in, they stole a user's account. Why is this significant? This activity made them immune to password changes, allowing them to always have a door into Greenfield's systems. With this new access, they could then blend in, disguised as a Microsoft process. Now that they have the master key to accounts and servers, they can easily stay off the radar, keeping their presence quiet and constant. Did they successfully ship out company data? **TBD**

**When it happened:** At first, I thought it started at **2026-07-04 08:01:00 UTC**. That was the first sign of malicious activity, when the attacker used a stolen cloud ID to run a script remotely, which automatically gave them full system-level access. Then I had to dive back into 2 different logs (Sentinel & Defender). I discovered that the `sancadmin` account was already an established account on computer GF-WS01, as of **2026-07-03 00:45:57 UTC**. At some point, it became the attacker's backdoor — I'm still trying to pinpoint when.

There was also a separate high-severity alert, which renamed files, at **2026-07-04 00:11:33 UTC**. I'm still investigating this, as I haven't nailed down how these connect yet, so I will confirm a final start time later.

**How long they were in:** They were at least in the system over 30 hours, from **2026-07-03 00:45:57 UTC** to **2026-07-05 03:00:00 UTC**.
> Confidence: Medium — the evidence is real; I just haven't cross-checked it against every other log yet.

**What they got into:** One computer, a server, and then a Domain Controller — since they had the master key to every account, they grabbed passwords, and this was all made to look like a normal Windows process, and therefore unnoticeable when they shipped out the data.
> Confidence: High on access reached; Medium on data being shipped out — it looks like it, but still working on getting solid proof.

**What needs to happen now:** Lock the stolen cloud login, investigate the `sancadmin` account, reset passwords within the company, and confirm if data really got out or not.

---

## 2. Incident Overview

| Field | Detail |
|---|---|
| Incident reference | GF-INC-2026-0704 |
| First malicious activity (UTC) | 2026-07-03 00:45:57 (unconfirmed as malicious — earliest reference to the sancadmin account/profile; see note below) |
| Incident detected (UTC) | Not confirmed — earliest matching Sentinel alert found is 2026-07-04 00:11:33, but detection (analyst/SOC becoming aware) timestamp is not captured in reviewed telemetry |
| Dwell time (detection minus first activity) | Not calculable — detection timestamp unconfirmed |
| Investigation started (UTC) | 2026-07-04 |
| Detection source | GF-WS01 alert, MSSP escalation |
| Severity | Critical |
| Incident type | Intrusion — cloud identity compromise leading to on-prem lateral movement |
| Hosts affected | GF-WS01, GF-SRV01, GF-DC01 |
| Accounts affected / compromised | Azure SP `5deb2a08...`, `sancadmin` (pre-existing account, takeover point unconfirmed), `m.smith`, `t.harris`, `svc_backup` (targeted, not confirmed compromised) |
| Domain / environment | GREENFIELD (Greenfield Logistics) |
| Current status | Contained pending remediation |
| Report prepared by | Danielle R, SOC Analyst |

> **Note:** "First malicious activity" is updated to **2026-07-03 00:45:57 UTC** — the earliest confirmed reference to the `sancadmin` account/profile on GF-WS01 — earlier than the 2026-07-04 08:01:00 UTC Azure Run Command previously used. This does not yet confirm malicious intent at that exact timestamp, only that the account existed and was in use before the incident window; the point of actual takeover is still unconfirmed (see Executive Summary).

---

## 3. Investigation Scope and Data Sources

**In scope:**
- Hosts: GF-WS01, GF-SRV01, GF-DC01
- Time window: 2026-07-03 00:00:00 UTC – 2026-07-05 03:00:00 UTC (expanded from the original 2026-07-04 10:00–2026-07-05 03:00 UTC window in C01, once Sentinel and Defender showed sancadmin activity starting earlier than I thought)
- Question: how did the attacker get in, what did they touch, and how far did they reach across the domain?

**Data sources used:**
- Microsoft Sentinel, `LAW-SilentCorridor` — WindowsProcess_CL, WindowsFile_CL, WindowsAuth_CL, WindowsRegistry_CL, WindowsNetwork_CL, WindowsDNS_CL, WindowsService_CL, WindowsAccountMgmt_CL
- Microsoft Sentinel, `LAW-Cyber-Range` — AzureActivity, MDE device tables
- Microsoft Defender Advanced Hunting — DeviceProcessEvents, DeviceRegistryEvents, DeviceEvents
- Sentinel alert/incident queues, pulled as a scheduled-alerts CSV export

**Limitations and gaps:**
- SecurityAlert/SecurityIncident didn't return anything directly in either workspace, so I pulled alert and incident data through a scheduled-alerts export instead. I don't have the exact query lineage documented for those two CSVs.
- No confirmed detection timestamp anywhere — only when alerts were generated and that a P1 was declared same-day. Because of that, I couldn't calculate dwell time in Section 2.
- AzureActivity in LAW-Cyber-Range for sancadmin/GF-WS01 returned zero results. No cloud-side telemetry backs up what I'm seeing on the host, so I can't confirm from Azure logs whether sancadmin was created, already existed, or exactly when it was taken over.
- Token-manipulation events only show up in Defender Advanced Hunting — WindowsProcess_CL has no equivalent event type, so privilege escalation isn't visible from the SIEM alone.
- Full command-line detail for the credential-access phase was in WindowsProcess_CL but mostly missing from the Defender Device Timeline.
- No DNS or network-egress logs for GF-WS01 in this window, so I can't establish how (or if) the keepass.zip archive actually left the network — staging is confirmed, exfiltration isn't.
- A registry modification by aggregatorhost.exe on GF-WS01, dated 2026-07-08, is four days outside my window. Noting it, not claiming it's related.
- sancadmin was already an established account on GF-WS01 as of 2026-07-03 00:45:57 UTC, well before the incident window. I believe this account was taken over rather than newly created, but haven't pinpointed the exact moment of takeover — flagging this as an open gap, not fact.
- I still haven't fully reconciled how the 00:45:57 UTC sancadmin reference, the 00:11:33 UTC mass-file-rename alert, and the 08:01:00 UTC Azure Run Command all connect into one timeline.

---

## 4. Timeline of Events

| Time (UTC) | Host | Account | Event | MITRE | Source |
|---|---|---|---|---|---|
| 2026-07-03 00:45:57 | GF-WS01 | GF-WS01$ / NT AUTHORITY\SYSTEM | cmd.exe runs `dir` against `C:\Users\sancadmin\AppData\Local\Temp` — confirms sancadmin profile already exists | — | WindowsProcess_CL |
| 2026-07-03 20:03:53 | GF-WS01 | sancadmin | Running normal desktop-session processes (explorer.exe, OneDrive, etc.) | — | DeviceProcessEvents (Defender) |
| 2026-07-03 20:04:51–20:06:16 | GF-WS01 | sancadmin | Registry key/value deletions tied to sancadmin's profile | — | DeviceRegistryEvents (Defender) |
| 2026-07-04 00:11:33 | GF-WS01 | (unattributed) | "Mass File Rename (Ransomware Indicator)" alert fires — link to rest of timeline [INFERRED, unconfirmed] | — | Sentinel scheduled-alerts export |
| 2026-07-04 02:07:56 | GF-WS01 | GREENFIELD\sancadmin | "Ingress transfer... CertUtil-URLCache by GREENFIELD\sancadmin" | T1105 | Sentinel scheduled-alerts export |
| 2026-07-04 08:01:00 | Azure (control plane) | SP 5deb2a08... | Azure Run Command issued from 4.153.100.221 | T1078 | AzureActivity, LAW-Cyber-Range |
| 2026-07-04 10:01:34.963 | GF-WS01 | NT AUTHORITY\SYSTEM | cmd /Powershell -ExecutionPolicy Unrestricted -File script49.ps1 | T1059 | WindowsProcess_CL |
| 2026-07-04 10:01:35.466 | GF-WS01 | NT AUTHORITY\SYSTEM | net.exe user sancadmin ChangeThis2026fix (password reset on existing account, not creation) | T1098 | WindowsProcess_CL |
| 2026-07-04 10:01:48 | GF-SRV01 | GF-SRV01$ | Pass-the-Hash authentication from 10.1.0.169 | T1550.002 | WindowsAuth_CL |
| 2026-07-04 09:15:01 | GF-SRV01 | sancadmin | cmdkey /add:GF-SRV01 /user:GREENFIELD\m.smith | T1555 | WindowsProcess_CL |
| 2026-07-04 10:04:50 | GF-SRV01 | sancadmin | KeePass.exe --preload launched | T1555 | WindowsProcess_CL |
| 2026-07-04 11:10:00 | GF-SRV01 | t.harris | Domain-user authentication from 10.1.0.120 | T1078 | WindowsAuth_CL |
| 2026-07-04 11:10:04 | GF-DC01 | GF-SRV01$ / t.harris | EventID 4768/4769 Kerberos TGT/TGS (Overpass-the-Hash), both routes converge | T1550.003 | WindowsAuth_CL, Defender XDR |
| 2026-07-04 11:10:49 | GF-SRV01 | t.harris | SMB file open attempts | T1550.003 | Defender XDR |
| 2026-07-04 11:32:41 | GF-SRV01 | sancadmin | Get-ADUser svc_backup -Properties Description,ServicePrincipalNames | T1087 | WindowsProcess_CL |
| 2026-07-04 11:49:19 | GF-WS01 | sancadmin | Scheduled task created by GF-WS01\sancadmin | T1053 | Sentinel scheduled-alerts export |
| 2026-07-04 12:08:26 | GF-SRV01 | sancadmin | tasklist \| findstr lsass | T1003 | WindowsProcess_CL |
| 2026-07-04 21:55:00.341 | GF-WS01 | gf-ws01\sancadmin | ProcessPrimaryTokenModification on StoreDesktopExtension.exe | T1134 | Defender XDR |
| 2026-07-04 21:55:00.500 | GF-WS01 | NT AUTHORITY\SYSTEM | cmd.exe spawned via named-pipe stdin | T1574 | WindowsProcess_CL |

> **Note:** Two events are still [INFERRED]/unresolved — the 00:11:33 mass-file-rename alert's link to this chain, and the exact moment sancadmin was taken over versus legitimately used (see Sections 1 and 3).

---

## 5. Technical Findings

The attacker used a stolen cloud ID to run a process on computer GF-WS01, used an existing account (sancadmin), and then moved to server GF-SRV01 using 2 paths, then GF-DC01 — which gave them domain-wide access — grabbed credentials, and I'm still confirming if data was sent out.

### 5.1 Initial Access

At **2026-07-04 08:01:00 UTC**, Azure logged a Run Command operation against GF-WS01, issued by Service Principal `5deb2a08-7269-47d6-896b-8bc52d396466` from IP `4.153.100.221` — an address I don't recognize as belonging to Greenfield.

*Evidence:* I ran a query in Microsoft Sentinel, LAW-Cyber-Range, filtered for the Run command, and it returned the caller ID and source IP above (C02).

*Interpretation:* Run Command is a built-in Azure feature that runs code straight on the machine as the system's own admin account (NT AUTHORITY\SYSTEM). That means stealing the cloud identity alone was enough to fully take over the host. I'm confident in this one; it's right there in the Azure logs, and it lines up with what happened on the host about two hours later.

### 5.2 Execution

At **10:01:34.963 UTC**, GF-WS01 shows cmd.exe launching PowerShell with `-ExecutionPolicy Unrestricted -File script49.ps1`, running as NT AUTHORITY\SYSTEM. Defender logged the same chain (cmd.exe → powershell.exe → net.exe) at 10:01:34.997 UTC.

*Evidence:* WindowsProcess_CL command line + Defender device timeline, both matching within a fraction of a second (C02).

*Interpretation:* The ~2-hour gap between the 08:01 Azure command and the 10:01:34 execution is just normal delay — it takes time for Azure to actually deliver the command to the machine and get it running. Same event, just seen from two different places.

### 5.3 Persistence

At **10:01:35 UTC**, `net.exe user sancadmin ChangeThis2026fix` followed by `net.exe user sancadmin /active:yes` ran on GF-WS01. Originally I read this as the attacker creating a brand-new backdoor account — but I've since found that sancadmin already had a user profile on GF-WS01 as far back as **2026-07-03 00:45:57 UTC** (WindowsProcess_CL, `C:\Users\sancadmin\AppData\Local\Temp` referenced in a cmd.exe process). So this command is more likely a password reset on an existing account, not a brand-new one.

*Evidence:* WindowsProcess_CL exact command lines and timestamps (C02); earlier profile reference in the same table (Section 3 gap notes).

*Interpretation:* Resetting the password still gives the attacker a way back in whenever they want — that's still persistence. I just don't know yet whose account this originally was or exactly when it got taken over. I'm flagging that as unresolved instead of guessing.

### 5.4 Privilege Escalation

At **21:55:00.341 UTC**, sancadmin triggered a `ProcessPrimaryTokenModification` event against `StoreDesktopExtension.exe`. The stolen token was assigned to `CollectGuestLogs.exe` at 21:55:00.412, which spawned cmd.exe as NT AUTHORITY\SYSTEM at 21:55:00.500, using a named pipe as stdin.

*Evidence:* Defender DeviceEvents/DeviceProcessEvents (C05); process chain services.exe → WaAppAgent.exe → CollectGuestLogs.exe → cmd.exe → conhost.exe.

*Interpretation:* Basically, the attacker borrowed the "keys" (permissions) from a process that already had full system access, instead of setting up something new that security tools would notice. No new service or task got created, so the usual alarms didn't go off. I'm confident in this one — it's straight from Defender — though it doesn't show up the same way in the SIEM (see Section 3).

### 5.5 Defence Evasion

The token-theft trick in 5.4 avoided the usual alerts because it didn't install anything new — it just reused a process that was already trusted. The password reset on the existing sancadmin account (5.3) works the same way — no "new account created" alert fires, because the account was already there.

*Interpretation:* Neither of these things tripped an alarm, which is worth calling out on its own — I go into that more in Section 11.

### 5.6 Credential Access

Between **09:15 and 12:08 UTC**, sancadmin ran a sequence of credential-harvesting actions on GF-SRV01: added stored credentials for GREENFIELD\m.smith (`cmdkey /add`), launched KeePass (`KeePass.exe --preload`), checked stored credentials repeatedly (`cmdkey /list`), targeted the svc_backup service account (`Get-ADUser svc_backup -Properties Description,ServicePrincipalNames`), and looked for the LSASS process (`tasklist | findstr lsass`).

*Evidence:* Full command-line telemetry from WindowsProcess_CL (C07), each independently timestamped.

*Interpretation:* This wasn't one tool run once — it's several different ways of grabbing passwords, back to back: saved Windows logins, a password vault, and info about a service account. Defender didn't pick up the same level of command-line detail for this part (Section 3).

### 5.7 Discovery

The `Get-ADUser svc_backup -Properties Description,ServicePrincipalNames` query at 11:32:41 doubles as reconnaissance — it's a standard first step before trying to crack a service account's password (Kerberoasting). I didn't find any wider network scanning or account sweeps in what I reviewed.

### 5.8 Lateral Movement

Two separate paths led to GF-SRV01: the GF-SRV01$ computer account got in using a stolen password hash from 10.1.0.169 at 10:01:48, and the domain user t.harris logged in from 10.1.0.120 at 11:10:00. Both then reached GF-DC01 through Kerberos ticket requests (4768/4769) at 11:10:04, using a similar hash-based trick. Defender confirmed this independently. t.harris then opened files over the network on GF-SRV01 at 11:10:49.

*Evidence:* WindowsAuth_CL logon events and Kerberos event IDs; Defender SMB access confirmation (C09).

*Interpretation:* GF-DC01 ended up as the central point every later login ran through — once the attacker had that, they could reach almost anything. I'm confident about the two paths in; less sure about a failed login attempt (event 4771) from the same IP that I haven't figured out yet.

### 5.9 Command and Control

I didn't find any outside servers, IPs, or check-in traffic the attacker might have used to control things remotely, in what I reviewed. That doesn't mean it didn't happen — it just means the DNS/network logging I have access to for these hosts is limited (Section 3).

### 5.10 Collection and Exfiltration

sancadmin bundled up harvested credential material into `keepass.zip` on GF-WS01 shortly after the credential-grabbing activity in 5.6.

*Interpretation:* I can confirm the file was created and packaged — that part's solid. Whether it actually left the network, and how, I can't confirm — there's no matching internet/network traffic for this host in this window. This is the "Did they successfully ship out company data? TBD" from my Executive Summary.

### 5.11 Impact

The attacker got full system-level access on GF-WS01, reset the password on an existing account (sancadmin) to keep a way back in, grabbed at least one domain user's credentials, packaged up a password vault for likely exfiltration, and used the domain controller as their hub for everything after that. This isn't just one machine — any account that logged into GF-SRV01 or GF-DC01 during this window should be treated as potentially exposed until passwords are reset.

---

## 6. MITRE ATT&CK Mapping

| C0# | Tactic | Technique ID | Technique Name | Evidence Reference |
|---|---|---|---|---|
| C02 | Initial Access | T1078 | Valid Accounts (Cloud) | See 5.1, AzureActivity 08:01:00 UTC |
| C02 | Execution | T1059 | Command and Scripting Interpreter (PowerShell) | See 5.2, WindowsProcess_CL 10:01:34.963 UTC |
| C02, C04 | Persistence | T1098* | Account Manipulation (password reset on existing account, not new account creation) | See 5.3, WindowsProcess_CL 10:01:35 UTC |
| C05 | Privilege Escalation / Defense Evasion | T1134 | Access Token Manipulation | See 5.4, Defender DeviceEvents 21:55:00.341 UTC |
| C05 | Defense Evasion | T1574 | Hijack Execution Flow | See 5.4, WindowsProcess_CL 21:55:00.500 UTC |
| C07 | Credential Access | T1555 | Credentials from Password Stores | See 5.6, WindowsProcess_CL 09:15–11:57 UTC |
| C07 | Credential Access | T1003 | OS Credential Dumping (preparation only) | See 5.6, WindowsProcess_CL 12:08:26 UTC |
| C08 | Discovery | T1087 | Account Discovery | See 5.7, WindowsProcess_CL 11:32:41 UTC |
| C09 | Lateral Movement | T1550.002 | Pass the Hash | See 5.8, WindowsAuth_CL 10:01:48 UTC |
| C09 | Lateral Movement | T1550.003 | Pass the Ticket / Overpass-the-Hash | See 5.8, EventID 4768/4769 11:10:04 UTC |
| C11 | Collection | T1560 | Archive Collected Data | See 5.10, keepass.zip staged, WindowsFile_CL |

\* T1098 replaces the T1136 (Create Account) label used elsewhere in the repo — per [screenshots.md](./screenshots.md), sancadmin was found to already exist on GF-WS01 as of 2026-07-03 00:45:57 UTC, so this is account takeover/password reset, not new account creation.

> **Note:** I'm not including an Exfiltration technique row (like T1041) — I can't confirm data actually left the network yet, only that it was staged. Adding that row would be asserting more than the evidence supports (see [screenshots.md](./screenshots.md) #7 for why this differs from the live repo's C11).

---

## 7. Impact Assessment

**Systems compromised:** GF-WS01 (the initial foothold — where the attacker got in), GF-SRV01 (a company server), and GF-DC01 — the domain controller. That last one manages logins for every account in the company, so this isn't a one-machine problem.

**Data:** The KeePass password vault was packaged up (`keepass.zip`) on GF-WS01. Whether it actually left the network, I can't confirm yet — no matching network traffic to prove exfiltration (see 5.10). The `svc_backup` service account's metadata was also queried/targeted.

**Accounts and credentials that need to be treated as compromised:** the Azure Service Principal used for initial access, `sancadmin` (still figuring out the takeover point — see 5.3), `m.smith` (stored credentials + login activity), `t.harris` (authenticated into GF-DC01), and the `GF-SRV01$` machine account. `svc_backup` was targeted but I haven't confirmed it was actually compromised — I'd still reset it out of caution.

**Persistence that survives a normal password reset:** The `sancadmin` account itself is the concern here — since it's an existing account that got taken over (not newly created), just resetting passwords company-wide won't necessarily lock the attacker out if they still have another way to get back into that account or something tied to it. This needs to be manually reviewed and removed, not assumed gone after a reset.

**Business/legal/regulatory exposure:** Given the domain controller was reached, any regulated data stored in this environment should get a compliance review. I don't have enough information from this investigation alone to say what data types are actually affected.

**Attribution:** Unknown. I don't have enough here to point to a specific group or campaign — the techniques used (cloud identity abuse, token theft, hash-based lateral movement) are common enough that I'm not going to guess.

---

## 8. Root Cause

The primary weakness: the Azure Service Principal used for initial access had enough standing permission to run commands directly on GF-WS01, with no extra approval step or restriction on where those commands could come from. Once that cloud identity was compromised, there was nothing else standing between the attacker and full system access on the host — Run Command did the rest automatically.

**Contributing factors:**
- Whatever compromised the Service Principal's credentials happened before this investigation's window, so I can't say how that initial theft occurred.
- PowerShell's execution policy could be bypassed outright (`-ExecutionPolicy Unrestricted`), so once code was running, nothing stopped it from doing whatever it wanted.
- The `sancadmin` account (existing or not) had local admin rights that let it reset its own password and use it for persistence without needing a fresh account.

The Service Principal's excessive standing access is the primary root cause — everything else in this incident depended on the attacker getting that first foothold, and that permission is what made the foothold possible.

---

## 9. Indicators of Compromise

| Type | Indicator | Context |
|---|---|---|
| Azure Service Principal | `5deb2a08-7269-47d6-896b-8bc52d396466` | Compromised identity used to issue the initial Run Command (5.1) |
| IP address | `4.153.100.221` | Source of the Azure Run Command (5.1) |
| IP address | `10.1.0.169` | Source of GF-SRV01$ Pass-the-Hash into GF-SRV01/GF-DC01 (5.8) |
| IP address | `10.1.0.120` | Source of t.harris authentication into GF-SRV01 (5.8) |
| File path | `script49.ps1` | Payload executed via Run Command on GF-WS01 (5.2) |
| File path | `C:\Users\sancadmin\AppData\Local\Temp` | Confirms sancadmin's profile existed on GF-WS01 before the incident window (5.3) |
| File path | `keepass.zip` (GF-WS01) | Staged credential-vault archive (5.10) |
| Account | `sancadmin` | Pre-existing account, taken over/reactivated as persistence (5.3) |
| Account | `m.smith` | Stored credentials targeted, login activity observed (5.6, 5.8) |
| Account | `t.harris` | Domain account used for lateral movement into GF-DC01 (5.8) |
| Account | `svc_backup` | Service account targeted for AD reconnaissance, not confirmed compromised (5.7) |
| Account | `GF-SRV01$` | Machine account used for Pass-the-Hash (5.8) |
| Process | `StoreDesktopExtension.exe` → `CollectGuestLogs.exe` | Token-theft chain used for privilege escalation (5.4) |

I'm leaving File hash (SHA-256), Domain, Scheduled task/service, and Registry key blank — I don't have confirmed evidence for any of those categories in this investigation. Adding placeholder values there would be guessing.

---

## 10. Containment, Eradication and Recovery

| Priority | Action | Rationale | Status |
|---|---|---|---|
| 1 | Disable/rotate the Azure Service Principal `5deb2a08-7269-47d6-896b-8bc52d396466` and reduce its permission scope | This is the root cause — it's how the attacker got in, and it's still valid unless revoked | Recommended |
| 2 | Reset the `sancadmin` account password and review what it has access to on GF-WS01, GF-SRV01, and GF-DC01 | It's an existing account that was taken over — a normal password reset alone might not fully lock the attacker out | Recommended |
| 3 | Force a credential reset for `m.smith`, `t.harris`, and the `GF-SRV01$` machine account | All three were observed authenticating or being targeted during the intrusion | Recommended |
| 4 | Reset `svc_backup` as a precaution, even though it wasn't confirmed compromised | It was targeted for reconnaissance — better to rotate than assume it's fine | Recommended |
| 5 | Investigate whether `keepass.zip` actually left the network, and how | Currently unconfirmed — closes an open gap | Recommended |
| 6 | Review GF-WS01, GF-SRV01, and GF-DC01 for any other scheduled tasks, services, or accounts tied to this activity | I don't have full confidence I've found everything — a manual sweep catches what telemetry review might've missed | Recommended |

---

## 11. Recommendations and Lessons Learned

**Detection gaps found:**
- Azure Run Command from a Service Principal outside CI/CD went completely unalerted. Should be flagged, especially from an unrecognized source IP.
- PowerShell's execution-policy bypass (`-ExecutionPolicy Unrestricted`) didn't trigger anything either.
- Password resets on existing local admin accounts (like what happened to sancadmin) aren't monitored the same way account creation is — a real blind spot, since it mattered here.
- The token-theft technique in 5.4 only shows up in Defender, not in the SIEM — anyone relying on Sentinel alone would've missed privilege escalation entirely.
- Credential-store enumeration (`cmdkey /list`) and password-manager access weren't flagged.
- AD reconnaissance against `svc_backup` (SPN query) wasn't flagged — a standard Kerberoasting precursor that should be.

**Hardening changes that would have slowed or blocked this:**
- Scope the Service Principal down to only what it needs, and require just-in-time access instead of standing Contributor rights.
- Restrict who can reset local admin account passwords, and alert on it when it happens outside normal IT workflows.
- Enforce execution-policy restrictions that can't just be bypassed with a flag.

**New detections I'd write from this:**
- A rule alerting on Run Command usage from Service Principals not tied to known CI/CD pipelines. False-positive risk: medium — needs an allow-list for legitimate automation.
- A rule correlating a password reset on a local admin account with unusual login activity right afterward. False-positive risk: medium — needs tuning against known helpdesk activity.
- A rule for `cmdkey /list` or `/add` combined with a password-manager process launching from the same account within a short window. False-positive risk: low-medium.

**Visibility gaps to fix:**
- No DNS or network-egress logging on GF-WS01 — the reason I couldn't confirm whether `keepass.zip` actually left the network. Needs to be turned on.
- Token-manipulation events need to be pulled into Sentinel from Defender, not left MDE-only — the reason privilege escalation had no SIEM visibility at all.

---

## 12. Appendices

### A. Queries Used

**AzureActivity (LAW-Cyber-Range)** — supports 5.1
```
AzureActivity
| where OperationName == "MICROSOFT.COMPUTE/VIRTUALMACHINES/DEALLOCATE/ACTION"
| where Caller == "5deb2a08-7269-47d6-896b-8bc52d396466"
| where CallerIpAddress == "4.153.100.221"
```

**WindowsProcess_CL — script49.ps1 execution (LAW-SilentCorridor)** — supports 5.2
```
WindowsProcess_CL
| where DvcHostname == "GF-WS01.greenfield.local"
| where TargetProcessCommandLine contains "script49.ps1"
| where ActorUsername == "NT AUTHORITY\SYSTEM"
```

**WindowsProcess_CL — sancadmin password reset (LAW-SilentCorridor)** — supports 5.3
```
WindowsProcess_CL
| where DvcHostname == "GF-WS01.greenfield.local"
| where TargetProcessCommandLine has_any ("net user sancadmin", "net localgroup")
```

**WindowsProcess_CL — sancadmin pre-existing profile check (LAW-SilentCorridor)** — supports 5.3, screenshots.md #4
```
WindowsProcess_CL
| where DvcHostname has "GF-WS01"
| where TargetProcessCommandLine has "sancadmin"
| where TimeGenerated between (datetime(2026-07-03 00:00:00) .. datetime(2026-07-04 23:59:59))
```

**DeviceProcessEvents / DeviceRegistryEvents (Defender Advanced Hunting)** — supports 5.4, screenshots.md #2/#3
```
DeviceProcessEvents
| where DeviceName has "GF-WS01"
| where Timestamp between (datetime(2026-07-04 00:00:00) .. datetime(2026-07-04 12:00:00))
```

**WindowsAuth_CL — lateral movement / Kerberos (LAW-SilentCorridor)** — supports 5.8
```
WindowsAuth_CL
| where EventID in (4768, 4769, 4771)
| where DvcHostname == "GF-DC01.greenfield.local"
```

**AzureActivity — sancadmin cloud-side cross-check (LAW-Cyber-Range)** — supports Section 3 gap, screenshots.md #5
```
AzureActivity
| where Caller has "sancadmin" or ResourceGroup has "GF-WS01"
```
Result: no rows returned.

### B. Artefact Analysis

**`keepass.zip`**
- Type: Archive
- Notes: Created on GF-WS01 after the credential-harvesting sequence in 5.6; confirmed via file-creation telemetry (WindowsFile_CL); no matching network egress found, so I can't confirm it left the host

I don't have a recovered malware binary with a hash, strings, or behavioral analysis in this investigation's evidence — I'm not filling this in with anything I haven't actually examined.

### C. Evidence and Screenshots

See [screenshots.md](./screenshots.md) for the full log of query exports and what each one supports — entries 1 through 7, each tied to the phase doc(s) and finding it backs up.

---

*This report is the analyst's own investigation of GF-INC-2026-0704 conducted on the LOG(N) Pacific Cyber Range. All findings are based on telemetry and artefacts from the Greenfield training estate. This is a simulated incident.*
