# Detection Pack — GF-INC-2026-0704

Rules authored from this investigation's findings, covering techniques that did **not** alert during the incident. Query language: KQL (Sentinel Analytics Rules).

---

### 1. Azure Run Command from a Service Principal outside CI/CD

**Covers:** T1078 (Valid Accounts, Cloud) — Section 5.1

```kql
AzureActivity
| where OperationNameValue == "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION"
| where CallerIpAddress !in (KnownCiCdRunnerIPs)
| where Caller has "-" // Service Principal GUIDs, not UPNs
| project TimeGenerated, Caller, CallerIpAddress, ResourceId
```

**False-positive risk:** Medium — legitimate break-glass or admin tooling may also use Run Command outside CI/CD.
**Tuning:** Maintain an allow-list of known automation IPs/SPs (`KnownCiCdRunnerIPs`, `KnownAutomationSPs`); alert only on SPs not in either list, and raise severity if the target VM is a domain-joined production host.

---

### 2. PowerShell execution-policy bypass

**Covers:** T1059 (Command and Scripting Interpreter) — Section 5.2

```kql
WindowsProcess_CL
| where TargetProcessCommandLine has_any ("-ExecutionPolicy Bypass", "-ExecutionPolicy Unrestricted", "-ep bypass")
| where ActorUsername == "NT AUTHORITY\\SYSTEM" or ActorUsername has "$"
| project TimeGenerated, DvcHostname, ActorUsername, TargetProcessCommandLine
```

**False-positive risk:** Medium — some legitimate deployment/config-management scripts (SCCM, DSC) use bypass flags.
**Tuning:** Exclude known management-tool parent processes (e.g. `ccmexec.exe`); prioritize alerts where the parent process is `cmd.exe` spawned from a remote-execution context (Run Command extension, WinRM) rather than a scheduled task.

---

### 3. Local admin account creation + immediate activation

**Covers:** T1136 (Create Account) — Section 5.3

```kql
WindowsProcess_CL
| where TargetProcessCommandLine has_any ("net user", "net localgroup administrators")
| summarize Events = make_set(TargetProcessCommandLine), Count = count() by DvcHostname, ActorUsername, bin(TimeGenerated, 5m)
| where Count >= 2
```

**False-positive risk:** Low — chained account-creation + admin-group-add + activation within minutes is rare in normal IT operations.
**Tuning:** Exclude documented provisioning windows tied to a change ticket (join to a CMDB change-request table if available); alert immediately otherwise.

---

### 4. Access token manipulation (MDE-only today)

**Covers:** T1134 (Access Token Manipulation) — Section 5.4

```kql
DeviceEvents
| where ActionType == "ProcessPrimaryTokenModification"
| where InitiatingProcessAccountName !endswith "$" // exclude machine-account service noise
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FileName
```

**False-positive risk:** Medium-high without tuning — some legitimate service-hosting patterns (e.g. IIS app pool recycling) trigger token operations.
**Tuning:** Baseline normal token-modification pairs per host (source process → target process) over 30 days; alert only on **new** pairings not seen in the baseline, and require this rule to feed Sentinel via the Defender XDR connector so it isn't MDE-only blind spot (see Section 3 of the report).

---

### 5. Named-pipe stdin shell execution

**Covers:** T1574 (Hijack Execution Flow) — Section 5.4

```kql
WindowsProcess_CL
| where TargetProcessCommandLine has "cmd.exe" or TargetProcessCommandLine has "powershell.exe"
| where AdditionalFields has "CmdExecutionWithStdInNamedPipe" // or equivalent MDE detection tag if surfaced via connector
| project TimeGenerated, DvcHostname, ActorUsername, TargetProcessCommandLine
```

**False-positive risk:** Low — this execution pattern is uncommon outside remote-tooling/RAT usage.
**Tuning:** If the field isn't natively exposed via current connectors, request MDE schema enrichment; until then, treat this as a hunting query rather than a live rule.

---

### 6. Credential-store enumeration + password-manager access in sequence

**Covers:** T1555 (Credentials from Password Stores) — Section 5.6

```kql
WindowsProcess_CL
| where TargetProcessCommandLine has_any ("cmdkey /list", "cmdkey /add")
   or TargetProcessCommandLine has "KeePass.exe"
| summarize Actions = make_set(TargetProcessCommandLine), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by DvcHostname, ActorUsername
| where FirstSeen != LastSeen // more than one action in sequence
```

**False-positive risk:** Low-medium — help-desk credential resets could trigger `cmdkey /add`; KeePass usage alone is common for legitimate users.
**Tuning:** Alert only when `cmdkey` and a password-manager process appear from the **same actor within a short window** (e.g. 2 hours), as seen in this incident; suppress single isolated KeePass launches.

---

### 7. AD service-account SPN reconnaissance (Kerberoasting precursor)

**Covers:** T1087 (Account Discovery) — Section 5.7

```kql
WindowsProcess_CL
| where TargetProcessCommandLine has "Get-ADUser" and TargetProcessCommandLine has "ServicePrincipalNames"
| where ActorUsername != "svc_adAudit" // exclude known legitimate audit tooling
| project TimeGenerated, DvcHostname, ActorUsername, TargetProcessCommandLine
```

**False-positive risk:** Medium — legitimate AD administration and auditing tools query SPNs routinely.
**Tuning:** Exclude a maintained allow-list of AD-admin/audit service accounts; escalate severity if the querying account is not a member of the Domain Admins/Account Operators group.

---

### 8. LSASS enumeration preceding dump tooling

**Covers:** T1003 (OS Credential Dumping — preparation) — Section 5.6

```kql
WindowsProcess_CL
| where TargetProcessCommandLine has "tasklist" and TargetProcessCommandLine has "lsass"
| project TimeGenerated, DvcHostname, ActorUsername, TargetProcessCommandLine
```

**False-positive risk:** Low — `tasklist | findstr lsass` has almost no legitimate administrative use case.
**Tuning:** None needed to reduce noise; consider raising to high severity by default and auto-isolating the host pending triage.

---

### 9. Pass-the-Hash / Overpass-the-Hash correlation

**Covers:** T1550.002 / T1550.003 — Section 5.8

```kql
WindowsAuth_CL
| where EventID in (4768, 4769)
| join kind=inner (
    WindowsAuth_CL
    | where EventID == 4771
) on DvcHostname
| where TimeGenerated1 between (TimeGenerated - 5m .. TimeGenerated + 5m)
| project TimeGenerated, DvcHostname, SourceIp, EventID, EventID1
```

**False-positive risk:** Medium — repeated failed pre-auth followed by success can also reflect normal password-typo retries.
**Tuning:** Scope to **machine-account** (`$`) callers and non-interactive source IPs (servers, not user workstations) to reduce noise; this is the pattern that produced the unresolved 4771 finding in Section 5.8 and warrants tighter correlation logic.

---

### 10. Kerberos ticket-volume baseline through the domain controller

**Covers:** Lateral-movement pivot detection — Section 5.8

```kql
WindowsAuth_CL
| where EventID in (4768, 4769) and DvcHostname == "GF-DC01"
| summarize TicketCount = count() by SourceIp, bin(TimeGenerated, 1h)
| join kind=leftouter (
    WindowsAuth_CL
    | where EventID in (4768, 4769) and DvcHostname == "GF-DC01"
    | summarize AvgHourly = avg(toreal(1)) by SourceIp
) on SourceIp
| where TicketCount > 3 * AvgHourly
```

**False-positive risk:** Medium — legitimate batch jobs or service restarts can spike ticket volume.
**Tuning:** Build the baseline over a rolling 14-day window excluding known batch-job hours; alert only on sustained (not single-hour) deviation.

---

### 11. Archive creation following credential-access indicators

**Covers:** T1560 / T1074 (Archive/Stage Collected Data) — Section 5.10

```kql
WindowsFile_CL
| where FileName endswith ".zip" or FileName endswith ".rar"
| join kind=inner (
    WindowsProcess_CL
    | where TargetProcessCommandLine has_any ("cmdkey", "KeePass", "lsass")
) on DvcHostname
| where TimeGenerated between (TimeGenerated1 .. TimeGenerated1 + 2h)
| project TimeGenerated, DvcHostname, FileName, ActorUsername
```

**False-positive risk:** Low-medium — routine log/backup archiving could coincide by chance.
**Tuning:** Exclude scheduled backup-service accounts; this rule directly closes the gap identified in Section 5.10 where staging was observed but no archive-creation alert fired.
