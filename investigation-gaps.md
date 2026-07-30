# Gaps & Unknowns — GF-INC-2026-0704

| Gap | Impact | Evidence | Mitigation |
|---|---|---|---|
| No token-manipulation event type in LAW-SilentCorridor | Privilege escalation (C05) only visible via Defender XDR | `ProcessPrimaryTokenModification` absent from `WindowsProcess_CL` | Cross-reference MDE for all token/privilege events; don't rely on SIEM process logs alone |
| Defender XDR lacks command-line detail for credential access (C07) | Can't confirm exact `cmdkey`/`Get-ADUser` arguments from MDE alone | Device Timeline shows high-level process only | Use LAW-SilentCorridor as primary source for command-line forensics |
| No Azure-side telemetry for on-host token theft or credential access | Can't confirm cloud-side visibility into local privilege escalation/credential harvesting | LAW-Cyber-Range has no matching events for C05/C07 | Treat LAW-Cyber-Range as initial-access/cloud-control-plane source only |
| Failed Kerberos pre-auth (4771) from 10.1.0.169 unresolved | Unclear if this is a separate hash-cracking attempt or noise | C09, row 1001 | Flag for follow-up hunt; correlate against successful 4768/4769 pair timing |
| `aggregatorhost.exe` registry activity (Jul 8) falls outside core incident window (4–5 Jul) | Unclear if related to this actor or unrelated background activity | Registry timestamp evidence, artifacts-analysis.md | Scope a separate query to confirm whether this is in-scope persistence or noise |
