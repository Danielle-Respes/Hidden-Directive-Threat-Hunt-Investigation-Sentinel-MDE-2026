<img width="1017" height="362" alt="Screenshot 2026-07-10 at 7 14 45 PM" src="https://github.com/user-attachments/assets/acc8293c-157c-4912-9139-c458125b3c87" />

# Hidden Directive — DFIR Investigation (GF-INC-2026-0704)

**Tools:** Microsoft Sentinel · Defender XDR · KQL
**Author:** Danielle Respes · [LinkedIn](https://www.linkedin.com/in/danielle-respes-64113767/)

## About this case

On 4 July 2026, GF-WS01 at Greenfield Logistics triggered alerts, the MSSP escalated, and a P1 incident was declared. I was brought in to work it as a full DFIR investigation across three in-scope hosts: GF-WS01, GF-SRV01, and GF-DC01. The task: reconstruct how the attacker got in, how far they moved laterally, and what was taken, every action cited to telemetry, followed by remediation recommendations.

This is a live-incident DFIR case, not a flag hunt. I work it in phases and document each one: the question, the query, what I found, and how I reasoned through it.

**Status:** In progress · started 20 July 2026

---

## Technical Stack
- **SIEM:** Microsoft Sentinel
- **Endpoint telemetry:** Microsoft Defender XDR
- **Query language:** KQL (Kusto Query Language)

---

## Investigation

*Phases documented below as I work them.*
## C01 — Access & Environment

**Goal:** Confirm access to the telemetry, scope queries to the three in-scope hosts and the incident window.

**Sources:** Microsoft Sentinel workspace `LAW-SilentCorridor` (ASIM/custom logs, primary) and `LAW-Cyber-Range` (MDE Device tables, fallback).

**Incident window:** 4 Jul 2026 10:00 UTC – 5 Jul 2026 03:00 UTC
**Host scope:** `DvcHostname has_any ("GF-WS01","GF-SRV01","GF-DC01")`

```kql
union withsource=SourceTable *
| where TimeGenerated between (datetime(2026-07-04 10:00) .. datetime(2026-07-05 03:00))
| where DvcHostname has_any ("GF-WS01","GF-SRV01","GF-DC01")
| distinct $table
```

**Found:** Confirmed access and scoping. Available tables for the incident: WindowsAuth_CL, WindowsNetwork_CL, WindowsProcess_CL, WindowsFile_CL, WindowsRegistry_CL, WindowsDNS_CL, WindowsService_CL, WindowsAccountMgmt_CL.

**Reasoning:** Confirming scope first (correct workspace, working host filter, right time window) prevents pulling other estates' data and maps which telemetry is available before hunting.


---
<div align="center">
[Portfolio](https://github.com/Danielle-Respes) &nbsp;|&nbsp; [LinkedIn](https://www.linkedin.com/in/danielle-respes-64113767/)
  

*LOG(N) Pacific Cyber Range // Hidden Directive // Built by SancLogic*
