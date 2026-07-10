# Investigation Notes — Full Technical Walkthrough
## Hidden Directive // GF-INC-2026-0704
## LOG(N) Pacific Cyber Range // July 2026

---

> *This document is the complete technical record of my investigation — 
> all queries, all findings, all reasoning. The daily logs capture 
> the live process. This document organizes everything into a clean, 
> readable technical walkthrough after the investigation closes.*

---

## // Environment Overview

**Greenfield Logistics** — simulated enterprise environment on the LOG(N) Pacific Cyber Range.

| Component | Details |
|---|---|
| SIEM 1 | Microsoft Sentinel |
| SIEM 2 | Microsoft Defender for Endpoint (MDE) |
| Artifacts | 5 files recovered from affected hosts |
| Investigation Period | July 18 – August 1, 2026 |

---

## // Investigation Approach

**My methodology:**

1. Read the brief and brief video — understand scope before touching data
2. Inventory artifacts before analyzing them
3. Triage Sentinel alert queue — highest severity first
4. Pivot from alerts into Sentinel hunting queries
5. Cross-reference findings in MDE (DeviceFileEvents, DeviceProcessEvents, DeviceNetworkEvents)
6. Analyze the 5 recovered artifacts and cross-reference against telemetry
7. Build attack timeline
8. Write detection rules from confirmed findings

---

## // Platforms and Tools Used

- **Microsoft Sentinel** — alert triage, KQL hunting queries, timeline reconstruction
- **Microsoft Defender for Endpoint** — endpoint telemetry, process/file/network events
- **MITRE ATT&CK** — technique mapping
- **NIST 800-61** — incident response structure

---

## // Step 1 — Alert Triage (Microsoft Sentinel)

### Alert Queue Summary

| Alert | Severity | Time | Entity Involved | Priority |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |

### What I Prioritized First and Why


### Key Sentinel Queries

**Query 1 — [Purpose]**

```kql
// query here
```
**Result:** 
**Finding:**

---

**Query 2 — [Purpose]**

```kql
// query here
```
**Result:**
**Finding:**

---

**Query 3 — [Purpose]**

```kql
// query here
```
**Result:**
**Finding:**

---

## // Step 2 — Endpoint Investigation (MDE)

### Devices Investigated

| Device Name | Why I Looked At This Device | What I Found |
|---|---|---|
| | | |

### Key MDE Queries

**Query 1 — [Purpose]**

```kql
// query here
```
**Result:**
**Finding:**

---

**Query 2 — [Purpose]**

```kql
// query here
```
**Result:**
**Finding:**

---

**Query 3 — [Purpose]**

```kql
// query here
```
**Result:**
**Finding:**

---

## // Step 3 — Artifact Analysis

### File 1 — [Filename]

- **Type:**
- **Contents:**
- **Key Finding:**
- **Corroborates:**
- **Contradicts:**
- **MITRE Technique:**

---

### File 2 — [Filename]

- **Type:**
- **Contents:**
- **Key Finding:**
- **Corroborates:**
- **Contradicts:**
- **MITRE Technique:**

---

### File 3 — [Filename]

- **Type:**
- **Contents:**
- **Key Finding:**
- **Corroborates:**
- **Contradicts:**
- **MITRE Technique:**

---

### File 4 — [Filename]

- **Type:**
- **Contents:**
- **Key Finding:**
- **Corroborates:**
- **Contradicts:**
- **MITRE Technique:**

---

### File 5 — [Filename]

- **Type:**
- **Contents:**
- **Key Finding:**
- **Corroborates:**
- **Contradicts:**
- **MITRE Technique:**

---

## // Step 4 — Attack Timeline (Reconstructed)

| Timestamp | Event | Source | MITRE Technique | Confidence |
|---|---|---|---|---|
| | Initial Access | | | |
| | | | | |
| | | | | |
| | | | | |
| | Impact | | | |

---

## // Step 5 — MITRE ATT&CK Mapping

| Technique ID | Technique Name | Evidence | Detection |
|---|---|---|---|
| | | | |
| | | | |
| | | | |

---

## // Indicators of Compromise (IOCs)

> *Sanitized — no real IPs, hostnames, or workspace IDs from the range*

| Type | Value | Context |
|---|---|---|
| File Hash | | |
| Process Name | | |
| File Path | | |
| Network Port | | |

---

## // Summary of Findings


---

*→ [Incident Report](./incident-report.md) — formal write-up*
*→ [Detection Engineering](./detection-engineering.md) — KQL rules built from findings*
