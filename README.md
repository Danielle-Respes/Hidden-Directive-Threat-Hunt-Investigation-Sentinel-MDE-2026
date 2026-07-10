<img width="1017" height="362" alt="Screenshot 2026-07-10 at 7 14 45 PM" src="https://github.com/user-attachments/assets/acc8293c-157c-4912-9139-c458125b3c87" />

# Hidden Directive — Live Threat Hunt Investigation
## Microsoft Sentinel + Microsoft Defender for Endpoint | LOG(N) Pacific Cyber Range | 2026

---

> **This is my first live threat hunt investigation.**
> No guided walkthrough. No flags. No score. No hints.
> A real incident dropped into a live environment. I investigated it, documented everything — including what confused me, what I got wrong, and what I figured out. The goal is to learn and to show the work.

---

## // Case Overview

| Field | Details |
|---|---|
| **Case ID** | GF-INC-2026-0704 |
| **Environment** | Greenfield Logistics — LOG(N) Pacific Cyber Range |
| **Investigation Opened** | July 18, 2026 @ 14:00 UTC (10:00 AM ET) |
| **Report Deadline** | August 15, 2026 |
| **Platform** | Microsoft Sentinel + Microsoft Defender for Endpoint (MDE) |
| **Artifacts Recovered** | 5 files |
| **Experience Level** | First live threat hunt |
| **Status** | 🔴 In Progress |

---

## // What This Is

Hidden Directive is the first live threat hunt investigation on the LOG(N) Pacific Cyber Range — built by [Mohammed A. / SancLogic](https://sanclogic.com/).

This is not a CTF. There are no flags to capture, no score, no leaderboard, and no guided walkthrough.

What drops on July 18:
- A live alert queue from a real detonation in the Greenfield environment
- Access to Microsoft Sentinel and Microsoft Defender for Endpoint
- Five files recovered from affected hosts during initial triage
- A report template and a short brief video walking through scope

I investigate. I analyze the artifacts. I pull the thread until I have the full picture. Then I write it up as a formal Incident Report.

---

## // Investigation Documents

| Document | Status | Description |
|---|---|---|
| [Day 1 Investigation Log](./day-1-notes.md) | 🔴 In Progress | Saturday — alert triage, initial Sentinel queries, first hypotheses |
| [Day 2 Investigation Log](./day-2-notes.md) | ⬜ Not Started | Sunday — deep dive, MDE analysis, artifact review |
| [Investigation Notes](./investigation-notes.md) | ⬜ Not Started | Full technical walkthrough — all queries, all findings |
| [Incident Report](./incident-report.md) | ⬜ Not Started | Formal IR — executive summary, attack timeline, findings, recommendations |
| [Detection Engineering](./detection-engineering.md) | ⬜ Not Started | KQL detection rules built from investigation findings |

---

## // Attack Timeline

> *Built in real time as the investigation progresses. Updated as findings are confirmed.*

| Timestamp | Event | Source | Confidence |
|---|---|---|---|
| TBD | Investigation opens — alert queue reviewed | Sentinel | — |
| TBD | | | |
| TBD | | | |
| TBD | | | |
| TBD | | | |

---

## // Tools & Techniques

**SIEMs:**
- Microsoft Sentinel (KQL — alert triage, hunting, timeline reconstruction)
- Microsoft Defender for Endpoint (DeviceFileEvents, DeviceProcessEvents, DeviceNetworkEvents)

**Artifact Analysis:**
- 5 recovered files from affected hosts (types TBD — revealed July 18)

**Frameworks:**
- MITRE ATT&CK (technique mapping)
- NIST 800-61 (incident response structure)

---

## // Detections Built

> *Populated after investigation closes — KQL rules written from confirmed findings*

| Rule Name | MITRE Tactic | Status |
|---|---|---|
| TBD | TBD | ⬜ Not yet written |

---

## // What I Learned

> *Filled in after investigation closes — honest reflection on what worked, what didn't, and what I'd do differently*

**What I got right:**
- TBD

**What I got wrong:**
- TBD

**What took longer than it should have:**
- TBD

**What I'd look for faster next time:**
- TBD

**Confidence calibration — was I right about my early hypothesis?**
- TBD

---

## // About This Portfolio

This investigation is part of my active Cyber Range internship at LogNPacific. I document every investigation in detail — including the learning process — so the progression from Hunt 1 to Hunt 5+ is visible.

Recruiters: compare this repo to future investigations in my portfolio to see growth over time.

📁 Full portfolio: [github.com/Danielle-Respes](https://github.com/Danielle-Respes)
🔗 LinkedIn: [linkedin.com/in/danielle-respes-64113767](https://www.linkedin.com/in/danielle-respes-64113767)

---

*LOG(N) Pacific Cyber Range // Hidden Directive // GF-INC-2026-0704 // Built by SancLogic*
