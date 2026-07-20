<img width="1017" height="362" alt="Screenshot 2026-07-10 at 7 14 45 PM" src="https://github.com/user-attachments/assets/acc8293c-157c-4912-9139-c458125b3c87" />

# Hidden Directive — Threat Hunt Investigation

**Tools:** Microsoft Sentinel · Microsoft Defender for Endpoint (MDE) · KQL
**Author:** Danielle Respes · [LinkedIn](https://www.linkedin.com/in/danielle-respes-64113767/)

## About this hunt

"Hidden Directive" is a threat hunt in the LOG(N) Pacific Cyber Range. Unlike a typical CTF, it runs as a live incident queue with raw telemetry and recovered artifacts, meant to simulate a real SOC environment. The premise: not everything in the data can be trusted, and the initial entry point is a decoy, so the work is separating the real intrusion from the noise.

I document each question as I solve it: the query I ran, what I found, and how I reasoned through it.

**Status:** In progress · started July 20, 2026

---

## Technical Stack
- **SIEM:** Microsoft Sentinel
- **Endpoint telemetry:** Microsoft Defender for Endpoint (MDE)
- **Query language:** KQL (Kusto Query Language)

---

*Findings below, one question at a time.*




---
## Peer review

After each hunt I bring my findings and sticking points to the LOG(N) community debrief sessions to pressure-test my reasoning against other analysts.


<div align="center">
[Portfolio](https://github.com/Danielle-Respes) &nbsp;|&nbsp; [LinkedIn](https://www.linkedin.com/in/danielle-respes-64113767/)
  

*LOG(N) Pacific Cyber Range // Hidden Directive // Built by SancLogic*
