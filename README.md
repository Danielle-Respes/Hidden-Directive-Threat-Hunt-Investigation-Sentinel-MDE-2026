<img width="1017" height="362" alt="Screenshot 2026-07-10 at 7 14 45 PM" src="https://github.com/user-attachments/assets/acc8293c-157c-4912-9139-c458125b3c87" />

# Hidden Directive: Threat Hunt Investigation

## Overview

This repository is dedicated to the "Hidden Directive" Threat Hunt Investigation within the LOG(N) Pacific Cyber Range. Unlike typical CTF challenges, this event provides a live incident queue, raw telemetry, and recovered artifacts to simulate a realistic SOC environment.

---

## Peer Review & Methodology Validation
> I believe real expertise is built by subjecting my analysis to peer scrutiny. 

**Community Collaboration:** I actively participate in Wednesday community sessions to pressure-test my hunting logic and compare pivot methodologies against peer workflows.

**Validation Strategy:** Post-investigation, all findings and detection logic are subjected to peer review to ensure accuracy, reduce bias, and refine my hunting patterns for professional SOC environments.

---

## Incident Report
**Full technical findings, timeline, and forensic evidence are documented in the following report:**
> **[View the Formal Incident Report](Incident-Report.md)** (pending)
---
## Investigation Lifecycle
*   **Phase 1 (Preparation):** Environment baselining, scope definition, and hypothesis generation.
*   **Phase 2 (Active Hunting):** Real-time triage, telemetry analysis, and iterative query refinement.
*   **Phase 3 (Reporting):** Evidence distillation, incident formalization, and detection engineering (writing the rules).
*   **Phase 4 (Continuous Improvement):** Peer review, feedback integration, and updating logic based on community debriefs.

---

## Pre-Investigation Planning & Methodology

> Before the live incident queue drops on July 18, I am establishing the following investigative baseline to ensure a structured response. 
> 
> *Note: I am currently finalizing an active threat hunt (Northpeak Descent) through July 17.*

> **July 10:** Reviewed event requirements and confirmed environment access protocols. Initial setup of report template and evidence logging structure.
>
> **July 11–17:** Baseline study of LOG(N) telemetry documentation; reviewing APT TTPs relevant to industrial infrastructure.
>
> **July 18 (Launch):** Transitioning focus exclusively to the Hidden Directive live incident queue.

---

## Investigation Schedule

> **Launch Date:** July 18, 2026
>
> **Investigation Window:** July 18 – August 1, 2026
>
> **Report Deadline:** August 15, 2026

---
## Career Signal — What This Demonstrates

*   **For SOC Roles:** Demonstrates end-to-end incident response, including multi-SIEM telemetry correlation (Sentinel/MDE), KQL-based pivot analysis, and proactive detection engineering developed from confirmed investigation findings.

*   **For GRC Roles:** Demonstrates adherence to the NIST Cybersecurity Framework (Detect, Respond, Recover), formal incident documentation, and the ability to translate technical findings into business-impact reports for leadership.

*   **For Remote Roles:** Proves effective asynchronous communication skills. This report is structured as a standalone artifact—providing clear, actionable data that requires minimal clarification, mirroring the standard for high-performance remote teams.

---

## Technical Stack

**Platform:** Microsoft Sentinel (SIEM/SOAR)

**Query Language:** Kusto Query Language (KQL)

**Endpoint Analysis:** Microsoft Defender for Endpoint (MDE)

## Role-Specific Takeaways

> I approach every investigation by considering the unique priorities of the security team.

*   **SOC Analyst Lens:** My methodology focuses on reducing "mean time to detect" (MTTD). In this investigation, I demonstrate how KQL pivoting moved me from initial alert to confirmed attacker command line. Each report includes a proposed detection rule to automate future defenses.

*   **GRC Analyst Lens:** I view incidents through the lens of risk and compliance. I identify the specific security controls (NIST CSF) impacted and translate technical findings into business-impact summaries suitable for leadership.

*   **Remote Work Evidence:** This report is written for clarity and asynchronous consumption. By documenting my thought process and providing high-fidelity logs, I ensure that my work is fully transparent and actionable for any team member, regardless of their location.

<div align="center">
[Portfolio](https://github.com/Danielle-Respes) &nbsp;|&nbsp; [LinkedIn](https://www.linkedin.com/in/danielle-respes-64113767/)
  

*LOG(N) Pacific Cyber Range // Hidden Directive // Built by SancLogic*
