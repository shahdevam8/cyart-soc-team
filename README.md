# cyart-soc-team
# SOC Week 2 – Alert Prioritization, Incident Classification & Response (Step-by-Step Guide)

## Overview
This document explains the complete workflow followed during **SOC Week 2**, focusing on how a Security Operations Center (SOC) analyst prioritizes alerts, classifies incidents, performs alert triage, validates threats, preserves evidence, and responds to attacks using real-world security tools.

The guide is written in a **step-by-step and explainable manner**, allowing anyone with basic SOC knowledge to understand and reproduce the workflow.

---

## Tools Used
- Wazuh (SIEM and alert monitoring)
- TheHive (Incident and case management)
- VirusTotal (Threat intelligence validation)
- Velociraptor (Endpoint forensics)
- FTK Imager (Evidence acquisition)
- Metasploit (Attack simulation)
- CrowdSec / iptables (Attack response and blocking)

---

# Part 1: Alert Priority Levels

## Understanding Alert Severity
SOC teams receive thousands of alerts daily. Prioritization ensures analysts focus on the most dangerous threats first.

### Alert Priority Definitions
- **Critical:** Active exploitation, ransomware activity, or major service disruption.
- **High:** Unauthorized access, privilege escalation, or confirmed malicious behavior.
- **Medium:** Suspicious behavior that may lead to compromise if ignored.
- **Low:** Informational events or benign activity.

Alert severity is determined based on **impact**, **urgency**, **asset importance**, and **likelihood of exploitation**.

---

## CVSS and Risk Scoring
The **Common Vulnerability Scoring System (CVSS)** is used to quantify technical risk.

### CVSS Severity Mapping
| Severity | CVSS Score |
|--------|-----------|
| Low | 0.1 – 3.9 |
| Medium | 4.0 – 6.9 |
| High | 7.0 – 8.9 |
| Critical | 9.0 – 10.0 |

### Priority Assignment Logic
- CVSS ≥ 9.0 → Critical  
- CVSS ≥ 7.0 → High  
- CVSS ≥ 4.0 → Medium  
- Below 4.0 → Low  

This method ensures consistent and objective alert prioritization.

---

# Part 2: Incident Classification

## Purpose of Incident Classification
Incident classification helps SOC analysts understand **what type of attack is occurring** and **how to respond effectively**.

### Common Incident Types
- Malware
- Phishing
- Brute-force attacks
- DDoS attacks
- Insider threats
- Data exfiltration

### Standardized Frameworks
- **MITRE ATT&CK:** Maps attacker behavior to tactics and techniques (e.g., T1566 – Phishing).
- **Incident metadata** includes affected hosts, timestamps, user accounts, source IPs, and Indicators of Compromise (IOCs).

Consistent classification improves detection accuracy, correlation, and automation.

---

# Part 3: Alert Triage Using Wazuh

## Alert Review Process
Alert triage is the process of reviewing alerts to determine whether they represent real threats.

### Brute-Force SSH Alert Scenario
Multiple failed SSH login attempts are generated within a short time window. Wazuh detects this behavior and raises an alert.

### Alert Evaluation
- The alert rule level indicates severity.
- A rule level of **5** maps to **Medium priority** in the SOC severity model.
- The activity is suspicious but does not confirm compromise.

The alert remains open for monitoring and further analysis.

---

# Part 4: Threat Intelligence Validation

## IOC Validation
Threat intelligence platforms are used to validate indicators such as IP addresses, domains, and file hashes.

### IP Address Validation
- The source IP is checked using VirusTotal.
- The IP is identified as private/internal.
- No malicious reputation is found.

### Conclusion
The alert is classified as **Medium priority** and marked as **non-malicious internal activity**, requiring monitoring rather than escalation.

---

# Part 5: Incident Case Management (TheHive)

## Creating an Incident Case
TheHive is used to track incidents from detection to closure.

### Case Details
- Clear title describing the incident
- Description including indicators
- Priority based on alert severity
- Assigned analyst

## Task Management
Tasks are added to structure the investigation process, such as:
- Malware analysis
- Log collection
- Evidence preservation

This ensures accountability and traceability.

---

# Part 6: Evidence Preservation

## Importance of Evidence Handling
Evidence must be collected carefully to maintain integrity and legal admissibility.

### Evidence Collected
- Memory dump from the affected system
- Network connection data

### Chain of Custody
Each evidence item includes:
- Description
- Collected by
- Date
- Cryptographic hash

This guarantees evidence authenticity.

---

# Part 7: Incident Response Documentation

## Mock Phishing Incident Documentation
A phishing scenario is documented to practice reporting and response procedures.

### Incident Summary
A suspicious email containing a malicious link was reported. Immediate investigation and containment actions were performed.

### Timeline
- Endpoint isolation
- Evidence collection
- Header analysis
- Threat validation
- User notification

### Impact Analysis
No credentials were compromised, and no malware execution occurred. Impact remained low.

### Remediation
- Blocked malicious sender
- Updated detection rules
- Reinforced phishing response checklist

### Lessons Learned
- Early detection prevents compromise
- Standard checklists improve efficiency
- Evidence collection supports accurate reporting

---

# Part 8: Capstone – Full Alert-to-Response Cycle

## Attack Simulation
A controlled attack is launched using Metasploit against a vulnerable VSFTPD 2.3.4 service.

## Detection and Triage
- Wazuh detects the exploit attempt.
- The alert is mapped to **MITRE ATT&CK technique T1190 (Exploit Public-Facing Application)**.
- The source IP and timeline are documented.

## Response Actions
- The attacker’s IP is blocked using CrowdSec or firewall rules.
- Network access from the attacker is successfully denied.

## Reporting
A structured incident report is created containing:
- Executive summary
- Timeline of events
- Actions taken
- Recommendations

---

# Final Outcome
This SOC Week 2 exercise demonstrates:
- Alert prioritization using CVSS
- Incident classification using MITRE ATT&CK
- Alert triage in Wazuh
- Threat intelligence validation
- Case management with TheHive
- Evidence preservation
- End-to-end incident response

---

## Conclusion
Following this workflow ensures a **repeatable, structured, and professional SOC process**.  
These skills are fundamental for Tier-1 and Tier-2 SOC analysts and align with real-world security operations.

---

**End of Document**
