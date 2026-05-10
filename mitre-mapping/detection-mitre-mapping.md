# Detection to MITRE ATT&CK Mapping

## Objective
Map SIEM detection use cases to MITRE ATT&CK techniques to support detection coverage, threat hunting, and SOC response workflows.

---

## Detection Coverage Matrix

| Detection Use Case | MITRE Technique | Technique ID | Tactic |
|---|---|---|---|
| Suspicious PowerShell Execution | PowerShell | T1059.001 | Execution |
| VPN Brute Force Activity | Brute Force | T1110 | Credential Access |
| Impossible Travel | Valid Accounts | T1078 | Defense Evasion / Initial Access |
| Suspicious Remote Access | Remote Services | T1021 | Lateral Movement |
| User Clicked Phishing Link | Phishing | T1566 | Initial Access |
| Malicious File Download | User Execution | T1204 | Execution |
| Suspicious External Connection | Application Layer Protocol | T1071 | Command and Control |

---

## Purpose

This mapping helps analysts:

- Understand attacker behavior
- Prioritize high-risk detections
- Improve SOC investigation workflows
- Identify detection coverage gaps
- Support threat hunting and incident response

---

## Analyst Notes

MITRE ATT&CK mapping provides context for how alerts connect to adversary tactics, techniques, and procedures. This improves triage quality and helps SOC teams communicate risk more effectively.
