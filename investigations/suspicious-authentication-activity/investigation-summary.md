# Suspicious Microsoft 365 Authentication Activity Investigation

## Overview

This investigation analyzed suspicious Microsoft 365 authentication activity identified in IBM QRadar involving a flagged external IP address associated with multiple successful user authentication events.

The activity was validated across:
- IBM QRadar
- Microsoft Defender XDR Advanced Hunting
- Microsoft Entra ID Sign-In Logs
- Entra Risky Users
- AbuseIPDB

---

# Investigation Workflow

## 1. QRadar Offense Review

Reviewed QRadar offenses and authentication event logs associated with the suspicious IP address.

### Validation Performed
- Reviewed offense magnitude and associated events
- Analyzed authentication activity timeline
- Verified affected users and source IP activity
- Confirmed event categorization

![QRadar Offense Overview](./screenshots/authentication-investigation-overview.png)

---

# 2. Microsoft Defender XDR Hunting

Performed Advanced Hunting queries to validate authentication behavior and determine whether endpoint compromise or malicious activity existed.

### KQL Queries Used

```kql
IdentityLogonEvents
| where IPAddress == "REDACTED"
| project Timestamp, AccountUpn, DeviceName, ActionType, Application, IPAddress

DeviceNetworkEvents
| where RemoteIP == "REDACTED"
| project Timestamp, DeviceName, RemoteIP, InitiatingProcessFileName
