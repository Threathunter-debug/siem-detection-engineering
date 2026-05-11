# DNS Tunneling Detection

## Objective
Detect suspicious DNS activity that may indicate DNS tunneling, command-and-control communication, or data exfiltration attempts.

Attackers commonly abuse DNS traffic because it is frequently allowed through perimeter defenses and often receives limited inspection.

---

## Detection Logic

### SIEM Correlation Criteria

```text
when:
- Excessive DNS queries observed
AND
- High volume of TXT or NULL record requests
OR
- Unusually long domain query strings
OR
- High entropy DNS requests
```

---

## Common DNS Tunneling Indicators

| Indicator | Description |
|---|---|
| Excessive TXT Requests | Possible encoded payload transmission |
| Long Subdomain Strings | Potential data encoding/exfiltration |
| High Query Frequency | Beaconing or tunneling behavior |
| Unusual DNS Record Types | Abuse of DNS protocol functionality |
| Randomized Domains | Algorithmically generated domains |

---

## Example KQL Query

```kql
DnsEvents
| summarize QueryCount=count() by ClientIP, Name
| where QueryCount > 100
| where strlen(Name) > 50
```

---

## Investigation Workflow

1. Identify affected endpoint
2. Review DNS query frequency
3. Analyze domain reputation
4. Validate DNS record types
5. Review endpoint process activity
6. Correlate outbound network connections
7. Investigate command-line activity
8. Determine whether encoded traffic exists

---

## Potential Security Risks

| Risk | Description |
|---|---|
| Command and Control | Malware communication over DNS |
| Data Exfiltration | Covert outbound data transfer |
| Defense Evasion | Bypassing traditional network controls |
| Persistence | Maintaining hidden communication channels |

---

## MITRE ATT&CK Mapping

| Technique | Description |
|---|---|
| T1071.004 | DNS Protocol |
| T1048 | Exfiltration Over Alternative Protocol |
| T1572 | Protocol Tunneling |

---

## Recommended Response Actions

- Block suspicious domains
- Isolate affected systems
- Review packet captures
- Investigate endpoint telemetry
- Reset compromised credentials if necessary
- Monitor for recurring DNS anomalies

---

## Tools Referenced

- IBM QRadar
- Microsoft Defender XDR
- CrowdStrike Falcon
- DNS Telemetry
- Packet Capture Analysis

---

## Analyst Notes

DNS tunneling activity may be difficult to identify due to legitimate DNS traffic volume. Detection efforts should focus on abnormal query behavior, excessive TXT requests, domain entropy, and endpoint correlation.
