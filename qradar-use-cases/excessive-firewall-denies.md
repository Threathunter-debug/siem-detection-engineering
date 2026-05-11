# Excessive Firewall Denies Investigation

## Objective
Detect abnormal firewall deny activity that may indicate reconnaissance, scanning activity, brute force attempts, or unauthorized access attempts.

---

## Alert Description

A SIEM correlation rule generated an alert after identifying excessive denied firewall connections originating from a remote external source targeting multiple internal systems.

The activity exceeded the established threshold for normal denied traffic behavior.

---

## Detection Logic

### QRadar Correlation Logic

```text
when:
- Multiple firewall deny events occur
AND
- Source IP targets multiple destinations
AND
- Event count exceeds threshold within defined time window
```

---

## Investigation Workflow

1. Identify source IP address
2. Review targeted destination systems
3. Analyze destination ports
4. Validate firewall action results
5. Review historical activity for source IP
6. Correlate with IDS/IPS telemetry
7. Check endpoint activity in EDR
8. Determine malicious vs benign behavior

---

## Investigation Findings

Analysis identified:
- High volume denied connections
- Sequential destination targeting behavior
- Multiple connection attempts across various ports
- No successful internal compromise observed
- Firewall protections successfully blocked activity

The behavior was consistent with automated external reconnaissance activity.

---

## MITRE ATT&CK Mapping

| Technique | Description |
|---|---|
| T1595 | Active Scanning |
| T1046 | Network Service Discovery |
| T1110 | Brute Force |

---

## Recommended Response Actions

- Block malicious source IPs
- Validate firewall policies
- Review IDS/IPS signatures
- Monitor for repeated scanning attempts
- Escalate if successful connections observed

---

## Tools Referenced

- IBM QRadar
- Firewall Telemetry
- CrowdStrike Falcon
- Microsoft Defender XDR

---

## SOC Analyst Notes

The investigation determined the activity was blocked by perimeter controls and no evidence of successful compromise or malicious execution was identified during analysis.
