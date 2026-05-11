# Non-TLS Traffic Detected on Port 443

## Objective
Identify network traffic communicating over port 443 that does not use valid TLS/SSL protocols.

This behavior may indicate:
- Command-and-control traffic
- Protocol tunneling
- Malware communication
- Evasion techniques
- Misconfigured applications

---

## Detection Logic

### SIEM Correlation Rule

```text
when:
- Destination Port = 443
AND
- TLS Handshake NOT detected
OR
- SSL/TLS protocol validation fails
```

---

## Investigation Workflow

1. Identify source and destination systems
2. Review associated network sessions
3. Validate application generating traffic
4. Analyze packet behavior and protocol metadata
5. Check for related IDS/IPS alerts
6. Investigate endpoint telemetry
7. Validate whether traffic is authorized

---

## Investigation Findings

Analysis identified:
- Traffic communicating over TCP port 443
- No valid TLS negotiation observed
- Inconsistent SSL/TLS session behavior
- Repeated outbound connection attempts

Endpoint and network telemetry were reviewed to determine whether the activity represented malicious communication or legitimate application behavior.

---

## Potential Security Risks

| Risk | Description |
|---|---|
| Command and Control | Malware beaconing over disguised HTTPS traffic |
| Protocol Tunneling | Non-standard communication over trusted ports |
| Defense Evasion | Attempt to bypass network monitoring controls |
| Data Exfiltration | Unauthorized outbound communication |

---

## MITRE ATT&CK Mapping

| Technique | Description |
|---|---|
| T1071 | Application Layer Protocol |
| T1572 | Protocol Tunneling |
| T1041 | Exfiltration Over C2 Channel |

---

## Recommended Response Actions

- Review packet captures
- Validate destination reputation
- Block unauthorized traffic
- Isolate suspicious hosts
- Investigate related endpoint activity
- Escalate confirmed malicious communication

---

## Tools Referenced

- IBM QRadar
- IDS/IPS Telemetry
- CrowdStrike Falcon
- Microsoft Defender XDR
- Packet Capture Analysis

---

## Analyst Notes

Non-TLS communication over port 443 may represent suspicious activity attempting to blend with legitimate HTTPS traffic. Validation of protocol behavior and endpoint telemetry is critical to determining malicious intent.
