# Suspicious PowerShell Detection Rule

## Objective
Detect potentially malicious PowerShell execution commonly associated with malware delivery, credential theft, and defense evasion.

---

## Detection Logic

### Example Indicators
- Encoded PowerShell commands
- PowerShell downloading external content
- Hidden execution flags
- Base64 encoded payloads
- PowerShell spawning from Office applications

---

## Sample QRadar Rule Logic

```text
when events match:
- Process Name = powershell.exe
AND
- Command Line contains "-enc"
OR
- Command Line contains "Invoke-WebRequest"
OR
- Parent Process = winword.exe
```

---

## MITRE ATT&CK Mapping

| Technique | Description |
|---|---|
| T1059.001 | PowerShell |
| T1204 | User Execution |
| T1562 | Defense Evasion |

---

## Investigation Steps

1. Validate parent-child process relationship
2. Review command-line arguments
3. Check outbound network connections
4. Verify file hash reputation
5. Investigate related user activity
6. Review endpoint telemetry in EDR

---

## Recommended Response Actions

- Isolate affected host
- Reset user credentials if compromised
- Block malicious hashes/domains
- Terminate malicious process
- Escalate confirmed compromise to IR team

---

## Tools Referenced

- IBM QRadar
- Microsoft Defender XDR
- CrowdStrike Falcon
- VirusTotal
