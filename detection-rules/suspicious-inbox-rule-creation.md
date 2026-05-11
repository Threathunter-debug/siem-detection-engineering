# Suspicious Inbox Rule Creation Detection

## Objective
Detect potentially malicious inbox rule creation activity commonly associated with phishing attacks, business email compromise (BEC), and account takeover incidents.

Attackers often create inbox rules to:
- Hide malicious emails
- Forward sensitive communications externally
- Delete security notifications
- Maintain persistence within compromised mailboxes

---

## Detection Logic

### Detection Criteria

```text
when:
- New inbox rule is created
AND
- Rule forwards emails externally
OR
- Rule deletes incoming messages
OR
- Rule moves emails to hidden folders
```

---

## Example KQL Query

```kql
OfficeActivity
| where Operation == "New-InboxRule"
| project TimeGenerated,
         UserId,
         ClientIP,
         Parameters
```

---

## Investigation Workflow

1. Identify affected mailbox user
2. Review inbox rule configuration
3. Determine whether forwarding behavior exists
4. Check for suspicious external destinations
5. Review recent sign-in activity
6. Validate MFA status
7. Investigate related phishing indicators
8. Correlate endpoint telemetry

---

## Investigation Findings

Analysis may identify:
- Unauthorized forwarding rules
- Suspicious mailbox manipulation
- External email forwarding
- Hidden folder redirection
- Rules created after phishing compromise

Inbox rule abuse is commonly observed during business email compromise investigations.

---

## Potential Security Risks

| Risk | Description |
|---|---|
| Business Email Compromise | Persistence within compromised mailbox |
| Data Exfiltration | Forwarding sensitive emails externally |
| Defense Evasion | Hiding security notifications |
| Account Persistence | Maintaining unauthorized access |

---

## MITRE ATT&CK Mapping

| Technique | Description |
|---|---|
| T1114 | Email Collection |
| T1078 | Valid Accounts |
| T1564 | Hide Artifacts |

---

## Recommended Response Actions

- Remove unauthorized inbox rules
- Reset user credentials
- Revoke active sessions
- Re-register MFA
- Review mailbox audit logs
- Investigate phishing exposure
- Block malicious forwarding destinations

---

## Tools Referenced

- Microsoft Defender XDR
- Microsoft 365 Defender
- Azure Entra ID
- Microsoft Sentinel
- IBM QRadar

---

## Analyst Notes

Inbox rule creation events should be prioritized during phishing and account compromise investigations, especially when external forwarding behavior or hidden message handling is identified.
