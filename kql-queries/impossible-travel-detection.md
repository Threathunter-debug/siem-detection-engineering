# Impossible Travel Detection Query

## Objective
Identify user sign-ins occurring from geographically impossible locations within a short time frame.

---

## Microsoft Defender XDR / Sentinel KQL Query

```kql
SigninLogs
| where ResultType == 0
| project UserPrincipalName, IPAddress, Location, TimeGenerated
| sort by UserPrincipalName asc, TimeGenerated asc
| serialize
| extend PreviousLocation = prev(Location),
         PreviousTime = prev(TimeGenerated),
         PreviousUser = prev(UserPrincipalName)
| where UserPrincipalName == PreviousUser
| extend TimeDifference = datetime_diff("minute", TimeGenerated, PreviousTime)
| where TimeDifference < 60
| where Location != PreviousLocation
```

---

## Detection Use Case

This query helps identify:
- Compromised accounts
- Suspicious VPN usage
- Credential theft
- Unauthorized remote access
- Account sharing

---

## MITRE ATT&CK Mapping

| Technique | Description |
|---|---|
| T1078 | Valid Accounts |
| T1021 | Remote Services |
| T1110 | Credential Access |

---

## Investigation Workflow

1. Review user sign-in history
2. Validate MFA activity
3. Check device compliance
4. Review IP reputation
5. Confirm travel legitimacy with user
6. Investigate concurrent sessions

---

## Recommended Response

- Reset credentials
- Revoke active sessions
- Require MFA re-registration
- Investigate endpoint activity
- Escalate confirmed compromise

---

## Tools Referenced

- Microsoft Defender XDR
- Microsoft Sentinel
- Azure Entra ID
