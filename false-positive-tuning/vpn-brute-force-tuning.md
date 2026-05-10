# VPN Brute Force Alert Tuning

## Objective
Reduce false positives generated from repetitive failed VPN authentication attempts caused by normal user behavior.

---

## Initial Problem

The SIEM generated excessive brute force alerts due to:
- Users entering expired passwords
- Mobile device authentication retries
- VPN reconnect loops
- Service account authentication failures

This resulted in alert fatigue and reduced analyst efficiency.

---

## Investigation Findings

Analysis identified:
- Multiple alerts tied to the same user within short intervals
- Consistent internal source IPs
- Successful authentication immediately after failed attempts
- No malicious indicators or lateral movement activity

---

## Tuning Improvements

### Threshold Optimization
Adjusted alert threshold from:

```text
5 failed logins in 5 minutes
```

To:

```text
15 failed logins in 10 minutes
```

---

### Whitelisting

Excluded:
- Trusted VPN gateway IP ranges
- Known service accounts
- Approved vulnerability scanners

---

### Behavioral Correlation

Added logic requiring:
- Multiple source IPs
- Geographic anomalies
- Lack of successful login after failures

before triggering high severity alerts.

---

## Results

| Metric | Before | After |
|---|---|---|
| Daily Alerts | 120 | 18 |
| False Positive Rate | High | Low |
| Analyst Review Time | Excessive | Optimized |

---

## MITRE ATT&CK Mapping

| Technique | Description |
|---|---|
| T1110 | Brute Force |
| T1078 | Valid Accounts |

---

## Tools Referenced

- IBM QRadar
- Azure Entra ID
- Microsoft Defender XDR
