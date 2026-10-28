# Investigation 06: Brute force against one account

| | |
|---|---|
| **Alert** | "Repeated failed logons for pieter.vanwyk (15)" (Medium) |
| **MITRE ATT&CK** | T1110.001 Brute Force: Password Guessing (Credential Access) |
| **Verdict** | True positive, the attack **failed** (no compromise) |
| **Analyst** | Tinotenda Masendeke |
| **Exercise** | Staged on purpose. Evidence is from the lab's real logs. |

Times are UTC. 28 October 2026.

## Summary

The account `pieter.vanwyk` was hit with 15 failed logons in 21 seconds from WS01. This is a brute force against a single account (many guesses at one account), distinct from a spray (one password against many accounts). It was a true positive, but **every attempt failed and none succeeded**, so there was no compromise. Worth noting: the source was WS01 again, a workstation that keeps appearing as the origin of this lab's attacks.

## Timeline

| Time (UTC) | Event | Detail |
|---|---|---|
| 16:47:34 to 16:47:55 | 4625 ×15 | Failed logons (type 3) for pieter.vanwyk, all from WS01 |
| (none) | 4624 | **No successful logon** for pieter.vanwyk |

21 seconds, 15 tries, zero successes.

## Triage

**What is it?** 15 failed logons (4625) for one account in a short burst.

```kql
SecurityEvent
| where EventID in (4624, 4625)
| where TargetUserName =~ "pieter.vanwyk"
| project TimeGenerated, Result = iff(EventID==4624,"SUCCESS","FAIL"), LogonType, Computer, IpAddress
| order by TimeGenerated asc
```

**Brute force or a user mistake?** The rate decides it. 15 attempts in 21 seconds, about 1.4 seconds apart, is a script, not a person fat-fingering a password. True positive.

**Did it work?** This is the question that sets the severity. The answer is in the data: **is there a 4624 success?** There is not, every event is a 4625 failure. So the attack failed, no account was taken over.

**Where from?** All from WS01, a workstation. A workstation launching logon attacks against the domain is itself suspicious and points to WS01 as the foothold.

## Verdict and action

**True positive, failed.** A brute force was attempted and did not succeed, so there is **no compromise to escalate.** Action: keep an eye on the account, and investigate **why WS01 keeps being the source** across these cases.

## Lessons

- **Rate separates attack from accident.** Many attempts per second = automated = attack.
- **"Did it succeed?" is a yes/no in the data:** is there a 4624 for this account? No 4624 = it failed. Never claim a breach without the success event.
- Many failures for one account = brute force; many accounts with few failures each = spray. Same event (4625), different shape.
- Watch the *source*, not just the target. The compromised workstation is the bigger thread.
