# Investigation 07: Failed logons for a service account

| | |
|---|---|
| **Alert** | "Repeated failed logons for svc_backup (12)" (Medium) |
| **MITRE ATT&CK** | n/a (benign misconfiguration, not an attack) |
| **Verdict** | Benign positive (likely a stale service credential) |
| **Analyst** | Tinotenda Masendeke |
| **Exercise** | Staged on purpose to practise clearing a benign "attack-shaped" alert. |

Times are UTC. 28 October 2026.

## Summary

The same rule that caught the brute force (investigation 06) fired again, this time for the service account `svc_backup`, 12 failed logons. But the shape is different: the failures came **from the domain controller itself**, for a **service account**, with no success. That pattern is far more often a service running with a stale or cached password than a human attack. The right call is benign, check the service's credentials, not "we're under attack."

## Triage

**What is it?** 12 failed logons for `svc_backup`.

```kql
SecurityEvent
| where TargetAccount has "svc_backup" and EventID in (4624, 4625, 4771)
| summarize n=count() by EventID, Computer
```

**Is it even an attack?** This is the question investigation 06 taught, asked the other way. Three things say "no, benign":
1. **It's a service account** (`svc_backup`), not a person's account. Humans brute-force user accounts; service accounts fail because of configuration.
2. **The source is the DC itself**, not an attacker's workstation. A service on the server authenticating with a bad password looks exactly like this.
3. **Event 4771** (Kerberos pre-authentication failed) appears alongside the 4625s, which is the signature of a service/Kerberos credential that no longer matches, not an interactive guessing attack.

**Did anything succeed?** No 4624. (As always, the breach claim needs the success event; there isn't one.)

## Verdict and action

**Benign positive.** The detection was technically correct (there really were 12 failures), but the cause is almost certainly a **stale/cached service credential**, not an attack. Action: close benign, and recommend checking `svc_backup`'s password and the service configuration (a password was likely changed without updating the service).

## Lessons

- **"Many failed logons" is not automatically an attack.** Context decides: *whose* account, *from where*.
- A **service account failing from a server** points to a configuration problem, not an intruder.
- **4771 (Kerberos pre-auth failure)** alongside 4625 is a tell for a bad service/machine credential.
- The same rule can produce a true-positive attack (investigation 06) and a benign false alarm (this one). The rule is fine; the **analyst's judgement** is what separates them.
