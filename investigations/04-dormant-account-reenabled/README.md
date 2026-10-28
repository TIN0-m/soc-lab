# Investigation 04: Dormant account re-enabled

| | |
|---|---|
| **Alert** | "Dormant account re-enabled: SOCLAB\brian.jacobs" (Medium) |
| **MITRE ATT&CK** | T1098 Account Manipulation (Persistence) |
| **Verdict** | Benign positive (authorised change) |
| **Analyst** | Tinotenda Masendeke |
| **Exercise** | Staged on purpose. Evidence is from the lab's real logs. |

Times are UTC. 27 October 2026.

## Summary

The disabled account `brian.jacobs` was switched back on. A dormant account coming back to life is a classic sign of attacker persistence (reactivating an old, forgotten account to hide in), so it fires an alert. Investigation showed the change was an authorised administrative action, so it closed as a benign positive, but the point stands: a re-enabled account is an incident until proven authorised.

## Triage

**What is it?** Windows event 4722 (a user account was enabled) for `brian.jacobs`, an account the onboarding pack lists as disabled.

```kql
SecurityEvent
| where EventID == 4722
| project TimeGenerated, Computer, EnabledAccount = TargetAccount, EnabledBy = SubjectAccount
```

**Is it authorised?** The question for any account/privilege change is: is there a change record? The onboarding pack's change register had no entry for re-enabling this account. In a real environment that makes it an incident until an admin confirms they did it. Here it was confirmed as authorised lab activity.

**Did the account then get used?** Checked for logons by `brian.jacobs` after it was enabled, there were none, so even if it had been malicious, the account was not yet used.

## Verdict and action

**Benign positive**: the detection was correct (the account really was re-enabled), and the actor was authorised. Closed benign. In a real SOC the next step on an *unconfirmed* one is to contact the account owner / IT and confirm the change, and if nobody owns it, disable it again and escalate.

## Lessons

- A dormant account re-enabled is a persistence red flag; always check it against a change record before clearing it.
- "No change ticket" does not instantly mean malicious, but it does mean you confirm with a human before closing.
- Check whether the account was *used* after the change, that tells you if anything happened yet.
