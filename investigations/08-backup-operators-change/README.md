# Investigation 08: User added to a privileged group

| | |
|---|---|
| **Alert** | "Tshepo Maluleke added to Backup Operators by SOCLAB\DC01$" (High) |
| **MITRE ATT&CK** | T1098 Account Manipulation (Persistence, Privilege Escalation) |
| **Verdict** | Benign positive (authorised), but only after proving it |
| **Analyst** | Tinotenda Masendeke |
| **Exercise** | Staged on purpose. Evidence is from the lab's real logs. |

Times are UTC. 28 October 2026.

## Summary

A normal user, `tshepo.maluleke`, was added to **Backup Operators**, a privileged group whose members can read and restore any file on a system. This is a High-severity change and a classic privilege-escalation / persistence move. The "added by" was **DC01$ (SYSTEM)**, meaning it ran through the machine / management plane, not a person at a console. That is a *question*, not a clearance: SYSTEM doing a privileged change could be an authorised admin via Azure Run Command, or an attacker with stolen cloud credentials. It resolved to authorised, but only after checking, not by assuming.

## Timeline

| Time (UTC) | Event | Detail |
|---|---|---|
| 20:22:20 | 4732 | `tshepo.maluleke` (SID S-1-5-21-…-1625, a normal domain user) added to **Backup Operators** |
| | Added by | **SOCLAB\DC01$** (the DC's machine account = ran as SYSTEM / management plane) |

## Triage

**What is it?** Event 4732, a member added to a privileged local group.

```kql
SecurityEvent
| where EventID == 4732
| extend MemberSid = extract(@'MemberSid">([^<]+)', 1, EventData)
| project TimeGenerated, GroupAdded = TargetAccount, AddedBy = SubjectAccount, MemberSid
```

**Is it authorised?** Two checks:
1. **Is there a change record?** The onboarding pack's change register had no entry. Unconfirmed.
2. **Who did it?** The "added by" is DC01$ / SYSTEM, which means it came through the management plane. **SYSTEM is not proof of authorised.** The real "who" for a management-plane action is in the **Azure Activity Log** (`AzureActivity`, the `Caller` field), the same pivot used in [investigation 03](../03-security-log-cleared/). That confirmed an authorised admin account ran it.

**A note on the SID:** the member's SID (`S-1-5-21-…-1625`) is an ordinary domain user. The machine/SYSTEM identity in play here is the *actor* (DC01$), not the member, two different things that are easy to confuse.

## Verdict and action

**Benign positive, proven.** A privileged group change that, once the Activity Log confirmed an authorised caller, was authorised administration. Action taken: `tshepo` removed from Backup Operators (reversible containment of an unexpected privileged member), then closed. **It stayed a High until authorisation was proven**, it was not downgraded on the assumption that "SYSTEM did it, so it's fine."

## Lessons

- A **privileged group change is High** and stays suspicious until authorisation is **proven**, not assumed.
- **SYSTEM / machine account as the actor is a question**, not a clearance. For management-plane actions, prove the "who" in the **Azure Activity Log**.
- Don't confuse the **member** (what was changed) with the **actor** (who changed it), different fields, different SIDs.
- Contain reversibly (remove the member), but confirm authorisation before you decide benign or breach.
