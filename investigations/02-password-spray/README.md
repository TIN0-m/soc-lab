# Investigation 02: Password spray from a workstation

| | |
|---|---|
| **How found** | Threat hunt in Sentinel logs. No rule existed yet, so nothing alerted. |
| **Detection built** | [Password spray: one host failing logons against many accounts](../../detections/password-spray/) (written as a result of this hunt) |
| **Severity** | High (spray succeeded: two accounts taken over) |
| **MITRE ATT&CK** | T1110.003 Brute Force: Password Spraying (Credential Access); T1078.002 Valid Accounts |
| **Verdict** | True positive: two accounts compromised, contained |
| **Analyst** | Tinotenda Masendeke |
| **Exercise** | The spray was generated on purpose to practise hunting and rule-writing. Everything below is from the lab's real logs. |

Times are UTC. The attack ran on 26 October 2026.

## Summary

A single workstation, **WS01**, failed to log on against **17 different accounts in about 45 seconds**, then two of those accounts logged on successfully seconds later. One password tried against many accounts, with a couple of hits, is a **password spray** (T1110.003). The two accounts that use a weak shared password, `zanele.mthembu` and `tshepo.maluleke`, were compromised. Because a workstation does not normally launch logons against the whole company, WS01 itself is treated as the likely foothold. No detection rule existed, so this was found by hunting the raw logs; a rule was then written and deployed so the next spray alerts automatically.

## Timeline

| Time (UTC) | Source | What happened |
|---|---|---|
| 12:39:35 to 12:40:21 | WS01, event 4625 ×17 | Failed network logons (type 3) against 17 different accounts in 45 seconds |
| 12:39:53 | WS01, 4624 type 3 | `zanele.mthembu` logs on successfully: first compromise |
| 12:40:18 | WS01, 4624 type 3 | `tshepo.maluleke` logs on successfully: second compromise |
| 13:07:53 | DC01, 4725 ×2 | Both accounts disabled and flagged to reset password (containment) |
| ~13:10 | Sentinel | Password-spray detection rule written and deployed |

## The hunt

Nothing alerted, so the starting point was "find one source failing against many accounts in a short window":

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count(), DistinctAccounts = dcount(TargetUserName),
    AccountsTargeted = make_set(TargetUserName, 100) by Computer, bin(TimeGenerated, 10m)
| where DistinctAccounts >= 5
```

This returned WS01 with 17 distinct accounts. Counting **distinct accounts** (not raw failures) is what separates a spray from a single locked-out user.

Then: did any succeed from the same host?

```kql
SecurityEvent
| where EventID in (4624, 4625) and LogonType == 3
| summarize Fails = countif(EventID==4625), Success = countif(EventID==4624) by TargetUserName
| where Success > 0
```

Two accounts, `zanele.mthembu` and `tshepo.maluleke`, showed a success right after the failures: the spray worked.

## Triage answers

1. **Pattern:** one source (WS01) failing against 17 different accounts in 45 seconds. Many distinct accounts from one source is a spray, not a lockout.
2. **Source:** WS01, a staff workstation. A workstation spraying the domain is itself suspicious, so WS01 is likely the attacker's foothold.
3. **Did it work:** yes. `zanele.mthembu` (12:39:53) and `tshepo.maluleke` (12:40:18) logged on during the spray. Both use a weak shared password, the planted weakness.
4. **Immediate action:** disable both accounts, force a password reset, and isolate and investigate WS01.
5. **Verdict and severity:** true positive, **High**. The onboarding pack rates a spray *with no success* as Medium, but *account takeover* as High. Two accounts were taken over, so this is High.

## Containment

On DC01:

```powershell
Disable-ADAccount -Identity zanele.mthembu
Disable-ADAccount -Identity tshepo.maluleke
Set-ADUser -Identity zanele.mthembu -ChangePasswordAtLogon $true
Set-ADUser -Identity tshepo.maluleke -ChangePasswordAtLogon $true
```

Disabling the accounts makes the stolen password useless immediately; the forced reset applies when they are re-enabled. Both disables are in the log as event 4725 at 13:07:53.

**Still needed in a real company:** isolate WS01 and investigate it as the source, reset the two users' passwords with them directly, and review whether the weak shared password is used anywhere else.

## The detection that was missing

No rule covered this, so it was built afterwards: [`detections/password-spray/`](../../detections/password-spray/). It groups failed logons by source host and fires when one host fails against **5 or more distinct accounts** in the look-back window.

**A design choice worth explaining:** the rule fires at **Medium**, not High. The spray *pattern* on its own does not prove a break-in, and firing everything at High causes alert fatigue. The rule's description tells the analyst to confirm whether any targeted account then succeeded and raise it to High if so. That mirrors the pack: spray with no success is Medium, account takeover is High.

Once deployed, the rule ran and **opened Sentinel incident #3, "Possible password spray from WS01.soclab.internal (17 accounts)" (Medium)**, on the same attack it was built from. The hunt found it once; the rule now finds it every time.

## Lessons from running it

- **Not everything alerts.** The privileged-group change (investigation 01) had a rule and opened an incident on its own. This had no rule, so it only existed in the raw logs until someone went looking. A SOC analyst both works the alert queue and hunts for what the queue misses.
- **Count distinct accounts, not failures.** Raw failure count can't tell a spray from a lockout. `dcount(TargetUserName)` is the signal.
- **The source matters as much as the target.** The compromised accounts are the obvious damage, but a workstation being the *source* of the spray is the bigger lead: it points to the foothold.
- **Build the rule after the hunt.** A hunt that finds something should end with a detection so it is caught automatically next time. The hunt and the rule are two halves of the same job.

After the exercise, the two accounts are re-enabled for future exercises.
