# Investigation 01: Sales user added to Domain Admins

| | |
|---|---|
| **Incident** | Sentinel #2 (and #1, a duplicate: see tuning) |
| **Detection** | [Member added to a privileged AD group](../../detections/privileged-group-change/) |
| **Severity** | High |
| **MITRE ATT&CK** | T1098 Account Manipulation (Persistence, Privilege Escalation); T1078.002 Valid Accounts: Domain Accounts |
| **Verdict** | True positive: unapproved change, contained |
| **Analyst** | Tinotenda Masendeke |
| **Exercise** | The "attacker" step was run on purpose to test the detection end to end. Everything below is from the lab's real logs. |

Times are UTC as Sentinel stores them, with South African time (SAST, UTC+2) where it matters.

## Summary

On **Sunday 25 October 2026 at 17:05 SAST**, the domain admin account `socadmin` signed in to the domain controller DC01 over Remote Desktop and added `zanele.mthembu`, a Sales user, to **Domain Admins**. There was no approved change, it happened outside office hours, and a Sales user never needs domain admin rights, so it was treated as an attacker planting a backdoor with a stolen admin account. Sentinel opened a High incident 10 minutes later. Zanele was removed from the group and her account disabled; her account was never used while it had admin rights.

## Timeline

| Time (UTC) | Source | What happened |
|---|---|---|
| 25 Oct 14:58 to 15:01 | DC01, event 4625 ×6 | Failed network logons from the SOC laptop's Tailscale address for a user that doesn't exist (status `0xC000006D`, sub-status `0xC0000064`) |
| 15:04:16, 15:04:21 | DC01, 4624 type 3 ×2 | Network logons for `socadmin` from the same address: Remote Desktop's pre-login check (Network Level Authentication) |
| 15:04:26 | DC01, 4624 type 10 | `socadmin` Remote Desktop session starts (logon ID `0x13f16c0`) |
| 15:05:54 | DC01, PowerShell 4104 | Script block logged: `Add-ADGroupMember -Identity "Domain Admins" -Members "zanele.mthembu"` |
| **15:05:55** | DC01, **4728** | **Zanele Mthembu added to Domain Admins by SOCLAB\socadmin** |
| 15:06:24 | Sentinel | Event 4728 arrives in the workspace (29 seconds after it happened) |
| **15:16:09** | Sentinel | **Incident #1 created**, High |
| 15:21:17 | Sentinel | Incident #2 created for the same event (duplicate) |
| 26 Oct 11:28:56 | DC01, 4729 | Zanele removed from Domain Admins |
| 11:28:56 | DC01, 4725 | Zanele's account disabled |
| 11:39:57 | Sentinel | Incident #2 closed: true positive, suspicious activity |

**Time to detect:** 10 minutes 14 seconds (event to incident).
**Time to contain:** about 20 hours. The lab machines shut down every night at 23:00 to save cost, so containment waited for the next session. Lowveld Logistics' playbook asks for High incidents within **1 hour**; in a real shift this would have been handled the same afternoon.

## Investigation

**1. What happened, and who did it?** The alert gave the change itself; PowerShell logging gave the exact command.

```kql
Event
| where Source == "Microsoft-Windows-PowerShell" and EventID == 4104
| where RenderedDescription has "Add-ADGroupMember"
| project TimeGenerated, Computer, UserName, RenderedDescription
```

**2. Where did it come from?** The change was made inside a Remote Desktop session (logon type 10) from `100.x.x.x`, the **SOC laptop's** Tailscale address. The two type 3 logons seconds earlier are normal for Remote Desktop: the client proves who it is over the network first, then the desktop session opens.

```kql
SecurityEvent
| where EventID == 4624 and TargetUserName =~ "socadmin"
| project TimeGenerated, Computer, LogonType, IpAddress, TargetLogonId
```

**3. Was it allowed?** No. The [onboarding pack](../../notes/onboarding-lowveld-logistics.md) says Domain Admins must contain exactly `socadmin` and `a-thabo.nkosi`, and any other member is an incident unless a change number covers it. The change register had nothing after 16 October. It also happened on a Sunday evening, using `socadmin`, the build and break-glass account.

**4. Was the backdoor used?** No. Zanele's account had no logons between being added and being removed.

```kql
SecurityEvent
| where TargetUserName =~ "zanele.mthembu" or MemberName has "Zanele"
| project TimeGenerated, Computer, EventID, Activity
```

**5. What else did the session do?** Apart from the PowerShell window used for the change, only normal first-login activity (Explorer, Edge setup, system tray), checked with process creation events (4688) for the session.

## Verdict

**True positive.** An unapproved change, outside office hours, made with the break-glass admin account, giving a Sales user rights she never needs. The most likely explanation in a real company is that someone had the `socadmin` password and was setting up a way back in (persistence, T1098).

## Containment

On DC01, in PowerShell:

```powershell
Remove-ADGroupMember -Identity "Domain Admins" -Members "zanele.mthembu" -Confirm:$false
Disable-ADAccount -Identity "zanele.mthembu"
Get-ADGroupMember "Domain Admins" | Select-Object Name   # socadmin, Thabo Nkosi (admin) only
```

Both actions show up in the logs (4729 and 4725), so the fix is as auditable as the attack.

**What I'd also do in a real company** (skipped in the lab so the build scripts keep working): reset the `socadmin` password, check who has access to it and to the SOC laptop, and look for other persistence on DC01: new accounts, scheduled tasks and services.

## Escalation

Per the onboarding pack, a High incident goes to Thabo Nkosi (IT Manager) by phone and email within 1 hour:

> **Subject: HIGH: unapproved change to Domain Admins on DC01 (incident #2)**
>
> Hi Thabo,
>
> At 17:05 SAST on Sunday 25 October, the admin account socadmin added zanele.mthembu (Sales) to Domain Admins on DC01. The change was made over Remote Desktop from the SOC laptop's Tailscale address. There's no matching change number, and it was outside office hours, so I'm treating it as a likely misuse of the socadmin account.
>
> **Done:** Zanele removed from Domain Admins and her account disabled (26 October, 13:28 SAST). Her account wasn't used while it had admin rights. Domain Admins is back to socadmin and a-thabo.nkosi only.
>
> **Needed from you:**
> 1. Confirm nobody approved this change.
> 2. Reset the socadmin password, and confirm who has access to it and to the SOC laptop.
> 3. Confirm with Zanele before we re-enable her account and she sets a new password.
>
> Details are in Sentinel incident #2.

## Tuning: one event, two incidents

The rule runs every **5 minutes** and looks back **10 minutes**, so the 15:05:55 event was caught by two runs in a row and opened two incidents. The wide look-back is deliberate: logs can arrive late (see below), and a 5-minute window would miss them. The fix was to switch on **incident grouping**: alerts with the same accounts and host within 1 hour now join one incident instead of opening a new one. Change made in [`deploy.sh`](../../detections/privileged-group-change/deploy.sh) and redeployed on 26 October.

## Lessons from running it

- **Logs lag after downtime.** After nine days switched off, the machines took about 15 minutes to send anything, and early events arrived 6 to 20 minutes late. A detection window shorter than that would have missed them.
- **The incident list is faster than the log tables.** Incidents showed in Sentinel's incident list before they appeared in the `SecurityIncident` table. Check the incident queue, not just KQL.
- **Read the failure code.** The six failed logons before the session were sub-status `0xC0000064`, meaning *the user doesn't exist*, not a wrong password (`0xC000006A`). That difference is how you tell password spraying (many usernames) from someone who forgot a password.
- **PowerShell logging pays off.** Script block logging (event 4104) recorded the exact command, which turned "someone changed the group" into "this command, from this session".
- **Remote access can drop for reasons outside the incident.** During containment, Tailscale on DC01 logged itself out about 40 seconds after a Remote Desktop sign-in, which cut the session. DC01 was signed back in with a one-time approval link and the `tag:lab-server` tag. The cause is still being checked.

After the exercise, Zanele's account was re-enabled for the next one (password spraying).
