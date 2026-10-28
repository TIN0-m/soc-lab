# SOC lab: a small Windows company, watched by Microsoft Sentinel

A security operations lab built in Azure (South Africa North) to practise the work of a SOC analyst: collecting the right logs, writing detections, investigating alerts and documenting what happened.

The lab simulates **Lowveld Logistics**, a fictional 19-person company with an Active Directory domain, a workstation, ordinary staff and some realistic weaknesses left in on purpose. Attacks against it are run from inside the lab, detected in Sentinel and Defender, and written up.

Everything is built with scripts, so the whole lab can be rebuilt or torn down in one go.

## What is built

| Step | What it adds | Docs |
|---|---|---|
| 01 Foundation | Budget alerts, resource group, private network with no inbound internet access | [01-foundation.md](build/01-foundation.md) |
| 02 Machines | Domain controller `DC01` and workstation `WS01` (Windows Server 2025), domain `soclab.internal` | [02-machines.md](build/02-machines.md) |
| 03 Access, users, logging | Admin access over Tailscale only, 19 staff accounts with planted weaknesses, an audit-policy baseline, Sysmon, PowerShell and command-line logging | [03-access-logging-users.md](build/03-access-logging-users.md) |
| 04 Sentinel and Defender | Log Analytics workspace, Microsoft Sentinel, Azure Monitor Agent with a data collection rule, Azure Activity log, Defender for Servers Plan 2 | [04-sentinel-defender.md](build/04-sentinel-defender.md) |

```
Analyst laptop ──Tailscale (RDP only)──► Azure, South Africa North
                                          ├─ DC01  10.10.1.4  domain controller + DNS
                                          ├─ WS01  10.10.1.5  workstation
                                          │    both: Sysmon, Azure Monitor Agent, Defender for Endpoint
                                          └─ law-soclab ─► Microsoft Sentinel
```

**Proof it ran:** [evidence/](evidence/) has the Sentinel query results (19,196 Windows security events and Sysmon activity from both machines), the live detection rule, and screenshots.

A plain-language map of every component is in [notes/lab-map.md](notes/lab-map.md). The fictional company's onboarding pack (people, assets, escalation, known risks) is in [notes/onboarding-lowveld-logistics.md](notes/onboarding-lowveld-logistics.md).

## Detections

| Detection | ATT&CK | Logic |
|---|---|---|
| [Member added to a privileged AD group](detections/privileged-group-change/) | T1098 Account Manipulation | Windows events 4728, 4732, 4756 for Domain Admins, Enterprise Admins and other privileged groups. Deployed as a Sentinel scheduled analytics rule. |
| [Password spray: one host failing against many accounts](detections/password-spray/) | T1110.003 Password Spraying | Event 4625 grouped by source host; fires when one host fails against 5+ distinct accounts in the window. |
| [Repeated failed logons for one account](detections/repeated-failed-logons/) | T1110 Brute Force | Event 4625 grouped by target account; fires on 10+ failures for one account. |
| [Dormant account re-enabled](detections/dormant-account-reenabled/) | T1098 Account Manipulation | Event 4722; a disabled account being switched back on. |
| [Security audit log cleared](detections/security-log-cleared/) | T1070.001 Clear Windows Event Logs | Event 1102; the Security log being wiped. |

## How alerts are worked

Every alert is triaged against a written [triage playbook](TRIAGE-PLAYBOOK.md): a 7-step flow, the evidence rules, and the three pivots (process tree, command line, Azure Activity Log). Each alert worked is written up below so the reasoning can be followed end to end.

## Investigations

| # | Case | Outcome |
|---|---|---|
| 01 | [Sales user added to Domain Admins](investigations/01-privileged-group-change/) | Detected in 10 minutes, contained, escalated; rule tuned to stop duplicate incidents |
| 02 | [Password spray from a workstation](investigations/02-password-spray/) | Found by hunting (no rule existed); two accounts compromised, contained; a detection rule was then written and deployed |
| 03 | [Security log cleared: authorised or breach?](investigations/03-security-log-cleared/) | Investigated across endpoint and cloud; determined benign true positive (authorised admin via Azure Run Command), proven with the Azure Activity Log |
| 04 | [Dormant account re-enabled](investigations/04-dormant-account-reenabled/) | Benign positive; a disabled account switched back on, confirmed authorised |
| 05 | [Malware detection on a workstation](investigations/05-eicar-malware/) | Benign positive; the threat name (EICAR) identified it as a harmless AV test file, already handled |
| 06 | [Brute force against one account](investigations/06-brute-force-single-account/) | True positive that **failed**; 15 attempts in 21s, no successful logon, no compromise |
| 07 | [Failed logons for a service account](investigations/07-service-account-failed-logons/) | Benign; a service account failing from the DC, a stale credential rather than an attack |
| 08 | [User added to a privileged group](investigations/08-backup-operators-change/) | High until proven; a SYSTEM-initiated group change confirmed authorised via the Azure Activity Log |

More follow the planted weaknesses: Kerberoasting, AS-REP roasting and misuse of a service account.

## Design choices worth knowing

- **No public IPs and no exposed RDP.** Administration goes through Tailscale, approved per device, with an access rule that allows only RDP to the lab servers.
- **No secrets in the repository.** Passwords are generated into a private file outside the repo and passed to the servers as protected parameters. The budget alert email is read from an environment variable.
- **Logging first.** The audit policy, Sysmon and PowerShell logging were set up and verified before the SIEM, because a detection is only as good as the events behind it.
- **Cost under control.** Free trial with the spending limit on, budget alerts at 25%, 50% and 75%, a 3 GB/day cap on ingestion, and auto-shutdown every night. The resource group is tagged with a delete-after date.

## Repository layout

```
build/          numbered build scripts (bash + Azure CLI) and a write-up for each step
build/scripts/  PowerShell run on the servers, plus ingestion and KQL helpers
detections/     one folder per detection: the KQL and the script that deploys it
evidence/       query results and screenshots showing the lab running
investigations/ one folder per case: timeline, queries, verdict, containment, escalation
notes/          lab map and the fictional company's onboarding pack
TRIAGE-PLAYBOOK.md   step-by-step alert triage flow and golden rules
```

## Status

Built 15 and 16 October 2026. Five detection rules and eight investigation write-ups (25 to 28 October 2026), each worked against a written triage playbook; more in progress. The lab is torn down by 14 November 2026, when the trial credit and the Defender trial end; the scripts and write-ups stay here.
