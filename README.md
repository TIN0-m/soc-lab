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

## Investigations

| # | Case | Outcome |
|---|---|---|
| 01 | [Sales user added to Domain Admins](investigations/01-privileged-group-change/) | Detected in 10 minutes, contained, escalated; rule tuned to stop duplicate incidents |

More follow the planted weaknesses: password spraying, Kerberoasting, AS-REP roasting and misuse of a service account.

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
```

## Status

Built 15 and 16 October 2026. First investigation written up on 26 October 2026; more in progress. The lab is torn down by 14 November 2026, when the trial credit and the Defender trial end; the scripts and write-ups stay here.
