# 04: Microsoft Sentinel and Defender for Servers

**Date built:** 16 October 2026
**Script:** [`04-sentinel-defender.sh`](04-sentinel-defender.sh), ingestion check: [`scripts/check-ingestion.sh`](scripts/check-ingestion.sh)

This step gives the SOC its eyes. Every Windows log the previous step switched on now flows to a cloud SIEM, and both servers get an EDR.

## What this step creates

| Component | Name | Notes |
|---|---|---|
| Log Analytics workspace | `law-soclab` | South Africa North, **3 GB/day cap**, 90-day retention |
| SIEM | Microsoft Sentinel on `law-soclab` | 31-day free trial, up to 10 GB/day |
| Collection agent | Azure Monitor Agent (AMA) on DC01 and WS01 | Auto-upgrade on, authenticates with a system-assigned managed identity |
| Data collection rule | `dcr-soclab-windows` | Decides which events are shipped (below) |
| Activity log export | `activity-to-sentinel` | Every management action in the Azure subscription |
| EDR | Microsoft Defender for Servers **Plan 2** | 30-day free trial; onboards Defender for Endpoint on both VMs |

## What gets collected

| Source | Filter | Lands in table | Why |
|---|---|---|---|
| Windows Security log | All events | `SecurityEvent` | Logons, Kerberos, process creation, account and group changes, audit tampering |
| Sysmon | All events (filtering is done by the sysmon-modular config itself) | `Event` | Process trees and hashes, network connections per process, LSASS access, registry persistence, DNS per process |
| PowerShell Operational | 4103, 4104 | `Event` | Module and script block logging: the code that actually ran |
| System | 7045, 7040, 104 | `Event` | Service installed, service start type changed, **event log cleared** |
| Defender Antivirus | 1116, 1117, 5001, 5007 | `Event` | Malware detected, action taken, real-time protection disabled, configuration changed |
| Azure Activity | Administrative, Security, Policy, Alert, ServiceHealth | `AzureActivity` | Who changed what in Azure, including **Run Command** use on the VMs |

## Design decisions

**1. A daily cap well below the free allowance.** The trial covers 10 GB a day. The workspace is capped at 3 GB, so a runaway log source (for example a noisy Sysmon rule during an attack simulation) cannot burn the credit. The trade-off is that ingestion stops for the rest of the day if the cap is hit. In a real SOC that would be a blind spot, so a production workspace would alert on approaching the cap instead of hard-stopping.

**2. Filter at the source, not in the SIEM.** The data collection rule uses XPath filters, so only the events that matter leave the machine for PowerShell, System and Defender. Ingestion is what costs money in Sentinel, so the cheapest event is the one never sent. The Security log is shipped in full because nearly every identity detection depends on it.

**3. The agent authenticates with a managed identity.** There are no workspace keys on the VMs. The older Log Analytics agent used a shared workspace key; AMA uses the VM's Azure identity instead, so there is no secret to steal from the machine.

**4. Azure Activity in the same workspace.** Attacks on cloud-hosted servers often go through the cloud control plane, not the network. Someone with stolen Azure credentials can run code on a VM through Run Command without ever touching RDP. That action appears in `AzureActivity` as `MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMANDS/WRITE`. This lab's own build used Run Command, so the log already holds real examples of what it looks like.

**5. Defender for Servers Plan 2, not Plan 1.** Plan 2 adds vulnerability assessment, file integrity monitoring and just-in-time VM access on top of the Defender for Endpoint EDR. The vulnerability findings feed the vulnerability management exercise later.

## Cost and the end date

| Item | Cost during the lab |
|---|---|
| Sentinel and Log Analytics | USD 0 (31-day trial, under 10 GB/day) |
| Activity log ingestion | USD 0 (free data source) |
| Defender for Servers P2 | USD 0 for 30 days, then about USD 15 per server per month |

> **Teardown deadline: 14 November 2026.** Before the Defender trial ends (about 15 November), set the plan back to Free (`az security pricing create -n VirtualMachines --tier Free`) and delete `rg-soclab`. The subscription's spending limit would stop real charges, but leaving it running would eat the remaining credit.

## Build notes

Two problems came up on the first run, and both were fixed in the scripts:

- **Git Bash path conversion.** Git Bash on Windows rewrites any argument starting with `/` into a Windows path, so the workspace ID `/subscriptions/...` became `C:/Program Files/Git/subscriptions/...` and Azure rejected it (`LinkedInvalidPropertyId`). Fixed with `MSYS_NO_PATHCONV=1` in [`lib.sh`](lib.sh).
- **Request body from a file.** With path conversion off, `--body @/tmp/dcr.json` no longer pointed at a file the Windows Azure CLI could read, and Azure answered `UnsupportedMediaType`. The rule body is now passed inline.

## Verification

First ingestion check, about 10 minutes after the agents were installed (16 October 2026, 10:44 SAST):

```
Table          Computer                Events  Latest (UTC)
Event          DC01.soclab.internal    418     08:43:55
Event          WS01.soclab.internal    652     08:43:46
Heartbeat      DC01.soclab.internal    6       08:43:09
Heartbeat      WS01.soclab.internal    4       08:43:16
SecurityEvent  DC01.soclab.internal    122     08:43:32
SecurityEvent  WS01.soclab.internal    56      08:43:02
```

Defender for Servers: `VirtualMachines` plan, tier `Standard`, sub-plan `P2`, free trial remaining `29 days, 23:59`.

_Still to confirm: AzureActivity rows (export can take up to an hour to start) and both VMs showing as onboarded in Defender for Endpoint (can take a few hours)._

Evidence screenshots: `11-sentinel-first-query.png`, `12-defender-servers-plan2.png`, `13-defender-endpoint-devices.png`.

## Next

05: First detection, start to finish. Simulate a technique on WS01, find it in Sentinel with KQL, turn the query into an analytics rule, and confirm it raises an incident.
