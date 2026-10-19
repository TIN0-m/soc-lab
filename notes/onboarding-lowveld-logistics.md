# Client onboarding pack: Lowveld Logistics (Pty) Ltd

> **Fictional company.** Lowveld Logistics exists only in this lab. The people, phone numbers and business details are invented; the network, accounts and systems are real and match the lab exactly. Items marked *(simulated)* are part of the story but not actually running.

**Prepared for:** SOC analyst assigned to this client
**Your role:** you work for a managed security provider (an MSSP, like Integrity360 or S-RM) that monitors Lowveld Logistics' environment around the clock. You watch, investigate and advise. Lowveld's own IT team makes changes on their side unless they ask you to act.

---

## 1. The business in one minute

| | |
|---|---|
| What they do | Road freight and warehousing across Mpumalanga and Gauteng |
| Head office | Mbombela (Nelspruit) *(story)* |
| Staff on the network | 19 employees, 1 IT admin account, 2 service accounts |
| Office hours | Monday to Friday, 07:30 to 17:00 SAST |
| Early shift | **Operations dispatch starts at 05:00** (dispatchers log on early, and that is normal) |
| What would hurt most | Losing the domain (nobody can log in), finance data leaking, or dispatch stopping (trucks don't move, money is lost every hour) |
| Regulation | POPIA applies: they hold staff and customer personal information. A breach must be reported to the Information Regulator and affected people as soon as reasonably possible (section 22). |

## 2. Who's who

### Contacts for incidents *(fictional)*

| Role | Person | When to contact |
|---|---|---|
| IT Manager (incident owner) | Thabo Nkosi | **All** confirmed incidents, High and Critical immediately |
| Service desk | Kagiso Molefe | Password resets, account unlocks, user questions |
| Systems Administrator | Sipho Ndlovu | Server and change questions |
| CFO | David Naidoo | Anything touching finance data or payments |
| HR Manager | Nomsa Khumalo | Suspected insider activity, leavers |
| CEO | Grace Moloi | Critical incidents only, through Thabo |

### Departments (Active Directory OU `Corp\Users`)

| Department | People | Group |
|---|---|---|
| Executive | Grace Moloi (CEO), David Naidoo (CFO) | `GG_Executive` |
| Finance | Lerato Mokoena (Finance Manager), Pieter van Wyk (Accountant), Ayanda Dlamini (Accounts Clerk) | `GG_Finance` |
| HR | Nomsa Khumalo (HR Manager), Fatima Patel (HR Officer) | `GG_HR` |
| IT | Thabo Nkosi (IT Manager), Kagiso Molefe (Service Desk), Sipho Ndlovu (Systems Admin) | `GG_IT`, `GG_Helpdesk` |
| Sales | Johan Botha (Sales Manager), Zanele Mthembu, Naledi Sithole, Ruan Pretorius (Sales Reps) | `GG_Sales` |
| Operations | Bongani Zulu (Ops Manager), Chantelle Adams (Logistics Coordinator), Tshepo Maluleke (Dispatcher), Anele Ngcobo (Warehouse Supervisor), Megan Smith (Fleet Coordinator) | `GG_Operations` |

Usernames are `firstname.lastname`, for example `lerato.mokoena`. Everyone is in `GG_AllStaff`.

### Privileged and special accounts (watch these closely)

| Account | What it is | Normal behaviour |
|---|---|---|
| `a-thabo.nkosi` | Thabo's separate **admin** account, Domain Admins | Used only for admin work, only from IT, during office hours unless there's a change |
| `socadmin` | Built-in domain admin created at setup, Domain Admins | Lab owner's build and break-glass account |
| `svc_sql` | Service account for the fleet dispatch database *(simulated)*, password never expires | Runs a service. **Should never log on interactively** (no RDP, no console) |
| `svc_backup` | Nightly backup account, in Backup Operators | Backup job at 01:00 *(simulated)*. **Should never log on interactively** |
| `brian.jacobs` | Former sales rep, left 31 August 2026, **disabled** | **Should do nothing at all.** Any activity is an incident |

**Domain Admins should contain exactly:** `socadmin`, `a-thabo.nkosi`. Anyone else is an incident until a change ticket proves otherwise.

## 3. Network

### Diagram

```
                         INTERNET
                            │
            (no inbound: nsg-servers denies all internet traffic)
                            │  outbound only (updates, agents)
┌──────────── Azure VNet vnet-soclab 10.10.0.0/16 · South Africa North ────────────┐
│                                                                                 │
│   Subnet snet-servers 10.10.1.0/24                                              │
│                                                                                 │
│      ┌────────────────────┐            ┌────────────────────┐                   │
│      │ DC01  10.10.1.4    │◄──────────►│ WS01  10.10.1.5    │                   │
│      │ Domain controller  │  Kerberos, │ Domain workstation │                   │
│      │ DNS for the domain │  LDAP, DNS,│ (staff machine)    │                   │
│      │ Group Policy       │  SMB, GPO  │                    │                   │
│      └────────────────────┘            └────────────────────┘                   │
│            │ logs (AMA)                       │ logs (AMA)                       │
└────────────┼──────────────────────────────────┼─────────────────────────────────┘
             ▼                                  ▼
      Log Analytics workspace law-soclab  ──►  Microsoft Sentinel (SIEM)
      Defender for Endpoint (EDR) on both machines ──► Defender portal

  SOC analyst laptop ──(Tailscale, RDP 3389 only)──► dc01 / ws01
```

### Address plan

| Name | Address | Role |
|---|---|---|
| Network | 10.10.0.0/16 | Whole virtual network |
| Server subnet | 10.10.1.0/24 | DC01 and WS01 (Azure reserves .0 to .3 and .255) |
| DC01 | 10.10.1.4 | Domain controller, DNS |
| WS01 | 10.10.1.5 | Workstation |
| Azure DNS | 168.63.129.16 | DC01 forwards internet lookups here |
| Tailscale: SOC laptop | 100.x.x.x | Analyst access |
| Tailscale: dc01 / ws01 | 100.x.x.x / 100.x.x.x | Admin access path |

**Domain:** `soclab.internal` (NetBIOS `SOCLAB`). **DNS for every machine:** DC01 (10.10.1.4).

### What traffic is normal

| From | To | What | Normal? |
|---|---|---|---|
| WS01 | DC01 | Kerberos (88), LDAP (389), DNS (53), SMB (445) for Group Policy | Yes, constantly |
| DC01, WS01 | Internet | Windows Update, Defender, Azure agents, Tailscale | Yes |
| SOC laptop | dc01, ws01 | RDP 3389 over Tailscale | Yes, during shifts |
| Internet | anything | Anything inbound | **Never** (blocked by the NSG) |
| WS01 | another WS01-type machine | SMB/RDP between workstations | **Suspicious**: workstations shouldn't talk to each other |
| Anything | Laptop | Anything | **Blocked** by the Tailscale ACL |

## 4. Asset register

| Asset | Type | Criticality | Why |
|---|---|---|---|
| DC01 | Domain controller | **Critical** | Whoever controls it controls every account and machine |
| Active Directory | Identity | **Critical** | All logons depend on it |
| Finance data (`GG_Finance`) *(simulated file share)* | Data | **High** | Payments, invoices, bank details: fraud target |
| HR data (`GG_HR`) *(simulated)* | Personal information | **High** | POPIA: staff ID numbers, salaries |
| Fleet dispatch database (SQL on WS01, `svc_sql`) *(simulated)* | Business system | **High** | If it stops, trucks stop |
| WS01 | Workstation | Medium | One machine, but a stepping stone to DC01 |
| Azure subscription / Entra ID | Cloud control plane | **Critical** | Control of Azure = control of every VM (Run Command) |

## 5. What you can see (log sources)

| Source | Table in Sentinel | Covers |
|---|---|---|
| Windows Security log (DC01, WS01) | `SecurityEvent` | Logons, Kerberos, processes with command lines, account and group changes, audit tampering |
| Sysmon | `Event` (Source = Microsoft-Windows-Sysmon) | Process trees and hashes, network connections, DNS per process, registry, LSASS access |
| PowerShell | `Event` (4103, 4104) | Code that PowerShell ran |
| System log (selected) | `Event` (7045, 7040, 104) | Services installed, log cleared |
| Defender Antivirus | `Event` (1116, 1117, 5001, 5007) | Malware found, protection turned off |
| Azure Activity | `AzureActivity` | Changes in Azure, including Run Command |
| Agent health | `Heartbeat` | Is each machine still reporting? |
| Defender for Endpoint | Defender portal (advanced hunting) | EDR alerts, device timeline |

**Blind spots (know these):** no email logs (no mail server), no firewall appliance logs, no Entra ID sign-in logs yet, and Sentinel is capped at 3 GB a day (if the cap is hit, logs stop until midnight UTC).

## 6. How the SOC works for this client

### Severity and response times

| Severity | Examples | Respond within | Tell the client |
|---|---|---|---|
| **Critical** | Domain admin compromised, ransomware, DC01 unreachable, mass data theft | 15 minutes | Phone Thabo immediately |
| **High** | Unapproved privileged group change, confirmed malware not blocked, account takeover | 1 hour | Phone and email Thabo |
| **Medium** | Malware blocked, suspicious logon pattern, password spray with no success | 4 hours | Email in the daily summary or sooner |
| **Low** | Policy deviation, single failed logons, informational | Next business day | Daily summary |

### Approved changes

Lowveld logs planned changes in a change register. **A change with a matching change number is a benign true positive. Without one, it's an incident.** Ask Thabo or Sipho when unsure.

| Change | What | When | Approved by |
|---|---|---|---|
| CHG-001 | Lab build: domain, users, Group Policy, Sysmon, Sentinel | 15 to 16 October 2026 | Thabo Nkosi |
| CHG-002 | Tailscale ACL and server tags | 16 October 2026 | Thabo Nkosi |
| *(none yet)* | *Any change to Domain Admins after 16 October* | | |

### Escalation path

1. **You (L1):** triage, investigate, verdict, contain within your permissions, document.
2. **Senior analyst (L2):** anything High or Critical, anything you're not sure about, any containment beyond isolating a machine.
3. **Client (Thabo Nkosi):** every confirmed incident, with your ticket note.

### Shift handover

Every shift ends with a handover note: open incidents, what you did, what's still unknown, and what the next analyst should watch.

## 7. Known risks (client's own risk register)

| # | Risk | Status |
|---|---|---|
| R1 | Some staff use weak, seasonal passwords | Open: password policy review planned |
| R2 | Service account passwords never expire | Open: accepted by IT for now |
| R3 | No MFA on internal domain logons | Open |
| R4 | Backup account has broad read rights on DC01 | Open |
| R5 | No email filtering logs available to the SOC | Open: blind spot |

*Not every weakness is on the client's register. Finding the ones that aren't is part of the job.*

## 8. Test yourself (after reading)

1. At 05:20 on a Tuesday, `tshepo.maluleke` logs on to WS01. Normal or suspicious? Why?
2. `svc_backup` appears in a 4624 with logon type 10. What does that mean, and what severity?
3. `brian.jacobs` has a failed logon (4625). What do you do?
4. `sipho.ndlovu` is added to Domain Admins at 14:00 on a weekday. There's no change number. What's the verdict, and who do you call?
5. Which single machine would you protect first if you could only protect one, and why?
6. Name two things the SOC **cannot** see in this environment.
