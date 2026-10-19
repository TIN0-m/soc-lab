# Lab map: what every part is and what it does

Read this top to bottom once. Then try drawing it from memory.

## The picture

```
 YOUR LAPTOP (victus)
   │  Tailscale: private encrypted tunnel, RDP (3389) only
   ▼
┌──────────────────────── AZURE: South Africa North (Johannesburg) ────────────────────────┐
│  Subscription "Azure subscription 1"  (free trial, $200, spending limit on)               │
│  └─ Resource group rg-soclab  (the folder that holds everything below)                   │
│                                                                                          │
│   NETWORK                                   SECURITY TOOLS (cloud services)              │
│   vnet-soclab 10.10.0.0/16                  law-soclab   Log Analytics workspace         │
│   └─ snet-servers 10.10.1.0/24                           (the log database)              │
│      guarded by nsg-servers                 Microsoft Sentinel  (SIEM on top of it)      │
│      (no inbound from internet)             Defender for Servers P2 (EDR + vuln mgmt)    │
│                                             dcr-soclab-windows (which logs to collect)   │
│   ┌──────────────┐     ┌──────────────┐                                                  │
│   │ DC01 10.10.1.4│◄───►│ WS01 10.10.1.5│    Both machines run:                           │
│   │ Domain        │     │ Workstation   │    - Sysmon (detailed activity logging)        │
│   │ controller +  │     │ (where attacks│    - Azure Monitor Agent (ships logs)          │
│   │ DNS           │     │  happen)      │    - Defender for Endpoint (EDR sensor)        │
│   └──────────────┘     └──────────────┘    - Tailscale (admin access)                   │
└──────────────────────────────────────────────────────────────────────────────────────────┘
   Separate, in the cloud: Microsoft Entra ID (cloud identity: your Azure login lives here)
```

## Every component, in one line each

### Azure foundation
| Component | What it is | Why it's there |
|---|---|---|
| Subscription | The billing account that owns everything | Free trial, $200 credit, spending limit stops real charges |
| Resource group `rg-soclab` | A labelled folder for lab resources | Delete it and the whole lab is gone in one go |
| Budget `budget-soclab` | Spending alerts at $50, $100, $150 | Early warning before the credit runs out |
| VNet `vnet-soclab` | The private network, like an office LAN | Machines talk to each other privately |
| Subnet `snet-servers` | A section of that network | Where both servers live |
| NSG `nsg-servers` | A firewall rule list for the subnet | Blocks all inbound traffic from the internet |
| NIC (`DC01VMNic`, `WS01VMNic`) | Each VM's network card | Holds the private IP address |
| OS disk (`osdisk-dc01`, `osdisk-ws01`) | Each VM's hard drive (C:) | Storage is separate from compute in Azure |
| Auto-shutdown schedules | Turns VMs off at 23:00 | Saves money overnight |

### The company (identity)
| Component | What it is | Why it's there |
|---|---|---|
| DC01 | Domain controller | Logs people in (Kerberos/NTLM), stores Active Directory, pushes Group Policy, runs DNS |
| Active Directory `soclab.internal` | The on-premises directory of users, groups and computers | Lowveld Logistics' 19 staff, admins, service accounts |
| Group Policy "SOC - Security Logging Baseline" | Settings pushed to every machine | Turns on the audit logs a SOC needs |
| WS01 | An employee machine joined to the domain | Where simulated attacks happen |
| Entra ID | Microsoft's *cloud* directory | Holds your Azure login. Not connected to the lab's AD |

### Visibility (logs and detection)
| Component | What it is | Why it's there |
|---|---|---|
| Windows Security log | Built-in Windows audit log | Logons (4624/4625), processes (4688), group changes (4728)... |
| Sysmon | Microsoft tool that logs extra detail | Process trees, network connections per process, DNS, registry changes |
| Azure Monitor Agent (AMA) | A small agent on each VM | Picks up the logs and sends them to Azure |
| Data collection rule `dcr-soclab-windows` | The instructions for AMA | Says *which* logs to send (all Security, Sysmon, PowerShell 4104...) |
| Log Analytics workspace `law-soclab` | The cloud database the logs land in | Tables: `SecurityEvent`, `Event`, `AzureActivity`, `Heartbeat` |
| Microsoft Sentinel | The SIEM, sitting on top of the workspace | Analytics rules search the logs and raise incidents |
| Analytics rule | A saved KQL query that runs on a schedule | "If someone is added to Domain Admins, create an incident" |
| Defender for Endpoint | EDR sensor on each VM | Watches behaviour, raises alerts, can isolate a machine |
| Defender for Cloud | Azure's security posture dashboard | Recommendations, secure score, vulnerability findings |
| Azure Activity log | Azure's own audit trail | Who created, changed or ran things in Azure (including Run Command) |

### Access and management
| Component | What it is | Why it's there |
|---|---|---|
| Tailscale | Private encrypted network between laptop and VMs | RDP without exposing anything to the internet |
| Tailscale ACL + `tag:lab-server` | Tailscale's own firewall rules | Only your laptop, only RDP |
| Azure CLI (`az`) | Command-line control of Azure | Builds everything from scripts (infrastructure as code) |
| Run Command | Run a script inside a VM through Azure | Management "back door" (useful to us, dangerous with stolen logins) |

## The journey of one event

When someone adds Ruan to Domain Admins on DC01:

1. **DC01** writes event **4728** (member added to a global security group) to its **Security log**. This happens because the logging **Group Policy** turned on "Security Group Management" auditing.
2. **Azure Monitor Agent** on DC01 reads it. The **data collection rule** says "send everything from the Security log".
3. It lands in **law-soclab**, table **SecurityEvent**, within about 5 to 10 minutes.
4. Every 5 minutes, **Sentinel's analytics rule** runs its KQL query over the last 10 minutes and finds the 4728 for "Domain Admins".
5. Sentinel creates an **incident**. That is where an analyst picks it up, triages it and responds (removes Ruan, finds out who did it and why).

Logs ≠ detection: without step 4, the event sits in the database and nobody is told.

## "I need to... so I go to..."

| I need to... | Go to |
|---|---|
| See the alerts I have to work on | **Sentinel → Incidents** |
| Search logs with KQL | **Sentinel → Logs** (or law-soclab → Logs) |
| Create or tune a detection | **Sentinel → Analytics** |
| Check which data sources are connected | **Sentinel → Data connectors** |
| See a machine's full activity timeline / isolate it | **Defender portal (security.microsoft.com) → Assets → Devices** |
| Check vulnerabilities and security recommendations | **Defender for Cloud → Recommendations**, or Defender portal → Vulnerability management |
| Find a user, reset a password, change group membership | **DC01 → Active Directory Users and Computers** (or PowerShell) |
| See or change policies pushed to machines | **DC01 → Group Policy Management** |
| Check who logged in to Azure / cloud sign-ins | **Entra ID → Sign-in logs** |
| See who changed something in Azure | **Monitor → Activity log**, or the `AzureActivity` table in Sentinel |
| Check firewall rules on the network | **VM → Networking**, or `nsg-servers` |
| Check what the lab costs | **Cost Management → Cost analysis** |
| Get into a machine | **Remote Desktop to dc01 / ws01 over Tailscale** |

## Words to know

- **SIEM:** collects logs from everywhere and searches them for threats (Sentinel).
- **EDR:** an agent on each machine that watches behaviour and can respond (Defender for Endpoint).
- **XDR:** EDR stretched across endpoints, email, identity and cloud, with alerts correlated together (Microsoft Defender XDR).
- **SOAR:** automation that responds to alerts (Sentinel playbooks / Logic Apps).
- **KQL:** the query language for Sentinel and Defender.
- **Workspace:** the database behind Sentinel.
- **Analytics rule → alert → incident:** a rule's query finds something, which creates an alert; alerts are grouped into incidents that analysts work.
