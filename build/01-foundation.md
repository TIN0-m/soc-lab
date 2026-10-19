# 01: Foundation (budget, resource group, network)

**Date built:** 15 October 2026
**Script:** [`01-foundation.sh`](01-foundation.sh)
**Region:** South Africa North (Johannesburg)

## What this step creates

| Resource | Name | Purpose |
|---|---|---|
| Budget | `budget-soclab` | USD 200 (the full free trial credit), email alerts at USD 50, 100 and 150 actual spend, plus a warning if Azure forecasts the full 200 will be used |
| Resource group | `rg-soclab` | One container for every lab resource, tagged with project, owner and a delete-after date of 14 November 2026 |
| Network security group | `nsg-servers` | Firewall rules for the server subnet |
| Virtual network | `vnet-soclab` (10.10.0.0/16) | Private network for the lab |
| Subnet | `snet-servers` (10.10.1.0/24) | Where the domain controller and workstation live |

## Starting point

- Azure free trial subscription (quota ID `FreeTrial_2014-09-01`), spending limit **On**, USD 200 credit confirmed through the billing API.
- Regional limit in South Africa North: **4 vCPUs** and **3 public IPs**. This shaped the lab: two 2-vCPU Windows machines, with the SIEM (Microsoft Sentinel) running as a cloud service that uses no vCPU quota.
- Resource providers registered before building: Compute, Network, Storage, OperationalInsights, OperationsManagement, SecurityInsights, Security, Insights, DevTestLab.

## Design decisions

**1. No inbound access from the internet.**
Azure's default rules already deny inbound internet traffic (`DenyAllInBound`, priority 65500). I added an explicit `Deny-Internet-Inbound` rule at priority 4000 so the intent is written down and still holds if someone later adds a broad allow rule at a lower number. Administration goes through Tailscale, a private encrypted network, so RDP (port 3389) is never exposed. Exposed RDP remains one of the most common ways ransomware gets in.

Inbound rules after this step:

| Rule | Priority | Access | Source |
|---|---|---|---|
| Deny-Internet-Inbound | 4000 | Deny | Internet |
| AllowVnetInBound | 65000 | Allow | VirtualNetwork |
| AllowAzureLoadBalancerInBound | 65001 | Allow | AzureLoadBalancer |
| DenyAllInBound | 65500 | Deny | Any |

**2. No public IPs on the machines; outbound uses Azure default outbound access.**
The VMs need outbound internet for Windows Update, Tailscale and the log collection agent. Microsoft's recommended pattern is a NAT gateway, but that costs about USD 33 a month, which is a sixth of the whole budget. For a 30-day lab I enabled default outbound access on the subnet instead and recorded the trade-off here. In production I would use a NAT gateway or route outbound traffic through a firewall so it can be inspected.

**3. Cost guardrails before anything that costs money.**
The budget and alerts were created before any VM exists. The subscription's spending limit stops real charges, but the alerts give early warning so the lab does not freeze in the middle of the two weeks. The budget uses an annual time grain because the trial crosses a month boundary (15 October to 14 November) and a monthly budget would reset halfway.

**4. The alert email is not in the script.**
The script reads the alert address from the `ALERT_EMAIL` environment variable, so no personal email address is published in the repository.

## How to run

```bash
ALERT_EMAIL="you@example.com" bash build/01-foundation.sh
```

The script is safe to re-run. Each command creates the resource or updates it to the same end state.

## Verification

Checked with the Azure CLI after the run:

- Budget: amount 200, grain Annually, alerts `actual_25`, `actual_50`, `actual_75`, `forecast_100`.
- Subnet: range 10.10.1.0/24, `nsg-servers` attached, default outbound access true.
- Resources in `rg-soclab`: `nsg-servers`, `vnet-soclab`.

Evidence screenshots: `03-azure-budget-alerts.png`, `04-azure-network.png`.

## Next

[02: Domain controller and workstation](02-machines.md): DC01 and WS01, Active Directory, audit policy, Sysmon and Tailscale.
