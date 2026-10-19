# 02: Machines and Active Directory domain

**Date built:** 15 October 2026
**Script:** [`02-machines.sh`](02-machines.sh)

## What this step creates

| Machine | Private IP | Role | Size | OS |
|---|---|---|---|---|
| `DC01` | 10.10.1.4 | Domain controller and DNS for `soclab.internal` | Standard_B2als_v2 (2 vCPU, 4 GiB) | Windows Server 2025 Datacenter |
| `WS01` | 10.10.1.5 | Domain-joined workstation, the target for simulated attacks | Standard_B2als_v2 (2 vCPU, 4 GiB) | Windows Server 2025 Datacenter |

Both machines:
- have **no public IP** and sit behind `nsg-servers`, which denies all inbound internet traffic;
- use **Trusted Launch** (Secure Boot and a virtual TPM), which protects against bootkits and rootkits that load before Windows;
- have a 64 GB Standard SSD OS disk;
- **shut down automatically at 23:00** South Africa time (21:00 UTC) to protect the budget;
- get Windows updates automatically (`AutomaticByOS` patch mode).

## Design decisions

**1. Windows Server as the workstation.**
Azure only allows Windows 10/11 client images for customers who already hold an eligible Windows licence, which a free trial does not include. Windows Server 2025 produces the same Security event log, PowerShell logging and Sysmon telemetry, and the attack techniques used in this lab work the same way on it. Plenty of real intrusions also land on servers first.

**2. Domain name `soclab.internal`.**
`.internal` was reserved by ICANN in 2024 for private networks, so it can never clash with a real internet domain. The older habit of using `.local` causes conflicts with multicast DNS (mDNS).

**3. Size chosen to fit the free trial quota.**
The free trial allows 4 vCPUs per region. Two 2-vCPU machines use exactly that. Standard_B2als_v2 was the cheapest 4 GiB size in South Africa North at USD 0.058 an hour with the Windows licence included (Azure retail price API, 15 October 2026).

**4. Smaller disks to save money.**
The default Windows image has a 127 GB disk (E10 Standard SSD, USD 14.02 a month in South Africa North). I used the small-disk image and grew it to 64 GB (E6, USD 7.01 a month), then extended the C: partition into the new space. This halves disk cost with plenty of room for a lab server.

**5. No passwords in the repository or the chat.**
Admin and Directory Services Restore Mode (DSRM) passwords are generated randomly (24 characters) into a private env file outside the repository. The script reads that file and passes the passwords to the VMs as **protected run-command parameters**, which Azure encrypts and does not return in command output.

**6. Configured through Azure Run Command, not RDP.**
Domain promotion, DNS forwarding and the domain join all run through `az vm run-command`, so the machines were fully set up before any remote desktop access existed. Run Command runs as SYSTEM through the Azure VM agent. That makes it a powerful admin tool and, for the same reason, something attackers abuse once they hold Azure credentials. It is worth watching for in the Azure Activity log.

## Build sequence

1. Create DC01 and WS01 with static private IPs and auto-shutdown.
2. Extend the C: partition on both to use the full 64 GB.
3. Promote DC01: install AD DS and create the forest `soclab.internal` (NetBIOS `SOCLAB`) with DNS, then restart.
4. After restart: wait for Active Directory to respond, then add Azure DNS (168.63.129.16) as a forwarder so the domain controller can resolve internet names.
5. Point the virtual network's DNS at DC01 (10.10.1.4) and restart WS01 so it picks this up.
6. Join WS01 to `soclab.internal`, then restart.
7. Confirm from DC01 that WS01 appears as a domain computer.

## Cost

| Item | Rate | Month at about 12 hours a day |
|---|---|---|
| 2 x Standard_B2als_v2, Windows | USD 0.058/hour each | about USD 42 |
| 2 x 64 GB Standard SSD (E6) | USD 7.01/month each | USD 14 |
| **Total** | | **about USD 56** of the USD 200 credit |

## Verification

From the build run on 15 October 2026 (every run command finished with state `Succeeded`, exit code 0):

```
DC01 created at 10.10.1.4, auto-shutdown 23:00 SAST
WS01 created at 10.10.1.5, auto-shutdown 23:00 SAST
C: is now 64 GB                       (DC01 and WS01)
Forest soclab.internal created, reboot required
Domain: soclab.internal  NetBIOS: SOCLAB  DC: DC01
Forwarders: 168.63.129.16
WS01 joined soclab.internal, reboot required
```

Domain computers listed from DC01 after the join:

```
Name DNSHostName          Enabled
---- -----------          -------
DC01 DC01.soclab.internal    True
WS01 WS01.soclab.internal    True
```

`az vm list -d` shows both machines with a private IP and an empty public IP field.

### Two expected warnings during promotion

- **"Network adapter does not have static IP addresses assigned."** In Azure the IP is made static on the network interface in Azure (10.10.1.4 here), and Windows keeps DHCP inside the VM. Microsoft's guidance for domain controllers in Azure is to leave the guest on DHCP, because hard-coding the IP inside Windows can cut the VM off if the Azure side changes. The warning is expected and safe to ignore here.
- **"A delegation for this DNS server cannot be created."** There is no parent `internal` zone to delegate from, because this is a new private forest. No action is needed.

Evidence screenshots: `05-vms-running-no-public-ip.png` (portal list of virtual machines), `06-ad-domain-computers.png` (Active Directory Users and Computers on DC01, taken once remote access is set up in step 03).

## Next

03: Logging and users. Windows audit policy, PowerShell logging, Sysmon, a realistic set of users and groups, and Tailscale for access.
