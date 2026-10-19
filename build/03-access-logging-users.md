# 03: Access, users and logging

**Date built:** 16 October 2026
**Scripts:** [`03a-tailscale.sh`](03a-tailscale.sh), [`03b-logging-users.sh`](03b-logging-users.sh), PowerShell in [`scripts/`](scripts/)

This step turns two bare servers into a small company that a SOC can watch. It covers private admin access, a realistic directory of staff, and the Windows logging that detections depend on.

## 1. Private access with Tailscale

| Device | Tailscale IP | Role |
|---|---|---|
| `victus` | 100.x.x.x | Analyst laptop |
| `dc01` | 100.x.x.x | Domain controller |
| `ws01` | 100.x.x.x | Workstation |

- Tailscale was installed on DC01 and WS01 through Azure Run Command. The script **checks the installer's Authenticode signature** and refuses to install unless it is validly signed by Tailscale Inc.
- Unattended mode keeps Tailscale running as a Windows service with nobody logged in.
- Each server printed a one-time login URL, and I approved it in my own Tailscale account. **No auth keys were created**, so there is no reusable secret that could leak.
- RDP (TCP 3389) was confirmed reachable on both servers **only over Tailscale**. The Azure NSG still denies all inbound internet traffic.

## 2. Lowveld Logistics in Active Directory

A fictional logistics company gives the logs realistic users, departments and behaviour to work with.

**OU layout**

```
soclab.internal
└── Corp
    ├── Users
    │   ├── Executive   (2)
    │   ├── Finance     (3)
    │   ├── HR          (2)
    │   ├── IT          (3)
    │   ├── Sales       (4)
    │   └── Operations  (5)
    ├── Groups            GG_<department>, GG_AllStaff, GG_Helpdesk
    ├── Workstations      WS01
    ├── Service Accounts  svc_sql, svc_backup
    ├── Admin Accounts    a-thabo.nkosi
    └── Disabled Users    brian.jacobs
```

- 19 staff accounts with department, job title and company set, plus a group per department.
- WS01 was moved out of the default `Computers` container into `Corp\Workstations` so that policy can target it. The default container cannot have Group Policy linked to it.
- The IT manager has a **separate admin account** (`a-thabo.nkosi`, Domain Admins) apart from his everyday account. Keeping daily and privileged identities apart is basic tiering, and it means a phished everyday account does not hand over the domain.
- The leaver `brian.jacobs` is disabled and kept, not deleted, so his history stays auditable.

### Weaknesses planted on purpose

Real environments have these, and later exercises attack them so there is something genuine to detect. All passwords are random except the ones below, which are deliberately weak and stored only in the private env file.

| Account | Weakness | Exercise it supports | What a SOC should see |
|---|---|---|---|
| `zanele.mthembu`, `tshepo.maluleke` | Same weak seasonal password (season + year + symbol) | Password spraying | Many 4625/4771 failures across accounts from one source, then a success |
| `svc_sql` | Service Principal Name `MSSQLSvc/ws01.soclab.internal:1433` with a wordlist password, never expires | Kerberoasting | 4769 service ticket requests with RC4 encryption (0x17) for a user-account SPN |
| `megan.smith` | Kerberos pre-authentication disabled | AS-REP roasting | 4768 with pre-authentication type 0 |
| `svc_backup` | Member of Backup Operators, which can read any file on a DC including `NTDS.dit` | Privilege abuse | 4672 special logon, use of backup privileges, shadow copy activity |

Verified from DC01 after the run:

```
Accounts created this run: 23
Staff per department: Executive 2, Finance 3, HR 2, IT 3, Sales 4, Operations 5
Domain Admins: socadmin, a-thabo.nkosi
Kerberoastable (user accounts with an SPN): svc_sql
AS-REP roastable (no pre-auth): megan.smith
Disabled: brian.jacobs
WS01 is in: CN=WS01,OU=Workstations,OU=Corp,DC=soclab,DC=internal
```

## 3. Logging baseline: "SOC - Security Logging Baseline" GPO

One Group Policy Object linked at the domain root, so it reaches every machine, DC01 included.

**Advanced audit policy (28 subcategories).** These are the ones detections lean on most:

| Subcategory | Setting | Key events |
|---|---|---|
| Logon | Success and Failure | 4624, 4625 |
| Credential Validation | Success and Failure | 4776 (NTLM) |
| Kerberos Authentication Service | Success and Failure | 4768, 4771 |
| Kerberos Service Ticket Operations | Success and Failure | 4769 |
| Process Creation | Success | 4688 |
| User Account Management | Success and Failure | 4720, 4722, 4724, 4740 |
| Security Group Management | Success | 4728, 4732, 4756 |
| Directory Service Access | Success and Failure | 4662 (DCSync) |
| Other Object Access Events | Success and Failure | 4698 (scheduled task created) |
| Security System Extension | Success | 4697 (service installed) |
| Audit Policy Change | Success | 4719 (someone tampered with auditing) |

The full list is in [`scripts/dc-gpo-logging.ps1`](scripts/dc-gpo-logging.ps1).

**Other settings in the same GPO**

- **Command line in process creation events.** Without this, 4688 says only that `powershell.exe` ran. With it, you see what it was told to do.
- **PowerShell script block logging (4104) and module logging (4103).** These record the code PowerShell actually executes, after de-obfuscation.
- **"Force audit policy subcategory settings"** (`SCENoApplyLegacyAuditPolicy`), so the old category-level policy cannot quietly override the advanced one.
- **Bigger logs:** Security 256 MB, System 64 MB, so evidence is not overwritten within hours.

**How it was built:** the registry settings use `Set-GPRegistryValue`. The advanced audit policy is written as `audit.csv` inside the GPO, the same file the Group Policy editor produces, with subcategory GUIDs read from `auditpol /list /subcategory:* /v` on the DC. The GPO is then registered for the Advanced Audit client-side extension and its version is bumped so clients re-apply it.

**Verified on both machines** after `gpupdate /force`:

| Check | DC01 | WS01 |
|---|---|---|
| GPO listed in `gpresult` | Yes | Yes |
| Script block logging | On | On |
| Command line in 4688 | On | On |
| Logon / Credential Validation / Other Object Access | Success and Failure | Success and Failure |
| Process Creation | Success | Success |
| Fresh 4688 includes full command line | Yes | Yes |
| Fresh 4104 present | Yes | Yes |
| Sysmon running and logging | Yes | Yes |

**Log size: delivered, applies at next boot.** The policy value (Security `MaxSize` 262144 KB) is present on WS01, but the Event Log service only picks up a new size when it restarts, so `wevtutil gl Security` still showed 20 MB on the day. Re-checked after the nightly shutdown: _pending_.

## 4. Sysmon

- Microsoft Sysinternals Sysmon, downloaded from `download.sysinternals.com`. The script checks that `Sysmon64.exe` is validly signed by Microsoft Corporation before installing.
- Configuration: the **balanced** profile from Olaf Hartong's [sysmon-modular](https://github.com/olafhartong/sysmon-modular), mapped to MITRE ATT&CK.
  - **Pinned to release `configs-a45dedb13a43`** rather than "latest". The project moved its prebuilt configs into GitHub Releases on 14 October 2026, which broke the old download path two days later, a small real-world reminder of why you pin versions.
  - The config's SHA256 is checked against the release's `SHA256SUMS` manifest before it is applied.

- **Two fixes were needed during the build, and both are recorded here.** The first run hit the moved config path (HTTP 404). The second run showed that Sysmon prints its banner to stderr, which Windows PowerShell 5.1 turns into a terminating error under `$ErrorActionPreference = "Stop"`. The script now relaxes that preference just for the native call and judges success by Sysmon's exit code.

Install result (both machines):

```
Sysmon installed on DC01 / WS01
Binary version: 15.22, signed by: CN=Microsoft Windows Publisher (O=Microsoft Corporation)
Config: sysmonconfig-15.21.xml from release configs-a45dedb13a43, schema 4.91,
        SHA256 64BEC37BA849C5F2934A55D2A29E7DDFAE46A30D56F7F2908D1F8A454898797E (matches SHA256SUMS)
Service: Running
```

Live on WS01 a few minutes later: the last 200 Sysmon events included IDs **1** (process create), **3** (network connection), **7** (image loaded), **10** (process access), **11** (file create), **12/13** (registry), **17** (pipe created), **22** (DNS query) and **26** (file delete logged).

## 5. Tailscale access policy (least privilege on the admin network)

Tailscale's default policy lets every device reach every port on every other device. I replaced it with one rule: my own user's devices may reach anything tagged `lab-server`, on RDP only. Everything else is denied by default, including the servers connecting back to the laptop.

```json
{
  "tagOwners": { "tag:lab-server": ["autogroup:admin"] },
  "acls": [
    { "action": "accept", "src": ["autogroup:member"], "dst": ["tag:lab-server:3389"] }
  ],
  "ssh": []
}
```

DC01 and WS01 are tagged `tag:lab-server`. Tagged devices belong to the tailnet rather than to a user, and their node keys do not expire.

**Verified from both sides (16 October 2026):**

| From | To | Port | Result |
|---|---|---|---|
| Laptop | dc01, ws01 | 3389 (RDP) | Open |
| Laptop | dc01, ws01 | 445 (SMB) | Blocked |
| Laptop | dc01, ws01 | 5985 (WinRM) | Blocked |
| dc01 | Laptop | 445, 3389 | Blocked |

### Incident: lost RDP to WS01 while applying tags

My RDP session to WS01 dropped and reconnecting failed with "Remote Desktop can't connect to the remote computer". Troubleshooting, in order:

1. **Power:** Azure showed WS01 running.
2. **Network path:** Tailscale showed `ws01` offline, while `dc01` on the same network still answered on 3389. That narrowed it to WS01 itself.
3. **Restart:** last boot was 07:54, hours earlier, and the only updates were Defender definition updates. It had not rebooted.
4. **Agent:** checked through Azure Run Command, because RDP was unavailable. The Tailscale service was **Running** but its state was **Logged out**.

**Root cause:** WS01's Tailscale node was signed out while it changed from user-owned to tagged. DC01 made the same change without a problem.
**Fix:** re-ran `tailscale up --advertise-tags=tag:lab-server` on WS01 through Run Command and approved the new login. It came back tagged, on a direct (not relayed) connection.
**Lesson:** keep an out-of-band management path. Here Azure Run Command was the way back in when the admin network failed. Tag changes are also safer done one device at a time, checking each before moving on.

## Known gaps and next hardening

- **No log forwarding yet.** Everything above lands in local Windows event logs. Step 04 ships it to Microsoft Sentinel.

Evidence screenshots: `06-ad-domain-computers.png`, `07-tailscale-three-machines.png`, `08-ad-corp-ou.png`, `09-gpo-logging-baseline.png`, `10-sysmon-events.png`.
