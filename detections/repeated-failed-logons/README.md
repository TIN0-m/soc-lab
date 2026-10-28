# Repeated failed logons for one account

Fires when one account has 10+ failed logons in the window (event 4625).

| | |
|---|---|
| Severity | Medium |
| Runs | every 10 min, 10 min look-back (tuned to avoid re-alerting the same burst) |
| ATT&CK | T1110 Brute Force (Credential Access) |
| Triage | Check the source and whether any attempt **succeeded** (a 4624). A service account failing from a server is usually a stale credential, not an attack; a user account hammered from a workstation is more likely real. |

Deployed as a Microsoft Sentinel scheduled analytics rule. Query: [query.kql](query.kql).
