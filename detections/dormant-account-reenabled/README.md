# Dormant account re-enabled

Fires when a disabled account is re-enabled (Windows event 4722).

| | |
|---|---|
| Severity | Medium |
| Runs | every 5 min, 1h look-back |
| ATT&CK | T1098 Account Manipulation (Persistence) |
| Triage | Check for a change ticket. A dormant account re-enabled without one is an incident until proven authorised. |

Deployed as a Microsoft Sentinel scheduled analytics rule. Query: [query.kql](query.kql).
