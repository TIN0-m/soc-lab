# Security audit log cleared

Fires when the Windows Security event log is cleared (event 1102).

| | |
|---|---|
| Severity | High |
| Runs | every 5 min, 1h look-back |
| ATT&CK | T1070.001 Clear Windows Event Logs (Defense Evasion) |
| Triage | Rarely legitimate. Find who/what cleared it (the 1102 Subject, the process tree, and for a management-plane action the Azure Activity Log) and whether it was authorised. See [investigation 03](../../investigations/03-security-log-cleared/). |

Deployed as a Microsoft Sentinel scheduled analytics rule. Query: [query.kql](query.kql).
