# Shift log

Day-to-day alert triage: alerts that came into the queue, were worked and closed.
These are the fast calls a Tier 1 analyst makes on shift. The deeper cases that
needed a full write-up are in [investigations/](investigations/). Every verdict
below was backed by the specific events named.

Worked against the [triage playbook](TRIAGE-PLAYBOOK.md).

| Date | Alert | Verdict | Key evidence | Action |
|---|---|---|---|---|
| 27 Oct | Dormant account re-enabled (brian.jacobs) | Benign positive | 4722 enable with no change ticket; authorised lab/admin activity | Closed benign |
| 28 Oct | EICAR_Test_File malware prevented (WS01) | Benign positive | Threat name = EICAR, the standard AV test file, not real malware; Defender handled it | Closed; noted "check who placed it (can also be an attacker probing defences)" |
| 28 Oct | Brute force against pieter.vanwyk | **True positive (failed)** | 15 × 4625 in 21s from WS01, **no 4624 success** | Monitor the account; flag WS01 as a recurring source; no compromise to escalate |
| 28 Oct | Repeated failed logons for svc_backup | Benign positive | Service account failing from the **DC itself** (4625 + 4771), no success, no attacker workstation | Closed benign; recommend checking the service credential/config |
| 28 Oct | tshepo added to Backup Operators | Benign positive | Added by DC01$/SYSTEM via Azure Run Command; confirmed authorised; member removed | Closed; note: in real IR, confirm the Run Command caller in the Azure Activity Log before closing a privileged-group change |

## What this practised

- Triaging a mixed queue (identity, endpoint/malware, privileged change) at Tier 1 pace.
- Separating **true positives** from **benign positives** and **false alarms** with evidence, not with the alert title.
- The core habit: a verdict only stands on a specific log line. "Did it succeed?" is answered by a logon success (4624), not a hunch.
- Reversible containment, and escalating rather than taking big destructive actions alone.
