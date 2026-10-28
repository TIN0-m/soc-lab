# Investigation 03: Security log cleared, authorised admin or breach?

| | |
|---|---|
| **Alert** | Sentinel incident "Security audit log cleared on WS01" (High), plus a Defender multi-stage "Execution & Defense evasion" incident on the same activity |
| **MITRE ATT&CK** | T1070.001 Indicator Removal: Clear Windows Event Logs (Defense Evasion) |
| **Verdict** | **Benign true positive**: the detection was correct, but the actor was an authorised admin |
| **Analyst** | Tinotenda Masendeke |
| **Exercise** | The log-clear was staged on purpose. Everything below is from the lab's real endpoint and cloud logs. |

Times are UTC. The activity happened on 27 October 2026.

## Why this one is worth reading

Clearing the Windows Security log is a classic attacker move to cover their tracks, so it fires a High alert. But the same action is also something a legitimate admin or a management tool can do. The job here was not "catch the attacker", it was to decide **authorised or breach?**, and to prove the answer. That decision used three pivots: the endpoint process tree, the command line, and the cloud Activity Log.

## Summary

At 20:57 on 27 October, the Security event log on WS01 was cleared with `wevtutil cl Security`, run by a PowerShell script launched through the **Azure Run Command** extension, as NT AUTHORITY\SYSTEM. Every tool in the chain was a legitimate, Microsoft-signed Windows or Azure binary (a "living off the land" pattern), so no malware was involved. The Azure Activity Log showed the command was invoked by the organisation's **own Azure admin account from an expected IP**, which makes this **authorised administration, not an intrusion**. Had the caller or source IP been unknown, the identical endpoint evidence would instead have meant a cloud account compromise.

## Pivot 1: the endpoint process tree (how)

Reading the tree top to bottom, ignoring the boot-time processes (an 80-minute gap separated them from the event, so they were not part of it):

```
WindowsAzureGuestAgent.exe                         (Azure agent, SYSTEM)
 └─ RunCommandExtension.exe  "enable"              (Azure Run Command)
     └─ cmd.exe /C powershell -File script7.ps1
         └─ powershell.exe -File script7.ps1       (T1070.001 flagged here)
             └─ wevtutil.exe cl Security           20:57:33  ← the log cleared
```

Each box is one sentence: the Azure Run Command extension launched PowerShell, which ran `wevtutil cl Security`.

## Pivot 2: the command line and script content (what)

Defender captured the script's exact content, so there was no guesswork:

```
wevtutil cl Security; 'Security log cleared on WS01 at ' + (Get-Date).ToUniversalTime().ToString('u')
```

`wevtutil cl Security` is the only meaningful action (clear the Security log). The rest just prints a timestamped confirmation.

## Is it malware? The four checks

| Check | Finding |
|---|---|
| Known programs? | Yes: cmd, powershell, wevtutil, the Azure agent |
| Right file paths? | Yes: `C:\Windows\System32` and the signed `Microsoft.CPlat.Core.RunCommandWindows` extension folder |
| Sensible parent chain? | Yes: Azure agent → Run Command → shell → wevtutil |
| Microsoft-signed? | Yes, all of them |

No foreign binaries, nothing from a Temp or Downloads folder, no Office app spawning a shell. **Not malware.** But the *tools* being clean is not the whole answer, because the *action* (wiping the log) is still suspicious. When legitimate tools do a suspicious thing ("living off the land"), the real question becomes: was it authorised?

## Pivot 3: the Azure Activity Log (who authorised it)

The process tree shows SYSTEM running the command, which can never say which person in the cloud triggered it. A Run Command comes from the Azure management plane, so the answer is in the Activity Log (`AzureActivity`):

```kql
AzureActivity
| where OperationNameValue has "runcommand"
| project TimeGenerated, Caller, CallerIpAddress, ActivityStatusValue
```

It returned the **organisation's own Azure admin account, from an expected IP**, with status Succeeded. That is the authorisation, confirmed.

## Verdict

**Benign true positive.** The detection fired correctly on real log-clearing, but the actor was an authorised administrator using Azure Run Command. Closed as benign, with the Activity Log caller recorded as the evidence.

**The flip side, the real-world value:** if that Activity Log caller had been an unknown account, or the IP a foreign one, this exact same endpoint evidence would be a **cloud account compromise**, an attacker with stolen Azure credentials running commands on the servers as SYSTEM. The endpoint logs look identical either way. Only the management-plane log tells them apart. That is why a Microsoft-shop SOC watches the cloud control plane, not just the machines.

## Lessons

- **Scope in time first.** The process tree included boot-time processes that had nothing to do with the event. The timestamp gap showed where the real activity began. Not everything in a tree is "the attack".
- **Three pivots answer three questions.** Process tree = *how*; command line and script content = *what*; Azure Activity Log = *who authorised it*.
- **Legitimate tools can do illegitimate things.** "Living off the land" means "signed and in the right folder" is not a clean bill of health. Judge the action, then the authorisation.
- **Benign true positive is a real, correct outcome.** Deciding that a scary alert is authorised, with proof, is as much the job as catching an intruder. Crying wolf on authorised admin work erodes trust in the SOC.
- **Management-plane logging is non-negotiable in the cloud.** Without the Activity Log, "who did this from Azure" is unanswerable.
