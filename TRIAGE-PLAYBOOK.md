# SOC alert triage playbook

How to work any alert, start to finish. Follow the steps in order. The golden rules at
the bottom are the habits; when in doubt, go back to them.

---

## The 7 steps

### 0. Freeze. Before you touch anything.
- Do **not** change the machine or accounts yet.
- Do **not** assume it's an attack, and do **not** assume it's benign. You decide with evidence, not with a first impression.

### 1. Pick it up.
- Assign the incident to **yourself**. Set status to **Active**.
- Now the team knows it's being worked.

### 2. Understand what actually fired.
- Read the alert: **what** rule/detection fired, **which** user / host / account, and **when**.
- **Click into the real events. Do not trust the title.** The title is a label, not the verdict.
- Note the **real event time** (StartTime/EndTime of the activity), not the alert time. *The alert time is when the rule ran, not when the thing happened.*

### 3. Scope it.
- When did the activity **start and end**? (first and last event)
- Is the whole thing one event, or several? Don't assume everything you see is "the attack", a process tree can be 90% normal boot activity with one bad node.

### 4. Classify it. (the core)
Answer two questions, each backed by a **specific event**:

**a) Did it really happen?** (is the detection correct?) Check the events exist.

**b) Is it malicious, benign, or authorised?** Use the right lens:

| The question | How to answer it |
|---|---|
| Is a process/file bad? | **4 checks:** known program? right path (System32 / Program Files, not Temp/Downloads)? sensible parent (Office launching a shell = bad)? Microsoft-signed? |
| Did they get in? | Is there a **logon success (4624)**? No 4624 = it failed, no breach. Don't say "they got in" without it. |
| Who did it / was it authorised? | If it ran as **SYSTEM / via Azure Run Command**, pivot to the **Azure Activity Log** for the caller. SYSTEM is not proof of authorised. |
| What is this IP? | **Process + direction + reputation.** (Defender → Microsoft on 443 = normal.) An IP near the time proves nothing on its own. |
| Is it even an attack? | A **service account** failing from a **server** is usually a stale/cached credential, not a brute force. Context first. |

**Rule: every sentence in your verdict must point to a specific log line. No event, no claim.**

### 5. Rate it.
- Set severity by matching **your facts to the onboarding pack's exact wording** (e.g. "spray with no success" = Medium, "account takeover" = High). Read the words, don't guess the number.

### 6. Act.
- **Benign / false positive:** note *why* (the evidence), then close.
- **Real, and within your remit:** contain **reversibly** — **disable, never delete**; **never touch built-in identities** (SYSTEM, Authenticated Users, INTERACTIVE). Then document.
- **Real, and big / destructive / beyond you:** **escalate.** You don't take major actions solo on a hunch. A cleared log or a domain-admin change is a "phone the manager" moment.

### 7. Document and close.
- Short note on the incident: **what happened, the evidence (event IDs + times), your verdict, what you did.**
- Set the **classification** (True Positive / Benign Positive / False Positive) and close.

---

## The golden rules (the habits)

1. **Don't assume, in either direction.** Not "it's an attack", not "it's fine". Prove it.
2. **Every claim points to an event.** If you can't cite the log line, you can't say it.
3. **Alert time ≠ event time.** Click in and find when it really happened.
4. **Unknown ≠ malicious.** If you don't recognise it, look it up, don't delete it.
5. **Disable, don't delete. Never touch what you don't understand.**
6. **SYSTEM is a question, not an answer.** For "who / authorised", pivot to the Activity Log.
7. **Escalate big actions.** When in doubt, don't make it worse.

---

## The three pivots (for a full picture)

| Pivot | Answers | Where |
|---|---|---|
| **Process tree** | *How* it happened (the chain) | Defender device timeline / `DeviceProcessEvents` |
| **Command line + script content** | *What* was run | the process's command line, event 4688 |
| **Azure Activity Log** | *Who* authorised it (for cloud/management actions) | `AzureActivity` (Caller, CallerIpAddress) |

Build the story: each box in the tree is a sentence (parent launched child, command line = what, time = when), and the proof is the event behind each sentence.
