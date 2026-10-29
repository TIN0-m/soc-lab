# Investigation 09: User-reported phishing email

| | |
|---|---|
| **Source** | A user clicked "Report phishing" on the message below |
| **MITRE ATT&CK** | T1566 Phishing (Initial Access) |
| **Verdict** | True positive: credential-phishing, impersonating Microsoft 365 |
| **Analyst** | Tinotenda Masendeke |
| **Exercise** | Manual phishing analysis on a sample message. The lab has no mail platform, so this is header and content analysis, not a Sentinel-detected incident. |

## The message

Defanged so nothing is clickable.

```
From: Microsoft 365 Security <security@micros0ft-support.com>
Reply-To: no-reply@account-verify.live
To: pieter.vanwyk@lowveld-logistics.co.za
Date: Wed, 29 Oct 2026 06:14:22 +0000
Subject: [Action Required] Your password expires in 2 hours

Authentication-Results: spf=fail (sender IP is 193.142.30.7)
  smtp.mailfrom=micros0ft-support.com; dkim=none;
  dmarc=fail action=quarantine
Received: from mail.account-verify.live (193.142.30.7)

Dear user,

Our records show your Microsoft 365 password will EXPIRE in 2 hours.
To avoid losing access to your email, files and Teams, verify your
account immediately.

      [ Keep My Current Password ]
      hxxps://m365-verify.secure-login[.]xyz/auth?u=pieter.vanwyk

Failure to verify will result in permanent account suspension.
This is an automated message from Microsoft 365. Do not reply.
```

## Triage

The call is made from the message itself, with a reason for every tell, not a gut feeling.

**The sender domain.** The display name says "Microsoft 365 Security", but the real address is `security@micros0ft-support.com`, a typosquat with a zero in place of the "o". Not a Microsoft domain.

**From vs Reply-To.** They do not match. A reply would go to `account-verify.live`, a different throwaway domain. Legitimate mail does not usually split these.

**The authentication results.** This is the email version of the logon events in the other cases. The proof is in the header:
- `spf=fail`: the sending server (193.142.30.7) is not on the approved list for the domain it claims to send as.
- `dkim=none`: the message is not signed at all. Real Microsoft mail is always signed.
- `dmarc=fail action=quarantine`: SPF and DKIM do not line up with the From domain, and the domain's own policy says quarantine it.

All three failing or absent is the signature of a forged sender.

**The link.** Read the domain right to left, to the top-level domain. In `hxxps://m365-verify.secure-login[.]xyz/auth`, the real domain is `secure-login.xyz`. "m365-verify" and anything Microsoft-looking in front of it are just subdomains added to fool the eye. It is not microsoft.com.

**The pressure.** A two-hour deadline, "permanent account suspension", and a generic "Dear user" greeting. Manufactured urgency and no personalisation.

## Did it work?

For phishing, "did it succeed" means did the user act on it: click the link and enter their password. In a real tenant you confirm this in the sign-in logs and by checking whether the account did anything unusual afterwards. Here the user reported it rather than clicking, so there is no compromise to chase. If they had entered credentials, this moves to an account-takeover response: reset the password, revoke sessions, and check for new mailbox rules.

## Verdict and action

**True positive, credential-phishing.** Severity Medium when it is reported with no click; High if the user entered their password.

- Purge the message from the user's mailbox, and search the rest of the tenant for other copies. One report usually means several people received it.
- Block the sender domain and the URL.
- Confirm whether the user clicked or entered anything. If they did, run the account-takeover steps above.
- Thank the user for reporting it, and use it as a short teaching example.

## Lessons

- **The header carries the proof.** SPF checks the sending server, DKIM checks the signature, DMARC checks they match the visible From and says what to do on failure. This is the email equivalent of "no 4624, no breach".
- **Read the link's domain right to left.** The registrable domain is the last two labels before the first single slash. Everything in front of it is window dressing.
- **"Did it succeed" is about the user, not the email.** A phish only lands if someone clicks and enters credentials, so the first thing to confirm is whether they did.
- **Scope it.** One reported phish is rarely the only copy. Search and purge across mailboxes before closing.
