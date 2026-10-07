# Impossible Travel to Business Email Compromise — Splunk Investigation

An impossible-travel alert on a Microsoft 365 account, followed through to what
the attacker actually did with the access: mailbox forwarding, an evidence-hiding
inbox rule, and a fraudulent "new bank account" email sent to a colleague
**12 minutes after the first login**.

> **Environment.** Microsoft 365 unified audit logs (Azure AD + Exchange Online)
> analysed in Splunk. Index `cloud` · 2024-02-11 UTC · 242 events. Simulated
> training dataset; the organisation in it is based in Vancouver, BC.

---

## Summary

| | |
|---|---|
| **Compromised account** | `jchan@7pd6vr.onmicrosoft.com` |
| **Attacker source** | `188.214.125[.]138` — Singapore, AS9009 M247 Europe SRL |
| **Expected source** | `181.214.153.165` — Vancouver, BC |
| **Impossible travel** | Vancouver login 20:33:37 → Singapore login 20:46:39 UTC (13 min apart) |
| **Persistence / collection** | Mailbox forwarding + inbox rule to `stoicellis@imcourageous[.]com` |
| **Fraud attempt** | `URGENT: Client Bank Account` with `NEW-BANK-ACCOUNT.pdf`, sent to `schan` at 20:58:54 UTC |
| **Other accounts on that IP** | None |

Full write-up: [`docs/investigation.md`](docs/investigation.md) ·
Recap: [`docs/recap-of-findings.md`](docs/recap-of-findings.md) ·
IOCs: [`iocs/iocs.md`](iocs/iocs.md) ·
Queries: [`queries/searches.md`](queries/searches.md)

---

## The attack in one view

```
20:33:37  jchan logs in from Vancouver (181.214.153.165)            expected
20:46:39  jchan logs in from Singapore (188.214.125.138)            IMPOSSIBLE TRAVEL
20:46:50  MailItemsAccessed (Bind) - attacker reads individual emails
20:48:54  Set-Mailbox - all mail forwarded to stoicellis@imcourageous[.]com
   (*)    New-InboxRule "1" - mail from schan: forward, mark read, move to Deleted Items
20:49:09  Create - draft items appear in the mailbox
20:56:25  MoveToDeletedItems - "Re: First Invoice of the month!" removed from Drafts
20:56:59  Create - draft "URGENT: Client Bank Account"
20:58:54  Send - that email goes out with NEW-BANK-ACCOUNT.pdf
21:01:36  schan (Vancouver) starts a reply
```

`(*)` Splunk places both mailbox-configuration events at 20:41:46. See
[A timestamp worth checking](#a-timestamp-worth-checking).

---

## Walkthrough

### 1. Start wide, with `table` rather than `stats`

`table` shows every row even when a field is empty; `stats` silently drops them.
That matters in the next step.

```spl
index="cloud" | table ClientIPAddress, Operation, UserId, Workload
```

![242 events in a table](screenshots/01-base-search-242-events.png)

### 2. The IP field that isn't there

Filtering to logins (`Operation=UserLoggedIn`) leaves 23 events and an empty
`ClientIPAddress` column. Exchange events use `ClientIPAddress`; Azure AD sign-ins
use `ClientIP` and `ActorIpAddress`. Same data source, different field names per
workload.

![Blank ClientIPAddress on Azure AD logins](screenshots/02-userloggedin-blank-clientip.png)

### 3. Remove the noise, then look at who logged in from where

`UserType=4` is a system account. Dropping it leaves three source IPs across two
users.

```spl
index="cloud" Operation=UserLoggedIn UserType!=4
| stats count by ClientIP, ActorIpAddress, Operation, UserId, Workload
```

![Three source IPs](screenshots/05-logins-by-ip-three-sources.png)

### 4. OSINT on the three addresses

Two resolve to Vancouver, where the company is. One resolves to Singapore, on
M247 — a hosting and VPN network, not a residential or corporate ISP.

![ipinfo.io lookups](screenshots/06-ipinfo-osint-singapore-vancouver.png)

### 5. The 13 minutes

Adding `_time` puts the two logins next to each other: Vancouver at 20:33:37,
Singapore at 20:46:39. A direct flight is about 16 hours.

![Vancouver then Singapore, 13 minutes apart](screenshots/08-impossible-travel-13-minutes.png)

### 6. The step that turns an alert into an investigation

Stopping at "impossible travel confirmed" answers nothing the business cares
about. Searching on the IP alone shows everything it did.

```spl
index="cloud" 188.214.125.138
| stats count by _time, Operation, UserId, Workload
| sort +_time
```

![Everything the attacker IP did](screenshots/09-attacker-ip-full-timeline.png)

Seven operation types, one user. No other account ever authenticated from this
address.

### 7. Forwarding and a rule built to hide replies

`New-InboxRule` named `1`: anything **from `schan`** is forwarded to an external
address, marked as read, and moved to Deleted Items. The real owner of the mailbox
never sees the reply.

![Inbox rule parameters](screenshots/11-inbox-rule-parameters.png)

Searching the attacker's domain instead of the full address (the username can
change between victims) surfaces a second control: `Set-Mailbox` with
`ForwardingSmtpAddress`, which forwards the whole mailbox.

![Set-Mailbox forwarding](screenshots/12-set-mailbox-forwarding-smtp.png)

### 8. Which emails were read

`MailAccessType: Bind` means individual messages were opened (as opposed to
`Sync`, a bulk download). Each one is recorded by `InternetMessageId` — a nested
field, so the full path is required:

```spl
| stats count by Folders{}.FolderItems{}.InternetMessageId
```

![Four message IDs accessed](screenshots/15-internetmessageid-nested-field.png)

Pivoting on one of those IDs ties it to a subject line and shows its whole life
in the mailbox: created, read, deleted.

![One message ID across three operations](screenshots/16-message-id-correlation.png)

### 9. The payload

One `Send` event from the Singapore IP: `URGENT: Client Bank Account`, attachment
`NEW-BANK-ACCOUNT.pdf`.

![Send event with attachment](screenshots/20-send-attachment-new-bank-account-pdf.png)

### 10. Who received it

Searching the subject across the index shows two users only. `schan` created a
`Re: URGENT: Client Bank Account` draft from the Vancouver office IP less than
three minutes later.

![Subject search showing recipient](screenshots/22-recipients-by-userid.png)

---

## A timestamp worth checking

Splunk shows the `Set-Mailbox` and `New-InboxRule` events at **20:41:46** — five
minutes *before* the first Singapore login. The `Set-Mailbox` event's own
`CreationTime` field reads **20:48:54**, which is after the login and fits the
rest of the sequence. These two events carry an `AppAccessContext` block with its
own issued-at timestamp ahead of `CreationTime`, and Splunk appears to have taken
`_time` from that. For these operations, `CreationTime` is the one to trust. I
confirmed it on `Set-Mailbox`; the `New-InboxRule` event's `CreationTime` still
needs the same check. Details in [`docs/investigation.md`](docs/investigation.md#timestamp-discrepancy).

---

## ATT&CK mapping

| Technique | ID | Evidence |
|---|---|---|
| Valid Accounts: Cloud Accounts | T1078.004 | `UserLoggedIn` from Singapore |
| Email Collection: Remote Email Collection | T1114.002 | `MailItemsAccessed` (Bind) |
| Email Collection: Email Forwarding Rule | T1114.003 | `Set-Mailbox` / `New-InboxRule` `ForwardTo` |
| Hide Artifacts: Email Hiding Rules | T1564.008 | Rule moves replies to Deleted Items, marks read |
| Indicator Removal: Clear Mailbox Data | T1070.008 | `MoveToDeletedItems` |
| Internal Spearphishing | T1534 | `Send` to a colleague from the compromised mailbox |

---

## Skills demonstrated

- Taking an identity alert past triage to scope and impact
- Working across M365 workloads with inconsistent field names
- OSINT enrichment and reading what an ASN says about an IP
- Nested JSON fields in Splunk (`Folders{}.FolderItems{}.InternetMessageId`)
- Message-ID correlation to establish exactly which emails were exposed
- Questioning a timeline that doesn't add up instead of reporting it as-is
- Scoped response actions for a business email compromise

## Tools used

| Tool | Purpose |
|---|---|
| Splunk Enterprise | Search, field analysis, `table` / `stats` / `sort` transformations |
| Microsoft 365 unified audit log | Azure AD sign-in and Exchange Online mailbox events |
| ipinfo.io | IP geolocation and ASN lookup |
| MITRE ATT&CK | Technique mapping |

## Key takeaways

- An impossible-travel alert describes how the attacker got in. What they did
  afterwards is found by searching on the IP.
- The source IP sits in different fields depending on the M365 workload.
- `Bind` access lets you name the exact emails exposed. `Sync` does not.
- An inbox rule that forwards, marks as read and deletes is built to hide a
  conversation from the mailbox owner.
- Check which timestamp the SIEM is displaying before building a timeline on it.

## Repository structure

```
README.md
docs/
  investigation.md        full walkthrough, findings, response actions
  recap-of-findings.md    bullet-point recap
iocs/
  iocs.md                 defanged indicators
queries/
  searches.md             every SPL query, in order
screenshots/              22 evidence captures
```

---

## Author

**Ojas Yajnik** · [github.com/ojasy](https://github.com/ojasy)

*All accounts, addresses and domains shown belong to a simulated training
dataset. The address bar of the Splunk instance is blurred in the screenshots.*
