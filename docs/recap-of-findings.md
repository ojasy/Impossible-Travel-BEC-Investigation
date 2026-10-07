# Recap of Findings

- **`jchan@7pd6vr.onmicrosoft.com` was compromised.** The account logged in from
  Vancouver (`181.214.153.165`) at 20:33:37 UTC and from Singapore
  (`188.214.125[.]138`) at 20:46:39 UTC on 2024-02-11 — 13 minutes apart.
- **The Singapore address belongs to AS9009 M247 Europe SRL**, a hosting network.
  The company is in Vancouver, and the user has no other Singapore login in the
  available data.
- **Both use cases fire.** Impossible travel on the 13-minute gap; unfamiliar
  sign-in on the new location. One day of data is not enough to baseline the
  user properly — 30 to 90 days is.
- **Only `jchan` authenticated from that address.** `schan` logged in from
  Vancouver only.
- **The attacker used Outlook on the web** (`Client=OWA`), with a Chrome 121 /
  Windows 10 user agent on one event.
- **Whole-mailbox forwarding was enabled**: `Set-Mailbox`,
  `ForwardingSmtpAddress = smtp:stoicellis@imcourageous[.]com`.
- **An inbox rule named `1` was created** to forward mail from `schan` to the
  same external address, mark it read, and move it to Deleted Items.
- **Four individual emails were opened** (`MailItemsAccessed`, `Bind`), each
  identifiable by `InternetMessageId`.
- **Two threads were handled:** `Re: First Invoice of the month!` and
  `URGENT: Client Bank Account`.
- **A draft on the invoice thread was moved from Drafts to Deleted Items** at
  20:56:25 UTC.
- **`URGENT: Client Bank Account` was sent at 20:58:54 UTC** with
  `NEW-BANK-ACCOUNT.pdf` attached — 12 minutes after the first Singapore login.
- **`schan` was the only recipient** and created a reply draft at 21:01:36 UTC
  from the Vancouver office. Whether it was sent is not confirmed.
- **Last activity from the attacker address:** a login at 21:25:24 UTC.

## Interesting

- **Field names change by workload.** Exchange uses `ClientIPAddress`; Azure AD
  sign-ins use `ClientIP` and `ActorIpAddress`. A search built on one silently
  misses the other.
- **`table` before `stats`.** `stats count by` discards events missing a `by`
  field. `table` showed the empty IP column that pointed to the field-name
  problem.
- **`UserType=4` is a system account** and can be filtered out of sign-in
  analysis.
- **Nested fields need the full path**:
  `Folders{}.FolderItems{}.InternetMessageId`, not `InternetMessageId`.
- **`Bind` versus `Sync`.** `Bind` records each message opened, so exposure can
  be reported per email. `Sync` cannot be narrowed that way.
- **Search the attacker's domain, not the full address.** The local part can
  change between victims.
- **`_time` is wrong on two events.** Splunk shows `Set-Mailbox` and
  `New-InboxRule` at 20:41:46, before the attacker's first login. `Set-Mailbox`
  has `CreationTime` 20:48:54. Splunk most likely parsed
  `AppAccessContext.IssuedAtTime` as the event time. Timelines from this data
  should be built on `CreationTime`.
- **The impossible-travel alert was the least important finding.** The business
  impact — forwarding, a hidden reply channel, and a payment-fraud email
  already delivered — only appears after scoping the IP.
