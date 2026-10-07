# Indicators

Defanged. All values are from lab data.

## Network

| Indicator | Type | Context |
|---|---|---|
| `188.214.125[.]138` | IPv4 | Attacker source. Singapore, AS9009 M247 Europe SRL, range `188.214.125.0/24` |

M247 is shared hosting infrastructure. Block the address, hunt on the range and
ASN, and expect the attacker to move.

## Email

| Indicator | Type | Context |
|---|---|---|
| `stoicellis@imcourageous[.]com` | Address | Forwarding target (`ForwardTo`, `ForwardingSmtpAddress`) |
| `imcourageous[.]com` | Domain | Attacker-controlled mail domain |
| `URGENT: Client Bank Account` | Subject | Fraudulent email sent from the compromised mailbox |
| `NEW-BANK-ACCOUNT.pdf` (43,059 bytes) | Attachment | Sent with the above. Not retrieved; no hash available |
| `PH7PR19MB818854FAFD1785788A21353691492@PH7PR19MB8188.namprd19.prod.outlook.com` | InternetMessageId | The sent message |

## Messages accessed by the attacker (`MailItemsAccessed`, Bind)

```
PH0PR19MB5243D32E25D8422418499DAB88492@PH0PR19MB5243.namprd19.prod.outlook.com
PH7PR19MB81881C6396A3362E98D988B491492@PH7PR19MB8188.namprd19.prod.outlook.com
PH7PR19MB8188D8A00DEAFD4DA081406F91492@PH7PR19MB8188.namprd19.prod.outlook.com   Re: First Invoice of the month!
PH7PR19MB8188E4572979AF35D286610291492@PH7PR19MB8188.namprd19.prod.outlook.com
```

## Behavioural

| Indicator | Detail |
|---|---|
| Inbox rule name | `1` |
| Rule actions | `ForwardTo` external + `MarkAsRead: True` + `MoveToFolder: Deleted Items` + `StopProcessingRules: True` |
| Mailbox setting | `ForwardingSmtpAddress` set to an external address |
| Client | `Client=OWA;Action=ViaProxy` |
| User agent | Chrome 121 on Windows 10 x64, via OWA |
| Session ID (Send) | `6b0f5b6e-66e8-46ca-bc41-e6709104fb14` |

## Accounts

| Account | Role |
|---|---|
| `jchan@7pd6vr.onmicrosoft.com` | Compromised |
| `schan@7pd6vr.onmicrosoft.com` | Targeted: inbox-rule subject and recipient of the fraudulent email |

## Expected (not malicious)

| Indicator | Context |
|---|---|
| `181.214.153.165` | `jchan`, Vancouver, BC |
| `181.214.153.176` | `schan`, Vancouver, BC |
