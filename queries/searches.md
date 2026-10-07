# SPL Queries

Index `cloud`, 2024-02-11 UTC, in investigation order.

## Find the anomalous login

```spl
index="cloud"
| table ClientIPAddress, Operation, UserId, Workload
```
242 events. `table` keeps rows with empty fields.

```spl
index="cloud" Operation=UserLoggedIn
| table ClientIPAddress, Operation, UserId, Workload
```
23 events. `ClientIPAddress` is empty for the AzureActiveDirectory workload.

```spl
index="cloud" Operation=UserLoggedIn
| stats count by ClientIP, ActorIpAddress, Operation, UserId, Workload
```
4 rows, including a system account.

```spl
index="cloud" Operation=UserLoggedIn UserType!=4
| stats count by ClientIP, ActorIpAddress, Operation, UserId, Workload
```
3 rows: two users, three source IPs.

```spl
index="cloud" Operation=UserLoggedIn UserType!=4 UserId!=schan@7pd6vr.onmicrosoft.com
| stats count by _time, ClientIP, ActorIpAddress, Operation, UserId, Workload
```
8 rows. Vancouver 20:33:37, Singapore 20:46:39.

## Scope the attacker IP

```spl
index="cloud" 188.214.125.138
| stats count by _time, Operation, UserId, Workload
| sort +_time
```
96 events, 18 rows, one user.

## Mailbox manipulation

```spl
index="cloud" 188.214.125.138 Operation=New-InboxRule
| stats count by _time, Operation, UserId, Workload
| sort +_time
```

```spl
index="cloud" @imcourageous.com
```
2 events: `New-InboxRule` and `Set-Mailbox`.

## Email access

```spl
index="cloud" 188.214.125.138 Operation=MailItemsAccessed
| stats count by _time, Operation, UserId, Workload
| sort +_time
```

```spl
index="cloud" 188.214.125.138 Operation=MailItemsAccessed
| stats count by Folders{}.FolderItems{}.InternetMessageId
```
4 message IDs. The nested path is required.

```spl
index="cloud" 188.214.125.138 PH7PR19MB8188D8A00DEAFD4DA081406F91492
| stats count by _time, Operation, UserId, Workload
```
Message ID with the angle brackets and `@...` suffix removed.

## Drafts, deletion, send

```spl
index="cloud" 188.214.125.138 Operation=Create
```

```spl
index="cloud" 188.214.125.138 Operation=MoveToDeletedItems "AffectedItems{}.Subject"="Re: First Invoice of the month!"
```

```spl
index="cloud" 188.214.125.138 Operation=Send
```

## Recipients

```spl
index="cloud" "URGENT: Client Bank Account"
```
9 events, two users.

## Hunt ideas

Not run against this dataset beyond the single-day window. Starting points for
a wider search.

```spl
index="cloud" ForwardingSmtpAddress
```
Any mailbox-level forwarding. Review every external value.

```spl
index="cloud" (Operation=New-InboxRule OR Operation=Set-InboxRule) (ForwardTo OR RedirectTo OR ForwardAsAttachmentTo)
```
Inbox rules that forward mail.

```spl
index="cloud" Operation=UserLoggedIn UserType!=4
| stats dc(ClientIP) as distinct_ips values(ClientIP) as ips by UserId
| where distinct_ips > 1
```
Users signing in from more than one address. Enrich the addresses with
location before judging.
