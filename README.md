# Evidence README: Nordia incident, 10-12 March 2026

## Conventions

- C1 = the customer who wrote to support (named in `environment.md`). C2 = the account that logged in successfully from `198.51.100.77` (command in F4). Customer addresses are not repeated here.
- `awk -F,` also splits user agents that contain a comma. Columns 1-6 and the last column are not affected, and those are the only ones used. `detect_rules.py` uses the `csv` module instead.
- Line numbers refer to the files as provided.

## How I narrowed down 20,842 lines (8,627 + 2,142 + 10,073)

1. `environment.md`: list the known noise first (scanner 10.20.9.50, uptime probe 10.20.9.20, Aegis on two workstations, office NAT 192.0.2.50, Debian mirror), so it is not mistaken for an attack.
2. Start from the complaint: C1 in `auth.csv` and `access.log`. One login stands out (new IP, Linux and Chrome, 03:27 UTC = 04:27 Paris).
3. Pivot on that IP across the three logs: failures, accounts reached, pages requested.
4. Count failures per IP over the whole of `auth.csv`: two IPs (740 and 309 failures), then at most 12. That bounds the customer-side attack.
5. Pivot on the accounts the IP reached: admin login, account creation, webhook page, exports.
6. Pivot on `web-01` in `dns.log`: one external domain that is not an obvious service, matched event by event to `access.log`.
7. Cross-check each claim in a second source (for example 740 failures in `auth.csv` = 740 `401` in `access.log`).

## Findings and commands

### F1. C1 was logged in from a new address at 11 Mar 03:27:23 (established)

```
grep -n "karim.haddad@webmail.example" auth.csv access.log
```

Result: `auth.csv:1029` `login_success` from `203.0.113.142` (Linux, Chrome 122), first try. C1's other logins (10 Mar 09:12 and 12:08, 12 Mar 16:20) come from `198.51.100.212` (iPhone, Safari). No `login_failure` for C1.

### F2. Credential testing from 203.0.113.142 (established)

```
grep '203.0.113.142' auth.csv | awk -F, '$3=="login_failure"{print $2}' | sort | uniq -c
grep '203.0.113.142' auth.csv | awk -F, '$3=="login_failure"{print $4}' | sort -u | wc -l
grep '203.0.113.142' auth.csv | awk -F, '$3=="login_failure"{print $NF}' | sort | uniq -c
awk -F, '$6=="203.0.113.142" && $2=="customer" && $3=="login_failure"{print $1}' auth.csv | sort | sed -n '1p;$p'
```

Result: 11 `admin` and 729 `customer` failures; 740 distinct usernames (one attempt per account); 459 `bad_password` and 281 `unknown_user`; customer failures from 02:41:07Z to 04:22:58Z.

### F3. The same IP in access.log (established)

```
grep '^203.0.113.142 ' access.log | awk '{print $9}' | sort | uniq -c
```

Result: 53 x `200`, 6 x `302`, 740 x `401`, 3 x `403`. The 740 `401` match the 740 failures of F2. No `429`: nothing throttled the attempts.

### F4. A second credential-testing IP, 198.51.100.77 (established); same operator (probable)

```
grep '198.51.100.77' auth.csv | awk -F, '{print $2,$3}' | sort | uniq -c
grep '198.51.100.77' auth.csv | awk -F, '{print $1}' | sort | sed -n '1p;$p'
grep '198.51.100.77' auth.csv | grep login_success
comm -12 <(grep '203.0.113.142' auth.csv | awk -F, '$3=="login_failure"{print $4}' | sort -u) \
         <(grep '198.51.100.77' auth.csv | awk -F, '$3=="login_failure"{print $4}' | sort -u) | wc -l
```

Result: 309 failures and 1 success (C2, 02:24:48); first and last line 01:58:03 and 02:40:59, and `203.0.113.142` starts at 02:41:07; no username in common. Rate: 310 attempts in 42 min 56 s and 730 in 101 min 51 s, both about 7.2 a minute. Same browser string on both.

### F5. Baseline: nobody else behaves like this (established)

```
awk -F, '$3=="login_failure"{print $6}' auth.csv | sort | uniq -c | sort -rn | head
awk -F, '$2=="customer"{print $6","$4}' auth.csv | sort -u | cut -d, -f1 | uniq -c | sort -rn | head
```

Result: 740 and 309 failures, then 12 (office address) and 12 (scanner), then 3 or fewer. Distinct customer usernames per IP: 730 and 310, then 6 at most.

### F6. Staff accounts attacked, then one logged into from an attacker address (established)

```
grep '203.0.113.142' auth.csv | awk -F, '$2=="admin"{print $1,$3,$4}'
grep 'l.fontaine' auth.csv
grep -E 'fontaine|svc-backup' accounts.csv
```

Result: 11 staff accounts fail once each between 04:31:31 and 04:37:37; `l.fontaine` succeeds at 04:38:21 with `mfa=none`, with no failure before. `accounts.csv`: role `support`, MFA `no`, last password change 2023-09-14, usual access office `192.0.2.50`. The legitimate sessions of `l.fontaine` come from `192.0.2.50` (Edge).

### F7. MFA is not enforced (established)

```
awk -F, '$2=="admin" && $3=="login_success"{print $NF}' auth.csv | sort | uniq -c
awk -F, '$2=="admin" && $3=="login_success"{print $6}' auth.csv | sort | uniq -c | sort -rn
cat accounts.csv
```

Result: 13 `mfa=none` and 33 `mfa=totp`. Admin logins by source: 33 office, 9 VPN (3 each from 10.20.8.20, .21, .32), 3 from `203.0.113.142`, 1 from `192.0.2.213`. Accounts without MFA: `l.fontaine`, `y.benamar`, `t.nguyen`, with the three oldest password changes (2023-09, 2024-02, 2024-06).

### F8. Unauthorised admin account created and used (established)

```
grep account_created auth.csv
grep -n '192.0.2.213' auth.csv access.log dns.log
```

Result: `2026-03-11T05:12:52Z` `svc-backup01`, actor `l.fontaine`, `role=admin;created_via=admin_ui`, from `203.0.113.142`. First login of `svc-backup01` on 12 Mar 14:07:33 from `192.0.2.213` (Firefox 123, Windows), `mfa=none` (`auth.csv:1995`, `access.log:7653`).

### F9. Webhook set up and contacted (established); destination (probable)

```
grep -n -i webhook access.log
grep 'hooks.nordia-notify' dns.log | sed -n '1,3p;$p'
awk '$1!~/^#/ && /nordia-notify/{print $2}' dns.log | sort | uniq -c
awk '$2=="10.20.1.10"{print $3}' dns.log | sort | uniq -c | sort -rn
python3 webhook_corr.py
```

Result: `access.log` lines 3983 (GET page, 05:06:44), 3986 (POST save, 05:07:21), 3987 (POST test, 05:08:03), 7655 (GET page by `svc-backup01`, 12 Mar 14:08:20). 53 DNS queries, all from `10.20.1.10` (`web-01`), all answered `203.0.113.250`. First query 05:08:06 (3 s after the test), then 05:12:53 (1 s after the account creation), 05:14:21 (3 s after the first export), last 12 Mar 14:15:15 (3 s after the last invoice export). `web-01` domains: `db-01` 432, `api.paygate` 366, `smtp.mailrelay` 330, `ocsp.certauth` 72, `hooks.nordia-notify` 53, `pkg.mirror-debian` 3: the only one that is not an obvious service (to confirm with IT). The script finds 51 triggering events (test, user creation, exports) and 53 queries: every event has a query within 10 s, and 2 queries have no logged event (11 Mar 13:00:56 and 13:25:22).

### F10. Exports (established); pages 14-15 and the total (probable)

```
grep -E "customers/export|invoices/export" access.log
grep '^203.0.113.142 ' access.log | grep 'customers/export' | awk '{s+=$10} END{print s, NR}'
```

Result: customer pages 1-13 and 16-39 (14 and 15 absent), all `size=500` except one `size=50` at 05:14:18; 12,100,227 bytes in 38 requests. Page 39 is 182,621 bytes against about 330,000 for a full page: a short last page, which suggests the end of the table was reached (estimate from `bytes_sent`, not proof). About 660 bytes a row gives about 277 rows on page 39 and about 18,300 rows logged (36 full pages of 500, plus the last), about 19,300 with pages 14-15 (estimate). Invoice exports by `svc-backup01`: `access.log` lines 7668, 7672, 7688 (1,298,431 + 1,244,102 + 1,187,760 = 3,730,293 bytes).

### F11. A hole in access.log (established); cause not confirmed

```
grep -E '11/Mar/2026:1[23]:' access.log | awk '{print $4}' | cut -c14-18 | sort | uniq -c
grep '^10.20.9.20 ' access.log | grep '11/Mar/2026:1[23]:' | awk '{print $4}' | cut -c14-18
awk -F, '$1>="2026-03-11T12:57:00Z" && $1<="2026-03-11T13:28:59Z"' auth.csv | wc -l
awk '$1>="2026-03-11T12:57:00Z" && $1<="2026-03-11T13:28:59Z" && $2=="10.20.1.10"' dns.log | wc -l
```

Result: no `access.log` line between 12:56 and 13:29; the uptime probe (every 5 minutes) is missing from 13:00 to 13:25; in the same window `auth.csv` has 10 events and `dns.log` 13 queries from `web-01`. The gap is in `access.log` only (`auth.csv` and `dns.log` continue), consistent with the log-shipping interruption IT reported for 11 March; the exact window and the cause are not confirmed.

### F12. Probing from 198.51.100.77 (established)

```
grep '^198.51.100.77 ' access.log | awk '{print $9}' | sort | uniq -c
grep '^198.51.100.77 ' access.log | awk -F'"' '{print $6}' | sort | uniq -c
grep '^198.51.100.77 ' access.log | grep ' 401 ' | awk '{print $6,$7}' | sort | uniq -c | sort -rn | head -5
grep '^198.51.100.77 ' access.log | grep 'python-requests' | awk '{print $9}' | sort | uniq -c
grep '^198.51.100.77 ' access.log | grep 'python-requests' | wc -l
grep '^198.51.100.77 ' access.log | grep -v python-requests | awk '{print $9}' | sort | uniq -c
grep '^198.51.100.77 ' access.log | awk '{print $4}' | sed -n '1p;$p'
grep '^198.51.100.77 ' access.log | grep '/download' | awk '{print $4,$7,$9}'
```

Result: 14 x `200`, 8 x `302`, 312 x `401` (309 `POST /login` and 3 `GET /api/v1/...`), 1 x `403`, 116 x `404` (`/.env`, `/backup/*`, `/.git/config`, ...). User agents: 315 Chrome 122 on Linux, 136 `python-requests/2.31.0`. The 136 `python-requests` requests break down as 116 x `404` + 9 x `200` (public pages) + 7 x `302` (redirects to login) + 3 x `401` (`GET /api/v1/users`, `/customers`, `/`) + 1 x `403` = 136 (the second `grep` above prints 136). The other 315 lines (Chrome) are 5 x `200` + 1 x `302` + 309 x `401` (the `POST /login` attempts), printed by the `grep -v python-requests` command; the two groups add up to the totals above (9 + 5 = 14 `200`, 7 + 1 = 8 `302`, 3 + 309 = 312 `401`). No sensitive file is served to the probe. First line 10 Mar 22:41:12, last 11 Mar 02:40:59. Two invoice downloads served in C2's session (02:25:34 and 02:25:52).

### F13. What the attacker did besides exporting (established, for logged lines)

```
grep '^203.0.113.142 ' access.log | grep -v 'customers/export' | grep -v ' 401 ' | awk '{print $4,$3,$6,$7,$9}'
```

Result: C1's pages; admin pages (`/admin/customers`, `/admin/customers/8812`, `/admin/settings`, `/admin/users`); the webhook page, save and test; `/admin/users/new` and one `POST /admin/users` at 05:12:52. The logins at 12:16:56 and 20:11:28 are followed only by exports. No other write.

### F14. Leads ruled out

```
grep -n -E "INV-2026-(028442|042374|024683)" access.log
awk '$1!~/^#/ && $3 ~ /aegis-telemetry/{print $2}' dns.log | sort | uniq -c
grep '10.20.9.50' auth.csv | awk -F, '{print $1}' | sed -n '1p;$p'
grep 'mirror-debian' dns.log | awk '{print $1,$2,$3}'
grep -E "customers/export|invoices/export" access.log | grep '192.0.2.50'
```

Result: three `403` in C1's session, and the same invoice 028442 served `200` to a different customer account from another IP at 11 Mar 12:40 (`access.log:5131`); Aegis queried only by `10.20.5.17` (287) and `10.20.5.18` (288); scanner failures 10 Mar 14:10:24 to 14:10:44, inside its 14:00-14:30 window; mirror queried daily around 03:10 by `10.20.1.10` and `10.20.1.20`; office exports are `size=50` or monthly invoices only.

### F15. Other figures quoted in the report (established)

```
python3 -c "from datetime import datetime as d; print(d(2026,3,12,14,15,15)-d(2026,3,10,22,41,12)); print(d(2026,3,12,16,40)-d(2026,3,11,3,27,23))"
grep -E '^(203.0.113.142|198.51.100.77) ' access.log | grep '/download' | awk '{print $1,$4,$7,$9}'
grep '^203.0.113.142 ' access.log | grep 'size=500' | wc -l
grep '^203.0.113.142 ' access.log | grep 'size=500' | awk '{print $4}' | sed -n '1p;$p'
grep ' l.fontaine ' access.log | awk '{print $1}' | sort | uniq -c
awk -F, '$1>="2026-03-12" && $4=="l.fontaine"{print $1,$3,$6,$NF}' auth.csv
grep -i -E 'password|reset' access.log | awk '{print $1,$4,$6,$7,$9}'
grep -c password_reset_requested auth.csv
```

Result: first request to last DNS query is 1 day 15:34:03 (about 40 hours); first login at C1 to the complaint is 1 day 13:12:37 (about 37 hours). Invoice downloads: 5 from `203.0.113.142` (2 x `200`, 3 x `403`) and 2 from `198.51.100.77` (`200`), in the C1 and C2 sessions. 37 customer export pages with `size=500`, from 11 Mar 05:25 to 12 Mar 03:10 (about 22 hours). `l.fontaine` has 108 requests from `192.0.2.50` (office) and 50 from `203.0.113.142` (attacker). On 12 Mar, `l.fontaine` fails twice and then logs in at 07:42 from the office address. The 15 `password_reset_requested` events match 15 `POST /password/forgot` (all `302`); none comes from `203.0.113.142` or `192.0.2.213`, and the only request from `198.51.100.77` is one `GET /password/forgot` (probing, 10 Mar 22:43:54). No password-change page appears. Staff browsers: 15 logins with Firefox 122, 3 with Chrome on Linux (`203.0.113.142`), 1 with Firefox 123 (`svc-backup01`), and 27 Windows Chromium-type strings that `awk -F,` cuts at a comma (their exact browser is not shown by this output).

## Detection rules (tested on these logs)

```
python3 detect_rules.py
```

| Rule | Query and threshold | Result on these logs |
| --- | --- | --- |
| R1 credential testing | 20 or more distinct usernames failing from one source IP within 60 minutes (benign maximum seen: 12 failures per IP in three days) | Fires for `198.51.100.77` and `203.0.113.142`, about 3 minutes after the first attempt of each, about 38 hours before the customer complaint |
| R2 admin login from an unknown network | Admin `login_success` from outside `192.0.2.50` and `10.20.8.0/24` | 4 of 46 admin logins (`203.0.113.142` x 3, `192.0.2.213` x 1), none of the 42 normal ones |
| R2b account created by a non-admin | Admin-portal `account_created` whose actor is not `admin` in `accounts.csv` | `svc-backup01` created by `l.fontaine` |
| R3 bulk export | `customers/export` answered 200 with `size` above 100 (normal use: 50) | 37 requests, all from `203.0.113.142` as `l.fontaine`; none from legitimate staff |

Measured output of `python3 detect_rules.py` on the logs as provided:

```
RULE1 198.51.100.77: 20 distinct usernames failed within 60 min; alert at 2026-03-11 02:00:42Z (first failure 01:58:03Z, 309 failures in total)
RULE1 203.0.113.142: 20 distinct usernames failed within 60 min; alert at 2026-03-11 02:43:44Z (first failure 02:41:07Z, 740 failures in total)
RULE2 2026-03-11 04:38:21Z admin login of l.fontaine from 203.0.113.142 (mfa=none)
RULE2 2026-03-11 12:16:56Z admin login of l.fontaine from 203.0.113.142 (mfa=none)
RULE2 2026-03-11 20:11:28Z admin login of l.fontaine from 203.0.113.142 (mfa=none)
RULE2 2026-03-12 14:07:33Z admin login of svc-backup01 from 192.0.2.213 (mfa=none)
RULE2 summary: 4 of 46 admin logins came from an unknown network
RULE2B 2026-03-11 05:12:52Z account svc-backup01 created by l.fontaine (role support) from 203.0.113.142 (role=admin;created_via=admin_ui)
RULE3 203.0.113.142 as l.fontaine: 37 customer-export requests with size>100, first at 2026-03-11 05:25:44Z
```

R1 alerts 2 min 39 s and 2 min 37 s after the first failure of each IP (02:00:42 and 02:43:44), about 38 hours before the complaint of 12 Mar 16:40 (measured from the first alert, 11 Mar 02:00:42; the 37 hours in the report are measured from the first login to C1, 11 Mar 03:27:23, see F15). No other IP, account or export triggers any rule. The false-positive rate on a longer period is unknown (three days of logs only).

## MITRE ATT&CK mapping

| Behaviour | Technique |
| --- | --- |
| Probing hidden paths from `198.51.100.77` | T1595.003 Active Scanning: Wordlist Scanning |
| Customer logins from a list | T1110.004 Credential Stuffing |
| 11 staff accounts tried once each | T1110 Brute Force (variant unknown) |
| Login as `l.fontaine` | T1078 Valid Accounts |
| `svc-backup01` created | T1136 Create Account |
| Customer table read page by page | T1213 Data from Information Repositories; T1119 Automated Collection |
| Webhook to an outside domain | T1567 Exfiltration Over Web Service (probable) |

## Facts for the data protection officer (no legal conclusions)

- People concerned: about 19,000 customers in the export (probable: the whole table); 2 customer accounts logged into from attacker addresses (probable: not by the holders); 1,040 customer login attempts (some usernames did not exist: 281 `unknown_user` among the 740 failures of the first IP).
- Data categories: unknown until the export header is obtained; invoices for December 2025 to February 2026 were exported.
- Period: first hostile request 10 Mar 22:41:12; last attacker activity logged 12 Mar 14:15:15; at that point the webhook and `svc-backup01` were still in place.
- Recipients (probable; the logs show what the server served, not what was received): the attacker IPs that were served the data; possibly `hooks.nordia-notify.example` through the webhook.
- Detection: customer complaint on 12 Mar 16:40; C1 reports a security e-mail after the 11 Mar 03:27 login; per the application team it is sent for any IP new to the account (these e-mails are not in the logs).
- Measures: none visible in the logs; planned measures are in section 6 of the report.
- Open points: section 7 of the report.

## Limits

Logs cover 10-12 March only and may be incomplete (one hole found). Row counts are estimates from `bytes_sent`. Rule R2b covered every `account_created` event (one hit). The 15 customer password-reset requests were checked only for attacker addresses (none), not for legitimacy.

Answers from IT before I started (questions asked: log reliability, export fields, security e-mail):

- The three systems take their time from the same internal time source and IT knows of no clock problem, so the order of events is reliable. Log shipping may have been interrupted for a while on 11 March, with no detail, so the absence of an event is not proof that it did not happen.
- The exact columns of the exports cannot be confirmed. I assume the customer export lists identity and contact details, and the report says how the impact changes if it also holds password hashes.
- The security e-mail is sent for any IP never used before on that account, with date, time, approximate location and browser, and it is not logged. A "new address" alert alone is a weak signal; the report relies on the attack pattern.
