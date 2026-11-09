## Checkpoint 0 — Labelled sample capture

A rule-based detector is only as trustworthy as the input it was validated against,
so the first step was to produce a labelled sample: a slice of `/var/log/auth.log`
whose contents were known in advance.

Four controlled SSH attempt series were replayed on the lab server:
wrong-password bursts, an invalid-username spray, a success-after-failure sequence,
and normal connections. The captured window was sliced into `samples/`.

Two findings emerged from validating the capture against the ground truth:

- Root is a real account, so an attempt on root logs as `Failed password for root`,
  not `Failed password for invalid user root`. Invalid-user detection only applies
  to usernames that do not exist.
- One failed attempt writes multiple log lines (pam failure, `Failed password`,
  connection close) sharing one sshd process id. The parser must count one
  authentication event per connection, or burst thresholds would be triple-counted.



## Checkpoint 1 — Auth-log parser

The parser (`authmon/auth_parser.py`) turns raw auth.log lines into a single
structured record per SSH connection. Because one attempt writes several lines
sharing one sshd process id (PAM failure, decisive outcome, connection close),
the parser keys on the definitive outcome line and records `Accepted password`,
`Failed password`, and `Failed password for invalid user`. This yields exactly
one event per connection, so burst thresholds are never inflated by duplicate
lines.

Design detail: invalid-user lines are matched before plain failures, because
the phrase "Failed password for invalid user" begins with "Failed password".

Validated against the labelled sample: 23 events (13 failed, 6 invalid-user,
4 accepted), 85 lines rejected as noise (PAM diagnostics, connection closes,
sudo/systemd session lines). This exactly matches the ground truth.


## Checkpoint 2 — Edge-case tests

Six edge-case tests (`tests/test_auth_parser_edges.py`) lock the parser down
against messy real-world input: IPv6 source addresses, invalid-user lines with
IPv6, unknown message types (DNS/getaddrinfo noise), connection-close lines,
an empty file, and duplicate decisive lines sharing one sshd pid. The last
test enforces the "one connection = one event" dedupe invariant, so burst
thresholds are never inflated by repeated lines. All six pass.

## Checkpoint 3 — Summaries

`authmon/summarize.py` produces a one-glance picture of parsed events: totals,
outcome counts (accepted/failed/invalid-user), first/last seen timestamps,
top source IPs and top usernames. Against the labelled sample it reports
23 events (13 failed, 6 invalid-user, 4 accepted) from 127.0.0.1, dominated by
the labuser account — matching the ground truth.

## Checkpoint 4 — Detection rules

`authmon/rules.py` implements three hostile-SSH detectors operating per source
IP: a failed-login burst (>=5 failures within 60 seconds), an invalid-username
spray (>=3 distinct non-existent accounts), and success-after-failure (an
accepted login preceded by failures from the same source). Against the labelled
sample, 127.0.0.1 triggers all three: a 13-failure burst (the whole series-1 +
root + series-3 sequence spans ~54 seconds, inside the 60s window), a 6-account
spray, and labuser succeeding at 14:39:44 after a failed streak.

The single 13-failure burst is a stronger signal than the chapters alone; the
windowed detector correctly collapses the attacker's entire hammering sequence
into one flag. Failures are counted only from the parser's unique per-pid events,
so thresholds are never inflated by duplicate log lines.

## Checkpoint 5 — Command-line interface

`authmon/cli.py` plus `__main__.py` turn the pipeline into one runnable command:
`python3 -m authmon <path-to-authlog>`. It takes the log file as a positional
argument, so the same binary runs against a shipped copy on the analyst host or
a live /var/log/auth.log on the monitored server (placement-agnostic).

`-m authmon` requires a package `__main__.py` entry point, which delegates to
`cli.main()`. Verified: full report (23 events, 4 accepted, 13 failed,
6 invalid-user, 85 rejected) plus all three detected strategies, and a clean
error path (`error: cannot read '...'`) with exit code 2 and no traceback.


## Checkpoint 6 — Live attack validation

The tool was validated against a real attack rather than only a planted sample.
All activity stayed inside the isolated lab: Kali (10.10.10.50) attacking
Ubuntu web01 (10.10.10.20) over RFC-1918 addresses, no internet-reaching target.

Sequence:
1. `nmap -sV -p 22 10.10.10.20` confirmed SSH and its banner.
2. Username spray: `hydra -L /tmp/lab-users.txt -p ... ssh://10.10.10.20`
   across six non-existent accounts (admin, service, appuser, temp,
   nobody_bt, baker).
3. Dictionary run: `hydra -l northstar -P /tmp/lab-wordlist.txt -t 4 -f -I`
   using a 500-entry slice. The run completed all 500 attempts at roughly
   70-82 tries per minute and reported "0 valid password found" — the
   dictionary did not contain the account's password, so no credential was
   compromised. This run evidences the failed-login burst.
4. To exercise the stateful rule, a throwaway account (labtarget) was created on
   web01 with a known weak password and logged into deliberately. It was removed
   afterwards with `sudo userdel -r labtarget`.

The attack window was sliced from the live log (BEFORE/AFTER line counts) into
`samples/ssh-attack-live-01.log`, then analysed:

    python3 -m authmon samples/ssh-attack-live-01.log

Result:
- 109 events, 101 failed, 6 invalid-user, 2 accepted, 568 lines rejected
- first seen 2026-11-08 09:25:03, last seen 09:37:47
- every event attributed to 10.10.10.50; top user northstar (102)
- burst: 18 failed in 60s
- spray: 6 invalid users (admin, appuser, baker, nobody_bt, service, temp)
- success-after-failure: labtarget succeeded at 09:36:48

Both accepted logins in the slice are accounted for:
    Nov  8 09:36:48 sshd[1552]: Accepted password for labtarget from 10.10.10.50
    Nov  8 09:37:47 sshd[1623]: Accepted password for northstar from 10.10.10.50

The first is the deliberate labtarget login that fires the stateful rule. The
second is the operator's own administrative session as northstar, used to create
labtarget and slice the log — not a hydra hit. Neither represents a cracked
credential.

The burst reports the densest 60-second window (18), not the campaign total
(101) — correct windowed behaviour, since 101 failures spread over ~12 minutes
is a campaign while 18 inside one minute is the burst. All three detectors fired
against a real remote source, proving detection on real-world input and not only
on hand-written patterns.

Note on the hydra screenshot: it records a repeat run of the same 500-entry
dictionary at 11:26-11:33, after the captured window, which also found no valid
password. It is included as evidence of the tooling and its rate, not as
evidence of a cracked credential.