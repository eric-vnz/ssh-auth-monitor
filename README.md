# ssh-auth-monitor

An offline Python analyser for Ubuntu `/var/log/auth.log`. It turns raw SSH
authentication lines into one structured event per connection, a traffic
summary, and detections for three hostile patterns.

Sibling project to [log-anomaly-detector](https://github.com/eric-vnz/log-anomaly-detector),
which analyses Nginx access logs. This one adds a stateful rule that needs
cross-line state.

## Detections

<table>
  <thead>
    <tr>
      <th align="left">Rule</th>
      <th align="left">Logic</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Failed-login burst</td>
      <td>5 or more failures from one source IP within 60 seconds</td>
    </tr>
    <tr>
      <td>Invalid-username spray</td>
      <td>3 or more distinct non-existent accounts from one source IP</td>
    </tr>
    <tr>
      <td>Success-after-failure</td>
      <td>an accepted login preceded by failures from the same source IP</td>
    </tr>
  </tbody>
</table>

Thresholds and windows are configurable. All three operate per source IP.

## Design note: one connection, one event

A single SSH attempt writes several log lines that share one `sshd` process id -
a PAM diagnostic, the decisive outcome, and a connection close. Counting lines
would triple-count every attempt and inflate burst thresholds.

The parser keys on the definitive outcome line only (`Accepted password`,
`Failed password`, `Failed password for invalid user`) and deduplicates by
`sshd` pid, so one connection always yields exactly one event. Invalid-user
lines are matched before plain failures, because `Failed password for invalid
user` begins with `Failed password`.

A related distinction: `root` is a real account, so an attempt on it logs as
`Failed password for root`, not `Failed password for invalid user root`.
Invalid-user detection applies only to usernames that do not exist.

## Usage

```bash
python3 -m authmon <path-to-authlog>
```

The log path is a positional argument, so the same command runs in two
placements:

```bash
# off-box, against a shipped log copy
python3 -m authmon samples/ssh-auth-lab-01.log

# host-based, against the live log on the monitored server
sudo python3 -m authmon /var/log/auth.log
```

Off-box collection keeps evidence away from an attacker who may already hold the
host; host-based monitoring sees activity in real time but runs on ground the
attacker could tamper with. Supporting both from one binary was a deliberate
design constraint.

Unreadable input fails cleanly with a message and exit code 2, no traceback:

```
error: cannot read '/no/such/file.log': [Errno 2] No such file or directory
```

## Validation

**Labelled sample** (`samples/ssh-auth-lab-01.log`) - four replayed series:
wrong-password bursts, an invalid-username spray, a success-after-failure
sequence, and normal connections.

- 23 events: 13 failed, 6 invalid-user, 4 accepted
- 85 lines rejected as noise (PAM diagnostics, connection closes, sudo/systemd)
- all three detectors fire on 127.0.0.1: burst 13 in 60s, spray 6 accounts,
  success-after-failure at 14:39:44

**Edge-case tests** (`tests/test_auth_parser_edges.py`) - six tests covering
IPv6 sources, invalid-user lines with IPv6, unknown message types, connection
close lines, empty input, and duplicate decisive lines sharing one pid. All six
pass.

**Live attack** (`samples/ssh-attack-live-01.log`) - a real attack from Kali
(10.10.10.50) against Ubuntu web01 (10.10.10.20), inside an isolated RFC-1918
lab: nmap service check, a six-account hydra spray, and a 500-entry hydra
dictionary run against `northstar`.

- 109 events: 101 failed, 6 invalid-user, 2 accepted, 568 lines rejected
- every event attributed to 10.10.10.50; top user `northstar` (102)
- burst 18 in 60s, spray 6 accounts, success-after-failure at 09:36:48

The dictionary run completed all 500 attempts at roughly 70-82 tries per minute
and reported `0 valid password found` - no credential was compromised. The
success-after-failure trigger came from a purpose-created throwaway account
(`labtarget`) with a known weak password, removed after the demo. The burst
reports the densest 60-second window (18), not the campaign total (101).

## Repository layout

```
authmon/
  auth_parser.py    parse auth.log lines into per-connection events
  summarize.py      totals, outcome counts, first/last seen, top sources and users
  rules.py          burst, spray and success-after-failure detectors
  cli.py            one-command pipeline
  __main__.py       package entry point for python3 -m authmon
tests/
  test_auth_parser_edges.py
samples/
  ssh-auth-lab-01.log
  ssh-attack-live-01.log
docs/
  02-ssh-auth-monitor.md
  images/
```

## Scope

Offline analysis only. No geo/ASN enrichment, no automatic IP blocking, no live
alerting, no ML, no dashboard, and no SSH key-auth success tracking.

All attack testing was performed inside an isolated lab - Kali 10.10.10.50
against Ubuntu web01 10.10.10.20, private RFC-1918 addresses only, no
internet-reaching target - as sanctioned security testing on systems under the
operator's control.

## Documentation

Full write-up, checkpoint by checkpoint, with screenshots:
[docs/02-ssh-auth-monitor.md](docs/02-ssh-auth-monitor.md)

## Licence

MIT
