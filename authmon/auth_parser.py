"""auth_parser.py - turn Ubuntu auth.log SSH lines into structured auth events.

One SSH connection writes several log lines that share a single sshd PID.
This parser keys on the one DEFINITIVE outcome line of each connection
("Accepted password" / "Failed password" / "Failed password for invalid user")
and ignores the sibling PAM, invalid-user-precursor and connection-close noise
lines, so one connection always produces exactly one event.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


# Line shape: "Nov  2 14:38:49 web01 sshd[1519]: <message>"
_LINE_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) "
    r"(?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<proc>\w+)\[(?P<pid>\d+)\]:\s*(?P<message>.*)$"
)

# The three decisive outcome lines.
_ACCEPT_RE = re.compile(
    r"^Accepted password for (?P<user>\S+) from (?P<ip>\S+) port \d+")
_INVALID_RE = re.compile(
    r"^Failed password for invalid user (?P<user>\S+) from (?P<ip>\S+) port \d+")
_FAIL_RE = re.compile(
    r"^Failed password for (?P<user>\S+) from (?P<ip>\S+) port \d+")


@dataclass
class AuthEvent:
    timestamp: datetime
    host: str
    pid: int
    source_ip: str
    username: str
    outcome: str      # 'accepted' | 'failed' | 'invalid_user'
    raw: str          # original line, for showing evidence


@dataclass
class ParsedLog:
    events: list
    rejected: int


def _parse_timestamp(month: str, day: str, time_: str, year: int = 2026) -> datetime:
    """'Nov', ' 2', '14:38:49' -> datetime. Single-digit days need padding."""
    return datetime.strptime(f"{month} {int(day):02d} {time_} {year}",
                             "%b %d %H:%M:%S %Y")


def parse_line(line: str, year: int = 2026) -> Optional[AuthEvent]:
    m = _LINE_RE.match(line)
    if not m:
        return None
    msg = m.group("message")

    # Check invalid-user BEFORE plain failed: it starts with "Failed password".
    am = _ACCEPT_RE.match(msg)
    if am:
        outcome, user, ip = "accepted", am.group("user"), am.group("ip")
    else:
        im = _INVALID_RE.match(msg)
        if im:
            outcome, user, ip = "invalid_user", im.group("user"), im.group("ip")
        else:
            fm = _FAIL_RE.match(msg)
            if not fm:
                return None                       # PAM / disconnect / noise
            outcome, user, ip = "failed", fm.group("user"), fm.group("ip")

    return AuthEvent(
        timestamp=_parse_timestamp(m.group("month"), m.group("day"),
                                   m.group("time"), year),
        host=m.group("host"),
        pid=int(m.group("pid")),
        source_ip=ip,
        username=user,
        outcome=outcome,
        raw=line.rstrip("\n"),
    )


def parse_log(text: str, year: int = 2026) -> ParsedLog:
    """Parse full auth.log text -> one AuthEvent per connection.

    Defensive dedupe by PID: if one connection ever produced two decisive
    lines, keep only the first so thresholds are never double-counted.
    """
    seen: set[int] = set()
    events: list[AuthEvent] = []
    rejected = 0
    for line in text.splitlines():
        ev = parse_line(line, year)
        if ev is None:
            rejected += 1
            continue
        if ev.pid in seen:
            continue
        seen.add(ev.pid)
        events.append(ev)
    return ParsedLog(events=events, rejected=rejected)
