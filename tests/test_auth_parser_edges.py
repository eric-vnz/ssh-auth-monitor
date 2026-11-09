"""Edge-case tests for authmon/auth_parser.py."""
import pytest
from authmon import auth_parser as ap


def test_ipv6_source_address():
    line = ("Nov  2 14:39:44 web01 sshd[1685]: "
            "Failed password for labuser from 2001:db8::1 port 12345 ssh2")
    ev = ap.parse_line(line)
    assert ev is not None
    assert ev.source_ip == "2001:db8::1"
    assert ev.outcome == "failed"


def test_invalid_user_with_ipv6():
    line = ("Nov  2 14:39:44 web01 sshd[1700]: "
            "Failed password for invalid user admin from 2001:db8::5 port 500 ssh2")
    ev = ap.parse_line(line)
    assert ev is not None
    assert ev.outcome == "invalid_user"
    assert ev.source_ip == "2001:db8::5"


def test_unknown_message_type_rejected():
    line = ("Nov  2 14:39:44 web01 sshd[1685]: "
            "reverse mapping checking getaddrinfo for 2001:db8::1 failed.")
    assert ap.parse_line(line) is None


def test_connection_closed_rejected():
    line = ("Nov  2 14:39:44 web01 sshd[1616]: "
            "Connection closed by authenticating user labuser 127.0.0.1 port 54740 [preauth]")
    assert ap.parse_line(line) is None


def test_empty_file():
    parsed = ap.parse_log("")
    assert parsed.events == []
    assert parsed.rejected == 0


def test_dedupe_duplicate_decisive_lines_same_pid():
    text = (
        "Nov  2 14:39:44 web01 sshd[1616]: Accepted password for labuser from 127.0.0.1 port 54740 ssh2\n"
        "Nov  2 14:39:44 web01 sshd[1616]: Accepted password for labuser from 127.0.0.1 port 54740 ssh2\n"
    )
    parsed = ap.parse_log(text)
    assert len(parsed.events) == 1
    assert parsed.events[0].outcome == "accepted"
