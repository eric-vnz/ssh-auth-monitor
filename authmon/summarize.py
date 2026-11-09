"""summarize.py - build a high-level summary of parsed auth events."""
from collections import Counter
from datetime import datetime


def summarize(events):
    if not events:
        return {
            "total": 0, "accepted": 0, "failed": 0, "invalid_user": 0,
            "first_seen": None, "last_seen": None,
            "top_sources": [], "top_users": [],
        }

    accepted = sum(1 for e in events if e.outcome == "accepted")
    failed   = sum(1 for e in events if e.outcome == "failed")
    invalid  = sum(1 for e in events if e.outcome == "invalid_user")

    sources = Counter(e.source_ip for e in events)
    users   = Counter(e.username   for e in events)

    times = sorted(e.timestamp for e in events)

    return {
        "total": len(events),
        "accepted": accepted,
        "failed": failed,
        "invalid_user": invalid,
        "first_seen": times[0],
        "last_seen": times[-1],
        "top_sources": sources.most_common(5),
        "top_users": users.most_common(5),
    }
