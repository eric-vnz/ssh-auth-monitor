"""rules.py - detect hostile SSH patterns in parsed auth events."""
from collections import Counter, defaultdict


# Thresholds (per source): failures inside this window == a burst.
BURST_WINDOW_SECONDS = 60
BURST_MIN_FAILURES = 5

# Distinct invalid users from one source over the whole log == a spray.
SPRAY_MIN_INVALID_USERS = 3


def _windowed_failures(events, source):
    """Failures from one source; None if source not seen."""
    t = [e.timestamp for e in events
         if e.source_ip == source and e.outcome == "failed"]
    return t


def detect_burst(events, source):
    """True if >= BURST_MIN_FAILURES failures occur within BURST_WINDOW_SECONDS."""
    times = sorted(_windowed_failures(events, source))
    for i, start in enumerate(times):
        # count failures within the window starting at 'start'
        end = start.timestamp() + BURST_WINDOW_SECONDS
        count = sum(1 for t in times if start.timestamp() <= t.timestamp() <= end)
        if count >= BURST_MIN_FAILURES:
            return True, count, times[i:i + count]
    return False, len(times), times


def detect_spray(events, source):
    """True if a source tried >= SPRAY_MIN_INVALID_USERS distinct usernames."""
    invalids = {e.username for e in events
                if e.source_ip == source and e.outcome == "invalid_user"}
    return len(invalids) >= SPRAY_MIN_INVALID_USERS, sorted(invalids)


def detect_success_after_failure(events, source):
    """True if any accepted event is preceded (same source) by >=1 failure."""
    ordered = sorted((e for e in events if e.source_ip == source),
                     key=lambda e: e.timestamp)
    for i, ev in enumerate(ordered):
        if ev.outcome == "accepted":
            prev = [x for x in ordered[:i] if x.outcome == "failed"]
            if prev:
                return True, ev, prev[-1]
    return False, None, None


def analyze(events):
    """Run all three detectors per source. Returns {source: [findings]}."""
    sources = {e.source_ip for e in events}
    findings_by_source = {}
    for src in sources:
        findings = []
        burst, count, times = detect_burst(events, src)
        if burst:
            findings.append(f"burst: {count} failed in {BURST_WINDOW_SECONDS}s")
        spray, users = detect_spray(events, src)
        if spray:
            findings.append(f"spray: {len(users)} invalid users ({', '.join(users)})")
        saf, accepted_ev, _ = detect_success_after_failure(events, src)
        if saf:
            findings.append(f"success-after-failure: {accepted_ev.username} succeeded "
                            f"at {accepted_ev.timestamp:%H:%M:%S}")
        if findings:
            findings_by_source[src] = findings
    return findings_by_source
