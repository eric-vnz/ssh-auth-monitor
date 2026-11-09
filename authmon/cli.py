"""cli.py - run the full auth-monitor pipeline from one command."""
import sys
from authmon import auth_parser as ap, summarize as s, rules as r


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 1:
        print("usage: python3 -m authmon <path-to-authlog>")
        return 2

    path = argv[0]
    try:
        with open(path) as f:
            text = f.read()
    except OSError as err:
        print(f"error: cannot read '{path}': {err}", file=sys.stderr)
        return 2

    parsed = ap.parse_log(text)
    summ = s.summarize(parsed.events)
    findings = r.analyze(parsed.events)

    print("== Summary ==")
    print(f"  events        : {summ['total']}")
    print(f"  accepted      : {summ['accepted']}")
    print(f"  failed        : {summ['failed']}")
    print(f"  invalid_user  : {summ['invalid_user']}")
    print(f"  first seen    : {summ['first_seen']}")
    print(f"  last seen     : {summ['last_seen']}")
    print(f"  top sources   : {summ['top_sources']}")
    print(f"  top users     : {summ['top_users']}")
    print(f"  lines rejected: {parsed.rejected}")

    print("== Detected strategies by source ==")
    if not findings:
        print("  (none)")
    for src, dets in findings.items():
        print(f"  {src}:")
        for d in dets:
            print(f"    - {d}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
