"""Entry point so `python3 -m authmon <logfile>` runs the CLI."""
import sys

from authmon import cli


if __name__ == "__main__":
    sys.exit(cli.main())
