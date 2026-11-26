"""Allow invoking the unified CLI via `python3 -m open_fleet`."""

import sys

from open_fleet.cli import main


if __name__ == "__main__":
    sys.exit(main())
