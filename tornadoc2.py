#!/usr/bin/env python3
"""Beacon C2 — pull-based command and control.

Operator-side entry point. Boots the beacon listener, signs and
queues tasks, compiles agents, and drops into the interactive
console.

    python3 beacon_c2.py --beacon-port 8881

See README.md for the full operator reference and SECURITY.md for
the trust model and the report-a-vulnerability process.
"""

import sys

from tornadoc2.beacon_handler import BeaconHandler, main


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print()
        sys.exit(130)