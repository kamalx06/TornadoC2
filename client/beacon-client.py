#!/usr/bin/env python3
"""Entry point — dispatches to CLI or GUI based on --gui.

The CLI (tornado_client.repl) is unchanged and remains the default.
Passing --gui swaps in the Tkinter operator console from
tornado_client.gui. Both frontends share the same Client class and
the same protocol code; only the presentation differs.
"""

import sys


def _run_cli() -> int:
    from tornado_client.repl import main
    return main()


def _run_gui() -> int:
    from tornado_client.gui import main_gui
    return main_gui()


def main() -> int:
    argv = sys.argv[1:]
    runner = _run_gui if '--gui' in argv else _run_cli
    sys.argv = [sys.argv[0]] + [a for a in argv if a != '--gui']
    return runner()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
    except Exception as exc:
        if '--debug' in sys.argv:
            raise
        print(f"unexpected error: {exc}", file=sys.stderr)
        sys.exit(1)