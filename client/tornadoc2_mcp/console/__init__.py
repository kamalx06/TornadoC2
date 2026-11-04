"""The `console` subpackage.

Re-exports the four entry points so callers do not need to
reach into `console.loop` and `console.main` directly.

  main_ai      — beacon-client.py ai
  run          — python -m tornadoc2_mcp --ai
  run_console  — inline console (from the REPL's `ai`)
  run_one_shot — inline one-shot (from the REPL's `ai <q>`)
"""

from .main import main_ai, run
from .loop import run_console, run_one_shot

__all__ = ['main_ai', 'run', 'run_console', 'run_one_shot']