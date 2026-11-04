"""The `beacon-client.py ai` entry point.

Two callers, two conventions:

  main_ai(argv)
    Called from beacon-client.py's `_run_ai()`. `argv` is
    what follows `ai` on the command line — e.g.
    `['-c', 'alice.cfg', '--ai-config', '~/.tornadoc2/ai.json']`.
    argparse handles the flags; `load_ai_config` validates
    the ai.json; `run_console_from_path` loads the .cfg,
    authenticates, and enters the interactive loop.

  run(cfg_path, cfg)
    Called from `tornadoc2_mcp/__main__.py` when the operator
    runs `python -m tornadoc2_mcp --ai`. `__main__.py` has
    already parsed the arguments and built the AiConfig, so
    this is just the bridge to the async loop entry point.

Both end up in `loop.run_console_from_path`, which loads a
fresh client from the .cfg and runs the interactive agent
loop. Neither shares state with any other console — the AI
subcommand is a fresh process from the REPL's perspective.

For inline AI inside the REPL (sharing an already-loaded
Client), see `tornado_client/repl.py::_cmd_ai`, which calls
`loop.run_console` or `loop.run_one_shot` directly.
"""

import argparse
import asyncio
import sys

from .. import errors
from ..config import DEFAULT_AI_PATH, load_ai_config
from .loop import run_console_from_path


def main_ai(argv) -> int:
    """Entry point for `beacon-client.py ai`.

    Parses `-c <cfg>` and `--ai-config <path>`, loads the AI
    configuration, and runs the interactive console against a
    freshly-loaded client.

    Returns a process exit code:
      0    console ran, operator exited normally
      1    setup failed (bad ai.json, missing .cfg, provider
           not configured, cannot authenticate)
      130  Ctrl+C at the prompt
    """
    p = argparse.ArgumentParser(
        prog='beacon-client.py ai',
        description='AI operator console backed by the '
                    "operator's own LLM provider")
    p.add_argument(
        '-c', '--config', required=True,
        help='operator .cfg (mTLS + HMAC credentials; the '
             'same file the CLI takes)')
    p.add_argument(
        '--ai-config', default=str(DEFAULT_AI_PATH),
        help=f'provider, model, and allowlists '
             f'(default: {DEFAULT_AI_PATH})')
    args = p.parse_args(argv)

    # ---- Load the AI configuration ------------------------------
    # load_ai_config raises ProviderNotConfiguredError with a
    # .hint for every common failure (missing file, wrong
    # permissions, unknown provider, missing api_key). Print the
    # hint so the operator has an actionable next step instead
    # of just the error line.
    try:
        cfg = load_ai_config(args.ai_config)
    except errors.McpError as exc:
        print(f'[ai] {exc}', file=sys.stderr)
        hint = getattr(exc, 'hint', '') or ''
        if hint:
            print(f'     {hint}', file=sys.stderr)
        return 1

    # ---- Run the console ----------------------------------------
    # run_console_from_path loads the .cfg, authenticates,
    # prints the banner, and enters the interactive loop. It
    # returns 0 on clean exit, 1 on setup failure. Ctrl+C at
    # the prompt raises KeyboardInterrupt, which we translate
    # to the conventional 130.
    try:
        return asyncio.run(
            run_console_from_path(args.config, cfg))
    except KeyboardInterrupt:
        print()
        return 130


async def run(cfg_path, cfg):
    """Entry point for `python -m tornadoc2_mcp --ai`.

    The package's `__main__.py` has already parsed argv and
    built the AiConfig; this function's only job is to reach
    the async loop entry point. Kept async so `__main__.py`
    can use `asyncio.run(run(...))` symmetrically with the
    MCP server path.
    """
    return await run_console_from_path(cfg_path, cfg)


# ---------------------------------------------------------------------
# Standalone invocation, for testing.
#
#     python -m tornadoc2_mcp.console.main -c alice.cfg
#
# Equivalent to `beacon-client.py ai -c alice.cfg`, useful when
# the operator does not have beacon-client.py on PATH.

if __name__ == '__main__':
    sys.exit(main_ai(sys.argv[1:]))