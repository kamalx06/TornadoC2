"""python -m tornadoc2_mcp [-c alice.cfg] [--ai]"""

import argparse
import asyncio
import sys

from . import errors
from .config import DEFAULT_AI_PATH, load_ai_config


def main():
    p = argparse.ArgumentParser(
        prog='tornadoc2_mcp',
        description='MCP server and AI console for TornadoC2')
    p.add_argument('-c', '--config', required=True,
                   help='operator .cfg file (mTLS + HMAC)')
    p.add_argument('--ai-config', default=str(DEFAULT_AI_PATH),
                   help=f'ai.json with provider, model, key '
                        f'(default: {DEFAULT_AI_PATH})')
    p.add_argument('--ai', action='store_true',
                   help='run the built-in AI console instead '
                        'of the MCP stdio server')
    p.add_argument('--verbose', action='store_true')
    args = p.parse_args()

    try:
        cfg = load_ai_config(args.ai_config)
    except errors.McpError as exc:
        print(f'[ai] {exc}', file=sys.stderr)
        hint = getattr(exc, 'hint', '') or ''
        if hint:
            print(f'     {hint}', file=sys.stderr)
        return 1
    except Exception as exc:
        print(f'[ai] {exc}', file=sys.stderr)
        return 1

    if args.ai:
        from .console.loop import run_console_from_path
        try:
            return asyncio.run(
                run_console_from_path(args.config, cfg))
        except KeyboardInterrupt:
            print()
            return 130
        except errors.McpError as exc:
            print(f'[ai] {exc}', file=sys.stderr)
            hint = getattr(exc, 'hint', '') or ''
            if hint:
                print(f'     {hint}', file=sys.stderr)
            return 1

    from .protocol import serve
    try:
        asyncio.run(serve(args.config, cfg))
    except KeyboardInterrupt:
        print()
        return 130
    except errors.McpError as exc:
        print(f'[ai] {exc}', file=sys.stderr)
        hint = getattr(exc, 'hint', '') or ''
        if hint:
            print(f'     {hint}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main() or 0)