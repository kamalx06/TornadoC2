"""Structured logging.

Format is `key=value` on one line. Never JSON, because the
operator is usually watching a terminal and JSON on a terminal
is worse than useless.

Two channels:

  console → printed to stderr, for the operator
  journal → appended to <repo>/client/.tornadoc2/mcp.log

Neither channel ever logs a value the operator has not seen on
their own terminal. API keys are stripped by the config loader
before any log call could see them.
"""

import os
import sys
import time
from pathlib import Path
from threading import Lock

from .paths import MCP_LOG, ensure_state_dir


_JOURNAL_PATH = MCP_LOG
_MAX_BYTES = 5 * 1024 * 1024
_JOURNAL_LOCK = Lock()
_REDACT_KEYS = frozenset({
    'api_key', 'password', 'value', 'auth_hash',
    'client_key', 'private_key',
})


def _redact(extra: dict) -> dict:
    return {
        k: ('***' if k in _REDACT_KEYS else v)
        for k, v in extra.items()
    }


def _fmt(level: str, msg: str, extra: dict) -> str:
    parts = [f'ts={time.strftime("%Y-%m-%dT%H:%M:%S")}',
             f'level={level}',
             f'msg={msg!r}']
    for k, v in _redact(extra).items():
        if isinstance(v, str):
            parts.append(f'{k}={v!r}' if ' ' in v else f'{k}={v}')
        else:
            parts.append(f'{k}={v}')
    return ' '.join(parts)


def _journal(line: str) -> None:
    try:
        ensure_state_dir()
        with _JOURNAL_LOCK:
            try:
                if _JOURNAL_PATH.stat().st_size > _MAX_BYTES:
                    os.replace(_JOURNAL_PATH,
                               _JOURNAL_PATH.with_suffix('.log.1'))
            except OSError:
                pass
            with open(_JOURNAL_PATH, 'a', encoding='utf-8') as fh:
                fh.write(line + '\n')
            try:
                os.chmod(_JOURNAL_PATH, 0o600)
            except OSError:
                pass
    except OSError:
        pass


def debug(msg, **extra):
    line = _fmt('debug', msg, extra)
    _journal(line)


def info(msg, **extra):
    line = _fmt('info', msg, extra)
    _journal(line)


def warn(msg, **extra):
    line = _fmt('warn', msg, extra)
    print(line, file=sys.stderr, flush=True)
    _journal(line)


def error(msg, **extra):
    line = _fmt('error', msg, extra)
    print(line, file=sys.stderr, flush=True)
    _journal(line)