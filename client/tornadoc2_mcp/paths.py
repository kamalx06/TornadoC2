"""Client-side state paths.

Everything the operator workstation writes lives under
``<repo>/client/.tornadoc2/`` — never ``$HOME``. Kept as one
module so the MCP server, the REPL, the transport pin store and
the GUI all agree on the location.

``TORNADOC2_CLIENT_STATE`` overrides the directory, for tests.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

CLIENT_DIR = Path(__file__).resolve().parent.parent
STATE_DIR = Path(
    os.environ.get('TORNADOC2_CLIENT_STATE')
    or (CLIENT_DIR / '.tornadoc2'))

AI_CONFIG = STATE_DIR / 'ai.json'
MCP_LOG = STATE_DIR / 'mcp.log'
BUILD_DIR = STATE_DIR / 'builds'
PINS_DIR = STATE_DIR / 'pins'
HISTORY_FILE = STATE_DIR / 'history'
ARMORY_DIR = STATE_DIR / 'armory'

_MIGRATION_MARKER = STATE_DIR / '.migrated-from-home'
_LEGACY_DIR = Path.home() / '.tornadoc2'
_LEGACY_HISTORY = Path.home() / '.tornadoc2_history'

_MIGRATE_FILES = ('ai.json', 'mcp.log')
_MIGRATE_DIRS = ('builds', 'pins')


def _chmod(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _migrate_legacy_once() -> None:
    """Copy old ``$HOME`` state in once, never overwriting."""
    if _MIGRATION_MARKER.exists():
        return
    try:
        if not _LEGACY_DIR.is_dir() and not _LEGACY_HISTORY.is_file():
            return
        for name in _MIGRATE_FILES:
            src = _LEGACY_DIR / name
            dst = STATE_DIR / name
            if src.is_file() and not dst.exists():
                shutil.copy2(src, dst)
                _chmod(dst, 0o600)
        for name in _MIGRATE_DIRS:
            src = _LEGACY_DIR / name
            dst = STATE_DIR / name
            if src.is_dir() and not dst.exists():
                shutil.copytree(src, dst)
        for src in _LEGACY_DIR.glob('*.signer-pin'):
            dst = PINS_DIR / src.name
            if not dst.exists():
                shutil.copy2(src, dst)
                _chmod(dst, 0o600)
        if _LEGACY_HISTORY.is_file() and not HISTORY_FILE.exists():
            shutil.copy2(_LEGACY_HISTORY, HISTORY_FILE)
        _MIGRATION_MARKER.write_text(
            f'migrated from {_LEGACY_DIR}\n', encoding='utf-8')
        _chmod(_MIGRATION_MARKER, 0o600)
    except OSError:
        # Migration is best effort; a fresh tree is still usable.
        pass


def ensure_state_dir() -> Path:
    """Create the state tree ``0700`` and run legacy migration once."""
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    _chmod(STATE_DIR, 0o700)
    for d in (PINS_DIR, ARMORY_DIR):
        d.mkdir(mode=0o700, parents=True, exist_ok=True)
        _chmod(d, 0o700)
    _migrate_legacy_once()
    return STATE_DIR
