"""Per-session directory logging.

Every session — shell or beacon — gets its own directory under
``logs/``. The directory name is derived from the session's
identifier, user, host, and IP.

Two things matter more than anything else in this module:

1. **Writes never abort a session.** Every filesystem operation is
   wrapped in a try/except. If the disk is full, the permissions are
   wrong, or anything else fails, the session keeps running. Logging
   is a side effect, not a requirement.

2. **Target-supplied strings are sanitized before use as a path.**
   A compromised target can report any hostname it wants, including
   one containing ``..`` or ``/``. The directory name is sanitized
   so the logger can never write outside ``logs/``.
"""

import os
import re
import threading
import time

from .constants import LOGS_DIR


# ---------------------------------------------------------------------
# Path sanitization

_DIR_SAFE_RE = re.compile(r'[^\w@.\-]+')


def _safe_dirname(name: str) -> str:
    """Return a filesystem-safe directory name.

    Target-supplied strings (hostname, username) are the primary
    inputs. A malicious target could report ``../../tmp/evil`` as its
    hostname. Stripping path separators, collapsing any remaining
    ``..`` sequences, and capping the length keeps every write inside
    the ``logs/`` directory regardless of what the target sends.
    """
    if not name:
        return 'session'
    safe = _DIR_SAFE_RE.sub('_', str(name))
    while '..' in safe:
        safe = safe.replace('..', '_')
    safe = safe.lstrip('.')
    if len(safe) > 200:
        safe = safe[:200]
    return safe or 'session'


# ---------------------------------------------------------------------
# Terminal control sequence stripping

_CSI_RE = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
_OSC_RE = re.compile(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)')
_DCS_RE = re.compile(r'\x1b[PX^_][^\x1b]*(?:\x1b\\)?')
_SIMPLE_ESC_RE = re.compile(r'\x1b[@-Z\\-_]')
_NUL_RE = re.compile(r'\x00')


def _strip_control_sequences(text: str) -> str:
    """Remove ANSI / OSC / DCS sequences and NUL bytes.

    Cheap when there is nothing to strip. If the string does not
    contain an ESC byte or a NUL, the regexes are skipped entirely.
    """
    if not text:
        return text
    if '\x1b' in text:
        text = _CSI_RE.sub('', text)
        text = _OSC_RE.sub('', text)
        text = _DCS_RE.sub('', text)
        text = _SIMPLE_ESC_RE.sub('', text)
    if '\x00' in text:
        text = _NUL_RE.sub('', text)
    return text


# ---------------------------------------------------------------------
# Session logger

class SessionLogger:
    """One logging directory per session.

    The ``session_id`` passed to the constructor is treated as the
    directory name. Callers build it from any fields they like; the
    logger sanitizes it.

    Example::

        logger = SessionLogger(
            f"b{session.id:03d}_{user}@{host}_{ip}_beacon")
        logger.log_event("Beacon check-in from 192.168.1.10")
    """

    def __init__(self, session_id: str):
        self.session_id = _safe_dirname(session_id)
        self.session_dir = os.path.join(LOGS_DIR, self.session_id)
        self.log_path = os.path.join(self.session_dir, 'session.log')
        self._lock = threading.Lock()

        try:
            os.makedirs(self.session_dir, exist_ok=True)
        except OSError:
            self.session_dir = os.path.join(LOGS_DIR, '_fallback')
            try:
                os.makedirs(self.session_dir, exist_ok=True)
            except OSError:
                pass
            self.log_path = os.path.join(self.session_dir, 'session.log')

    # ------------------------------------------------------------------
    # Low-level write

    def _append(self, line: str) -> None:
        """Append a single line to session.log. Never raises."""
        try:
            with self._lock:
                with open(self.log_path, 'a', encoding='utf-8',
                          errors='replace') as fh:
                    fh.write(line)
                    if not line.endswith('\n'):
                        fh.write('\n')
        except OSError:
            pass

    @staticmethod
    def _timestamp() -> str:
        return time.strftime('%Y-%m-%d %H:%M:%S')

    # ------------------------------------------------------------------
    # Public API

    def log_event(self, message: str) -> None:
        """Append a timestamped event line.

        Used for check-ins, signature events, session state changes,
        and any other single-line annotation the operator or the
        engine wants to record.
        """
        message = _strip_control_sequences(str(message))
        self._append(f"{self._timestamp()} [EVENT] {message}")

    def log_command(self, cmd: str, output: str = '') -> None:
        """Append an operator command and its captured output.

        The command line itself is written verbatim. The output is
        sanitized — control sequences are stripped so a hostile
        target cannot smuggle terminal escapes into the log file.
        """
        cmd = _strip_control_sequences(str(cmd))
        output = _strip_control_sequences(str(output or ''))
        self._append(f"{self._timestamp()} [CMD] {cmd}")
        if output:
            for line in output.splitlines() or ['']:
                self._append(f"  {line}")

    def log_reconnect(self, detail: str) -> None:
        """Append a reconnect event."""
        detail = _strip_control_sequences(str(detail))
        self._append(f"{self._timestamp()} [RECONNECT] {detail}")

    # ------------------------------------------------------------------
    # Plugin reports

    def log_plugin_result(self, plugin_name: str, report: str,
                          detail: str = '') -> None:
        """Write a plugin report to ``<session>/plugins/<name>_<ts>.log``.

        Never raises. If the write fails, the failure is swallowed
        and the session continues.
        """
        plugin_name = _safe_dirname(plugin_name) or 'plugin'
        report = _strip_control_sequences(str(report or ''))
        detail = _strip_control_sequences(str(detail or ''))

        try:
            plugins_dir = os.path.join(self.session_dir, 'plugins')
            os.makedirs(plugins_dir, exist_ok=True)
            stamp = time.strftime('%Y%m%d_%H%M%S')
            fname = f"{plugin_name}_{stamp}.log"
            path = os.path.join(plugins_dir, fname)
            with self._lock:
                with open(path, 'w', encoding='utf-8',
                          errors='replace') as fh:
                    if detail:
                        fh.write(f"[detail]\n{detail}\n\n")
                    fh.write(report)
                    if not report.endswith('\n'):
                        fh.write('\n')
        except OSError:
            pass

    def save_sysinfo(self, info: dict) -> None:
        """Write a sysinfo snapshot to ``<session>/sysinfo.json``."""
        if not isinstance(info, dict):
            return
        try:
            import json as _json
            path = os.path.join(self.session_dir, 'sysinfo.json')
            with self._lock:
                with open(path, 'w', encoding='utf-8',
                          errors='replace') as fh:
                    _json.dump(info, fh, indent=2, default=str)
        except (OSError, ValueError, TypeError):
            pass