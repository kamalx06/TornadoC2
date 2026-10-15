"""Session registry — persistent, cross-session tracking.

The registry records every session the handler has ever seen,
including ones that have since disconnected. It exists so that:

  * A reconnecting session can reclaim its original ID and its
    original log directory (shell handler).
  * The operator can list historical sessions and see connect
    counts (both shell and beacon).
  * A beacon check-in can leave a durable record for reporting,
    even though the beacon engine keeps its own in-memory session
    list.

The registry persists to ``logs/registry.json``. Every mutation
writes the file atomically (temp + rename) so a crash cannot leave
a half-written registry behind.

All public methods are thread-safe. Writes never raise — the
registry is a side effect and must never abort a session.
"""

import hashlib
import json
import os
import re
import threading
import time
from typing import Optional

from .constants import LOGS_DIR


# ---------------------------------------------------------------------
# Fingerprinting

def _norm_machine_id(mid: str) -> str:
    """Normalize a machine ID for stable comparison.

    Windows MachineGuid is a GUID with casing that is not guaranteed
    to be consistent across tools. Linux machine-id is lowercase hex.
    Both sides are lowercased and stripped of whitespace so the
    fingerprint does not drift on casing alone.
    """
    if not mid:
        return ''
    return str(mid).strip().lower()


def compute_fingerprint(info: dict, probe_output: str = '') -> str:
    """Return a 32-char hex fingerprint over the fields that survive
    reimaging and reboots.

    ``machine_id`` alone is not sufficient — some imaging operations
    regenerate it. Including hostname and username makes the
    fingerprint resilient while still unique per machine.
    """
    h = hashlib.sha256()
    for key in ('machine_id', 'hostname', 'username', 'os'):
        value = ''
        if isinstance(info, dict):
            value = info.get(key) or ''
        h.update(str(value).encode('utf-8', 'replace'))
        h.update(b'\x00')

    if probe_output:
        h.update(str(probe_output)[:4096].encode('utf-8', 'replace'))

    return h.hexdigest()[:32]


# ---------------------------------------------------------------------
# Path sanitization for the log_session_id field

_DIR_SAFE_RE = re.compile(r'[^\w@.\-]+')


def _safe_log_id(name: str) -> str:
    if not name:
        return ''
    safe = _DIR_SAFE_RE.sub('_', str(name))
    while '..' in safe:
        safe = safe.replace('..', '_')
    safe = safe.lstrip('.')
    return safe[:200]


# ---------------------------------------------------------------------
# Registry

class SessionRegistry:
    """Persistent, thread-safe session tracking."""

    REGISTRY_FILENAME = 'registry.json'

    def __init__(self, path: Optional[str] = None):
        self._lock = threading.RLock()
        self._path = path or os.path.join(
            LOGS_DIR, self.REGISTRY_FILENAME)
        self._records: list = []
        self._by_fp: dict = {}
        self._load()

    # ------------------------------------------------------------------
    # Persistence

    def _load(self) -> None:
        """Load the registry from disk. Never raises."""
        if not os.path.isfile(self._path):
            return
        try:
            with open(self._path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return
        if not isinstance(data, list):
            return
        for rec in data:
            if not isinstance(rec, dict):
                continue
            fp = rec.get('fingerprint')
            if not fp:
                continue
            self._records.append(rec)
            self._by_fp[fp] = rec

    def _save(self) -> None:
        """Write the registry atomically. Never raises."""
        try:
            tmp = self._path + '.tmp'
            os.makedirs(os.path.dirname(self._path) or '.',
                        exist_ok=True)
            with open(tmp, 'w', encoding='utf-8') as fh:
                json.dump(self._records, fh, indent=2, default=str)
            os.replace(tmp, self._path)
        except (OSError, ValueError, TypeError):
            pass

    # ------------------------------------------------------------------
    # Internal helpers

    @staticmethod
    def _addr_str(info: dict) -> str:
        """Render an address tuple or string as a printable string."""
        addr = info.get('addr')
        if not addr:
            return ''
        if isinstance(addr, (tuple, list)) and len(addr) >= 2:
            return f"{addr[0]}:{addr[1]}"
        return str(addr)

    def _log_id_of(self, info: dict) -> str:
        """Extract the log directory name from an info dict, if the
        logger has already been constructed."""
        logger = info.get('logger')
        if logger is not None and hasattr(logger, 'session_id'):
            return _safe_log_id(logger.session_id)
        return ''

    # ------------------------------------------------------------------
    # Mutation

    def register_active(self, info: dict, fingerprint: str,
                        probe_output: str = '') -> None:
        """Register or update a session.

        Called every time a session produces an activity signal:
        a shell ``handle_client`` on connect or reconnect, or a
        beacon ``check-in`` on every poll.

        The fingerprint is the primary key. A session with a
        fingerprint that is already known has its record updated
        in place — connect_count, sysinfo, address, and log id.
        A new fingerprint creates a new record.
        """
        if not fingerprint:
            return
        with self._lock:
            rec = self._by_fp.get(fingerprint)
            if rec is None:
                rec = {
                    'fingerprint': fingerprint,
                    'session_id': info.get('id'),
                    'kind': info.get('kind', 'shell'),
                    'name': info.get('name'),
                    'type': info.get('type', 'unknown'),
                    'direction': info.get('direction', ''),
                    'sysinfo': dict(info.get('sysinfo') or {}),
                    'identity': dict(info.get('identity') or {}),
                    'first_seen': time.time(),
                    'last_seen': time.time(),
                    'connect_count': info.get('connect_count', 1),
                    'log_session_id': self._log_id_of(info),
                    'disconnected': False,
                    'addr': self._addr_str(info),
                }
                self._records.append(rec)
                self._by_fp[fingerprint] = rec
            else:
                rec['last_seen'] = time.time()
                if info.get('id') is not None:
                    rec['session_id'] = info['id']
                if info.get('name'):
                    rec['name'] = info['name']
                if info.get('type'):
                    rec['type'] = info['type']
                if info.get('direction'):
                    rec['direction'] = info['direction']
                if info.get('sysinfo'):
                    rec['sysinfo'] = dict(info['sysinfo'])
                if info.get('identity'):
                    rec['identity'] = dict(info['identity'])
                if info.get('connect_count') is not None:
                    rec['connect_count'] = info['connect_count']
                log_id = self._log_id_of(info)
                if log_id:
                    rec['log_session_id'] = log_id
                rec['disconnected'] = False
                rec['addr'] = self._addr_str(info)
            self._save()

    def mark_disconnected(self, info: dict) -> None:
        """Mark the session for this info dict as disconnected.

        The record is kept — a reconnecting session reclaims it.
        Only the ``disconnected`` flag is flipped so a display can
        distinguish "seen before, gone now" from "currently active".
        """
        fp = info.get('fingerprint') if isinstance(info, dict) else None
        if not fp:
            return
        with self._lock:
            rec = self._by_fp.get(fp)
            if rec is None:
                return
            rec['disconnected'] = True
            rec['last_seen'] = time.time()
            self._save()

    def migrate_fingerprint(self, old_fp: str, new_fp: str,
                            info: dict) -> None:
        """Move a record from one fingerprint to another.

        Used when sysinfo changes enough that the computed
        fingerprint drifts — for example, after a host rename or an
        OS upgrade. The old record is updated in place with the new
        fingerprint so its history is preserved.
        """
        if not old_fp or not new_fp or old_fp == new_fp:
            return
        with self._lock:
            rec = self._by_fp.pop(old_fp, None)
            if rec is None:
                # Nothing to migrate. Register fresh.
                self.register_active(info, new_fp)
                return
            if new_fp in self._by_fp:
                try:
                    self._records.remove(rec)
                except ValueError:
                    pass
                self._save()
                return
            rec['fingerprint'] = new_fp
            self._by_fp[new_fp] = rec
            self._save()

    # ------------------------------------------------------------------
    # Lookup

    def find_reconnect(self, fingerprint: str, probe_output: str,
                       info: dict, live_ids=None) -> Optional[dict]:
        """Return the record for a reconnecting session, or None.

        The primary match is by fingerprint. If no record exists for
        the fingerprint, the fallback is a machine_id / hostname /
        username match against every record on disk. This catches
        the case where the fingerprint algorithm changed between
        handler runs.
        """
        if fingerprint:
            with self._lock:
                rec = self._by_fp.get(fingerprint)
            if rec is not None:
                return dict(rec)

        mi = _norm_machine_id((info or {}).get('machine_id') or '')
        hn = str((info or {}).get('hostname') or '').strip().lower()
        un = str((info or {}).get('username') or '').strip().lower()
        if not (mi or hn):
            return None
        live_ids = set(live_ids or ())
        with self._lock:
            for rec in self._records:
                rec_id = rec.get('session_id')
                if rec_id in live_ids:
                    continue
                ident = rec.get('identity') or {}
                r_mi = _norm_machine_id(ident.get('machine_id') or '')
                r_hn = str(ident.get('hostname') or '').strip().lower()
                r_un = str(ident.get('username') or '').strip().lower()
                if mi and r_mi and mi == r_mi:
                    return dict(rec)
                if hn and r_hn and hn == r_hn and un == r_un:
                    return dict(rec)
        return None

    def get_connect_count(self, fingerprint: str) -> int:
        """Return the connect count for a fingerprint, or 1 if unknown."""
        if not fingerprint:
            return 1
        with self._lock:
            rec = self._by_fp.get(fingerprint)
            if rec is None:
                return 1
            return int(rec.get('connect_count') or 1)

    def restore_logger(self, log_session_id: str):
        """Reconstruct a SessionLogger for a reconnecting session.

        The logger is only recreated when the directory already
        exists. A reconnecting session from a fresh install (or
        after the operator deleted ``logs/``) gets a new logger the
        normal way, not a dangling reference to a missing directory.
        """
        if not log_session_id:
            return None
        safe_id = _safe_log_id(log_session_id)
        if not safe_id:
            return None
        path = os.path.join(LOGS_DIR, safe_id)
        if not os.path.isdir(path):
            return None
        try:
            from .session_log import SessionLogger
            return SessionLogger(safe_id)
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Reconnect history (append-only log alongside the registry)

    RECONNECT_FILENAME = 'reconnects.json'

    def log_reconnect(self, previous_id, new_id, fingerprint: str,
                      addr) -> None:
        """Append a reconnect event to ``logs/reconnects.json``.

        The file is a JSON array of events. It is separate from the
        registry so it does not grow the primary file unboundedly.
        """
        try:
            path = os.path.join(LOGS_DIR, self.RECONNECT_FILENAME)
            events = []
            if os.path.isfile(path):
                try:
                    with open(path, 'r', encoding='utf-8') as fh:
                        data = json.load(fh)
                    if isinstance(data, list):
                        events = data
                except (OSError, ValueError):
                    events = []
            if isinstance(addr, (tuple, list)) and len(addr) >= 2:
                addr_str = f"{addr[0]}:{addr[1]}"
            else:
                addr_str = str(addr or '')
            events.append({
                'ts': time.time(),
                'previous_id': previous_id,
                'new_id': new_id,
                'fingerprint': fingerprint,
                'addr': addr_str,
            })
            
            if len(events) > 1000:
                events = events[-1000:]
            with self._lock:
                os.makedirs(LOGS_DIR, exist_ok=True)
                tmp = path + '.tmp'
                with open(tmp, 'w', encoding='utf-8') as fh:
                    json.dump(events, fh, indent=2, default=str)
                os.replace(tmp, path)
        except (OSError, ValueError, TypeError):
            pass

    # ------------------------------------------------------------------
    # Display

    def list_sessions(self, colors: Optional[dict] = None) -> None:
        """Print all tracked sessions."""
        c = colors or {}
        cyan = c.get('cyan', '')
        green = c.get('green', '')
        yellow = c.get('yellow', '')
        red = c.get('red', '')
        end = c.get('end', '')

        with self._lock:
            records = [dict(r) for r in self._records]

        print(f"\n{cyan}TRACKED SESSIONS | {len(records)} total{end}")
        if not records:
            print(f"{yellow}No sessions recorded{end}")
            return

        # Sort newest-seen first.
        records.sort(key=lambda r: r.get('last_seen', 0), reverse=True)
        for rec in records:
            state = (f"{red}disconnected{end}"
                     if rec.get('disconnected')
                     else f"{green}active{end}")
            sid = rec.get('session_id', '?')
            kind = rec.get('kind', 'shell')
            name = rec.get('name') or ''
            ident = rec.get('identity') or {}
            user = ident.get('username', '?')
            host = ident.get('hostname', '?')
            last = rec.get('last_seen', 0)
            age = int(time.time() - last) if last else 0
            print(f"  #{sid:<5} [{kind}] {user}@{host} "
                  f"state={state} last={age}s ago "
                  f"connects={rec.get('connect_count', 1)}"
                  + (f" name={name}" if name else ""))

    def list_reconnects(self, colors: Optional[dict] = None) -> None:
        """Print the reconnect history."""
        c = colors or {}
        cyan = c.get('cyan', '')
        yellow = c.get('yellow', '')
        end = c.get('end', '')

        path = os.path.join(LOGS_DIR, self.RECONNECT_FILENAME)
        events = []
        if os.path.isfile(path):
            try:
                with open(path, 'r', encoding='utf-8') as fh:
                    data = json.load(fh)
                if isinstance(data, list):
                    events = data
            except (OSError, ValueError):
                events = []

        print(f"\n{cyan}RECONNECTS | {len(events)} events{end}")
        if not events:
            print(f"{yellow}No reconnect events recorded{end}")
            return

        for ev in events[-50:]:
            ts = ev.get('ts', 0)
            when = time.strftime('%Y-%m-%d %H:%M:%S',
                                 time.localtime(ts))
            prev = ev.get('previous_id', '?')
            new = ev.get('new_id', '?')
            addr = ev.get('addr', '?')
            fp = (ev.get('fingerprint') or '?')[:16]
            print(f"  {when}  #{prev} -> #{new}  {addr}  fp={fp}…")