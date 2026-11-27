"""Bounded, thread-safe operator event ring.

The team server keeps request, auth, task, listener, build and operator
events in memory so the desktop can render them without the handler
printing every HTTP request to the CLI. Events carry no request bodies
and no credentials.

Readers see their own events plus pre-auth failures from their own
address unless they hold ``audit.read.all``. A monotonic sequence lets
a client resume after a disconnect without duplicates.
"""

from __future__ import annotations

import threading
import time
from collections import deque

CAPACITY = 2000
MAX_TEXT = 500
MAX_PATH = 300
MAX_UA = 160

LEVELS = frozenset({'info', 'warn', 'err'})
SOURCES = frozenset({
    'http', 'auth', 'task', 'listener', 'build', 'operator',
    'system',
})

# Never emit the poll itself; a 1s loop would otherwise flood the ring.
SKIP_PATHS = frozenset({'/api/v1/events'})


def _clip(value, limit):
    text = str(value or '')
    return text[:limit]


class Event:
    __slots__ = ('seq', 'ts', 'level', 'source', 'text', 'cn', 'ip',
                 'meta')

    def __init__(self, seq, level, source, text, cn='', ip='', meta=None):
        self.seq = seq
        self.ts = time.time()
        self.level = level
        self.source = source
        self.text = text
        self.cn = cn
        self.ip = ip
        self.meta = meta or {}

    def as_dict(self):
        return {
            'seq': self.seq,
            'ts': self.ts,
            'level': self.level,
            'source': self.source,
            'text': self.text,
            'meta': self.meta,
        }


class EventRing:
    def __init__(self, capacity: int = CAPACITY):
        self._items = deque(maxlen=max(1, capacity))
        self._cond = threading.Condition()
        self._seq = 0

    # ------------------------------------------------------------------
    # Write

    def emit(self, level: str, source: str, text: str,
             cn: str = '', ip: str = '', meta: dict | None = None):
        if level not in LEVELS:
            level = 'info'
        if source not in SOURCES:
            source = 'system'
        clean = ' '.join(_clip(text, MAX_TEXT).split())
        with self._cond:
            self._seq += 1
            event = Event(self._seq, level, source, clean,
                          _clip(cn, 120), _clip(ip, 64), meta)
            self._items.append(event)
            self._cond.notify_all()
        return event

    def record_http(self, method=None, path=None, status=0,
                    duration_ms=0, size=0, cn: str = '',
                    ip: str = '', ua: str = ''):
        """Store one completed request. Called from the WSGI handler.

        The handler passes a single dict; the positional form is kept
        for unit tests and in-process callers.
        """
        if isinstance(method, dict):
            rec = method
            method = rec.get('method', '')
            path = rec.get('path', '')
            status = rec.get('status', 0)
            duration_ms = rec.get('duration_ms', 0)
            size = rec.get('size', 0)
            cn = rec.get('cn', '')
            ip = rec.get('ip', '')
            ua = rec.get('ua', '')
        path = _clip(path, MAX_PATH)
        if path in SKIP_PATHS:
            return None
        try:
            code = int(status)
        except (TypeError, ValueError):
            code = 0
        level = 'err' if code >= 500 else 'warn' if code >= 400 else 'info'
        try:
            bytes_out = int(size)
        except (TypeError, ValueError):
            bytes_out = 0
        who = cn or ip or '-'
        text = (f'{_clip(method, 12)} {path} '
                f'{code or "-"} {duration_ms:.0f}ms {who}')
        return self.emit(level, 'http', text, cn=cn, ip=ip, meta={
            'method': _clip(method, 12),
            'path': path,
            'status': code,
            'ms': round(duration_ms, 1),
            'bytes': bytes_out,
            'ua': _clip(ua, MAX_UA),
        })

    # ------------------------------------------------------------------
    # Read

    def latest(self) -> int:
        with self._cond:
            return self._seq

    def wait(self, since: int, timeout: float) -> None:
        deadline = time.monotonic() + max(0.0, timeout)
        with self._cond:
            while self._seq <= since:
                left = deadline - time.monotonic()
                if left <= 0:
                    return
                self._cond.wait(left)

    def read(self, since: int = 0, limit: int = 200,
             cn: str = '', ip: str = '', all_scope: bool = False):
        limit = max(1, min(int(limit), 500))
        since = max(0, int(since))
        with self._cond:
            rows = []
            for event in self._items:
                if event.seq <= since:
                    continue
                if not all_scope and event.cn != cn:
                    if event.cn or event.ip != ip:
                        continue
                rows.append(event)
                if len(rows) >= limit:
                    break
            next_seq = self._seq if not rows else rows[-1].seq
            return [e.as_dict() for e in rows], next_seq

    def clear(self) -> None:
        with self._cond:
            self._items.clear()
            self._cond.notify_all()


RING = EventRing()
