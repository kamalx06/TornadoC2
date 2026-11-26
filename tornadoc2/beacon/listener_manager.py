"""Listener manager.

Owns ``<repo>/listeners.json`` and the lifecycle of every
beacon-facing transport (HTTP, QUIC, WebSocket, DNS, ICMP,
WireGuard). One manager per handler instance.

Created by ``BeaconHandler.__init__``. Reconstituted by
``BeaconHandler.start()`` via ``load_from_store()`` +
``start_all_enabled()``. Mutated by the operator API through the
handler's ``listener_*`` pass-throughs.

The store is the single source of truth. Every mutation writes
atomically to disk. Status, ``started_at``, and ``error_message``
are runtime-only and never persisted — a listener that was
running when the server stopped comes back as ``status='stopped'``
on the next load, then transitions to ``'running'`` (or
``'error'``) via ``start_all_enabled()``.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import threading
import time

_LISTENER_TYPES = ('http', 'quic', 'websocket',
                   'dns', 'icmp', 'wireguard')

# Fields written to disk. Everything else is runtime-only and
# gets stripped by _persist_view before _save.
_PERSIST_KEYS = frozenset({
    'id', 'name', 'type', 'host', 'port', 'public_host',
    'enabled', 'tls', 'profiles', 'domain', 'subnet',
    'server_tunnel_ip', 'server_ip', 'interface',
    'created_by', 'created_at', 'updated_at',
})

_STORE_VERSION = 1


# ---------------------------------------------------------------------
# Exceptions

class ListenerError(Exception):
    """Base class for listener-manager errors."""


class ListenerNotFound(ListenerError):
    """The requested listener id does not exist."""


class ListenerConflict(ListenerError):
    """A name or port collision would be created."""


class ListenerInvalid(ListenerError):
    """The listener spec failed schema validation."""


class ListenerStateError(ListenerError):
    """The operation is not valid for the listener's state."""


class ListenerStartError(ListenerError):
    """The transport failed to start."""


# ---------------------------------------------------------------------
# Manager

class ListenerManager:
    """Owns listeners.json and drives the transport lifecycle."""

    def __init__(self, handler, engine=None, store_path=None):
        self.handler = handler
        self._engine = engine
        self._store_path = (
            store_path or self._default_store_path())
        self._lock = threading.RLock()
        self._listeners: dict = {}   # id -> config dict
        self._instances: dict = {}   # id -> running transport
        self._load_initial()
        if not os.path.exists(self._store_path):
            try:
                self._save()
            except OSError as exc:
                self._log(
                    f"cannot create {self._store_path}: {exc}",
                    level='warn')

    # ------------------------------------------------------------------
    # Paths

    @staticmethod
    def _default_store_path():
        """Repo-root listeners.json, beside logs/ and the cert roots.

        beacon/listener_manager.py -> ../../../listeners.json
        """
        here = os.path.dirname(os.path.abspath(__file__))
        repo = os.path.dirname(os.path.dirname(here))
        return os.path.join(repo, 'listeners.json')

    def store_path(self):
        return self._store_path

    # ------------------------------------------------------------------
    # Logging

    def _log(self, msg, level='info'):
        try:
            c = self.handler.colors
            key = {'info': 'cyan', 'warn': 'yellow',
                   'error': 'red'}.get(level, 'cyan')
            color = c.get(key, '')
            end = c.get('end', '')
            print(f"{color}[LISTENERS]{end} {msg}")
        except Exception:
            print(f"[LISTENERS] {msg}")

    # ------------------------------------------------------------------
    # Store I/O

    def _read_store(self):
        """Read listeners.json. Returns {id: cfg} or {} on any error.

        A missing file is a normal cold start. A malformed file is
        logged and treated as empty — the operator sees the
        warning and can inspect / fix the file, but a corrupted
        store does not stop the team server from booting.
        """
        path = self._store_path
        if not os.path.isfile(path):
            return {}
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                raw = json.load(fh)
        except (OSError, ValueError) as exc:
            self._log(
                f"cannot read {path}: {exc} -- starting empty",
                level='warn')
            return {}
        if not isinstance(raw, dict):
            self._log(
                f"{path} top level is not an object -- "
                f"starting empty", level='warn')
            return {}
        entries = raw.get('listeners') or []
        if not isinstance(entries, list):
            self._log(
                f"{path}: 'listeners' is not a list -- "
                f"starting empty", level='warn')
            return {}
        out = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            lid = entry.get('id')
            if not lid or not isinstance(lid, str):
                continue
            out[lid] = dict(entry)
        return out

    def _save(self):
        """Write the persisted view atomically.

        Writes to ``.tmp``, fsyncs, rotates the previous file to
        ``.bak``, then ``os.replace`` to swap. A crash mid-write
        leaves either the old file untouched or the new file
        complete -- never a partial file at the store path.
        """
        data = {
            'version': _STORE_VERSION,
            'listeners': [
                self._persist_view(c)
                for c in self._listeners.values()
            ],
        }
        body = json.dumps(data, indent=2, sort_keys=True)
        path = self._store_path
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        tmp = path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as fh:
            fh.write(body)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        if os.path.isfile(path):
            try:
                shutil.copy2(path, path + '.bak')
            except OSError:
                pass
        os.replace(tmp, path)

    def _persist_view(self, cfg):
        """Return the subset of a config that goes to disk."""
        return {k: cfg[k] for k in _PERSIST_KEYS if k in cfg}

    # ------------------------------------------------------------------
    # Load and reconcile

    def _load_initial(self):
        """Read the store once at construction. Does not start anything."""
        cfgs = self._read_store()
        for _lid, cfg in cfgs.items():
            cfg['status'] = 'stopped'
            cfg['started_at'] = None
            cfg['error_message'] = ''
        self._listeners = cfgs

    def load_from_store(self):
        """Re-read from disk. Called by BeaconHandler.start()."""
        self.reload()

    def reload(self):
        """Re-read the store and reconcile running instances.

        Configurations on disk replace in-memory configs. Running
        instances whose id is no longer on disk are stopped.
        Running instances whose config changed on disk keep
        running with the new config in memory -- the operator
        should stop and start to apply.
        """
        with self._lock:
            new_cfgs = self._read_store()
            for lid, cfg in new_cfgs.items():
                if lid in self._instances:
                    cfg['status'] = 'running'
                    cfg['started_at'] = (
                        self._listeners.get(lid, {})
                        .get('started_at'))
                    cfg['error_message'] = ''
                else:
                    cfg['status'] = 'stopped'
                    cfg['started_at'] = None
                    cfg['error_message'] = ''
            for lid in list(self._instances.keys()):
                if lid not in new_cfgs:
                    try:
                        self.stop(lid, by='reload')
                    except Exception:
                        pass
            self._listeners = new_cfgs

    def start_all_enabled(self):
        """Start every enabled listener. Called at boot.

        One listener failing does not prevent the others from
        starting. Each failure is logged; the failing listener's
        status is set to 'error' with a message that shows up in
        ``listeners list``.
        """
        with self._lock:
            lids = [
                lid for lid, c in self._listeners.items()
                if c.get('enabled') and lid not in self._instances
            ]
        for lid in lids:
            try:
                self.start(lid, by='boot')
            except Exception as exc:
                self._log(
                    f"start {lid} failed: {exc}", level='warn')

    def stop_all(self):
        """Stop every running listener. Called at shutdown."""
        with self._lock:
            lids = list(self._instances.keys())
        for lid in lids:
            try:
                self.stop(lid, by='shutdown')
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Query

    def list(self, type=None, running_only=False):
        """Return config dicts with runtime status attached.

        Sorted by created_at so the console and API render a
        stable order. ``type`` filters to a single transport type
        (used by the build wizard to find a matching listener).
        ``running_only`` filters to bound listeners (used by
        ``_beacon_build_default_url`` and the mTLS preflight).
        """
        with self._lock:
            out = []
            for lid, cfg in self._listeners.items():
                if type and cfg.get('type') != type:
                    continue
                if running_only and lid not in self._instances:
                    continue
                out.append(dict(cfg))
            out.sort(key=lambda c: c.get('created_at', 0))
            return out

    def get(self, listener_id):
        with self._lock:
            cfg = self._listeners.get(listener_id)
            return dict(cfg) if cfg is not None else None

    # ------------------------------------------------------------------
    # Mutations

    def _new_id(self):
        return 'lst_' + secrets.token_hex(4)

    def create(self, spec, by):
        """Validate, allocate an id, persist. Does not start.

        Refuses if the name collides with an existing listener,
        or if the spec is ``enabled: true`` and its port collides
        with a currently-running listener. The operator starts
        the listener explicitly (via ``listeners start <id>``)
        or on next boot (``start_all_enabled``).
        """
        with self._lock:
            clean = self._validate_spec(spec)
            for existing in self._listeners.values():
                if existing['name'] == clean['name']:
                    raise ListenerConflict(
                        f'a listener named {clean["name"]!r} '
                        f'already exists (id '
                        f'{existing.get("id", "?")})')
            lid = self._new_id()
            clean['id'] = lid
            if clean['type'] == 'wireguard' \
                    and not clean.get('interface'):
                clean['interface'] = f'tc2wg{lid[4:12]}'
            now = time.time()
            clean['created_by'] = by or ''
            clean['created_at'] = now
            clean['updated_at'] = now
            clean['status'] = 'stopped'
            clean['started_at'] = None
            clean['error_message'] = ''
            if clean['enabled']:
                conflict = self._find_running_conflict(
                    clean['type'], clean['port'],
                    exclude_id=None)
                if conflict is not None:
                    raise ListenerConflict(
                        f'port {clean["port"]} is already bound '
                        f'by running listener '
                        f'{conflict["id"]} '
                        f'({conflict["name"]}, '
                        f'{conflict["type"]}). Stop it first, '
                        f'or create with enabled=false.')
            self._listeners[lid] = clean
            try:
                self._save()
            except Exception:
                del self._listeners[lid]
                raise
            self._log(
                f"created {clean['name']} ({lid}, "
                f"{clean['type']} {clean['host']}:"
                f"{clean['port']}) by {by}")
            return dict(clean)

    def start(self, listener_id, by):
        """Construct the transport and bind. Idempotent on running."""
        with self._lock:
            cfg = self._listeners.get(listener_id)
            if cfg is None:
                raise ListenerNotFound(listener_id)
            if listener_id in self._instances:
                return dict(cfg)
            conflict = self._find_running_conflict(
                cfg['type'], cfg['port'],
                exclude_id=listener_id)
            if conflict is not None:
                raise ListenerConflict(
                    f'port {cfg["port"]} is already bound by '
                    f'listener {conflict["id"]} '
                    f'({conflict["name"]})')
            err = ''
            instance = None
            try:
                instance = self._construct_transport(cfg)
            except ListenerInvalid:
                raise
            except Exception as exc:
                cfg['status'] = 'error'
                cfg['started_at'] = None
                cfg['error_message'] = (
                    f'construct failed: {exc}')
                try:
                    self._save()
                except Exception:
                    pass
                raise ListenerStartError(str(exc)) from exc

            try:
                ok = instance.start()
            except Exception as exc:
                ok = False
                err = f'start raised: {exc}'
            else:
                if not ok:
                    err = (getattr(instance, '_last_error', '')
                           or 'start returned False')
            if not ok:
                cfg['status'] = 'error'
                cfg['started_at'] = None
                cfg['error_message'] = err
                try:
                    self._save()
                except Exception:
                    pass
                raise ListenerStartError(err)
            self._instances[listener_id] = instance
            cfg['status'] = 'running'
            cfg['started_at'] = time.time()
            cfg['error_message'] = ''
            try:
                self._save()
            except Exception:
                pass
            self._log(
                f"started {cfg['name']} ({listener_id}, "
                f"{cfg['type']} {cfg['host']}:{cfg['port']}) "
                f"by {by}")
            return dict(cfg)

    def stop(self, listener_id, by):
        """Close the transport and release the port."""
        with self._lock:
            cfg = self._listeners.get(listener_id)
            if cfg is None:
                raise ListenerNotFound(listener_id)
            instance = self._instances.pop(listener_id, None)
            if instance is None:
                cfg['status'] = 'stopped'
                cfg['started_at'] = None
                cfg['error_message'] = ''
                return dict(cfg)
            try:
                instance.stop()
            except Exception as exc:
                self._log(
                    f"stop {listener_id} raised: {exc}",
                    level='warn')
            cfg['status'] = 'stopped'
            cfg['started_at'] = None
            cfg['error_message'] = ''
            try:
                self._save()
            except Exception:
                pass
            self._log(
                f"stopped {cfg['name']} ({listener_id}) by {by}")
            return dict(cfg)

    def delete(self, listener_id, by):
        """Remove a listener. Refuses if it is running."""
        with self._lock:
            cfg = self._listeners.get(listener_id)
            if cfg is None:
                raise ListenerNotFound(listener_id)
            if listener_id in self._instances:
                raise ListenerStateError(
                    f'listener {listener_id} is running; '
                    f'stop it first')
            del self._listeners[listener_id]
            try:
                self._save()
            except Exception:
                self._listeners[listener_id] = cfg
                raise
            self._log(
                f"deleted {cfg['name']} ({listener_id}) by {by}")

    def update(self, listener_id, patch, by):
        """Apply a patch to a listener.

        Host and port changes are refused while running -- the
        operator must stop the listener first. All other fields
        can be changed live; the new values take effect on the
        next start (for transport-relevant fields) or immediately
        (for cosmetic fields like name, public_host, enabled).
        """
        with self._lock:
            cfg = self._listeners.get(listener_id)
            if cfg is None:
                raise ListenerNotFound(listener_id)
            if not isinstance(patch, dict):
                raise ListenerInvalid('patch must be an object')
            candidate = dict(cfg)
            for k, v in patch.items():
                if k in ('id', 'created_by', 'created_at'):
                    continue
                candidate[k] = v
            clean = self._validate_spec(candidate)
            clean['id'] = cfg['id']
            clean['created_by'] = cfg.get('created_by', '')
            clean['created_at'] = cfg.get('created_at', 0)
            clean['updated_at'] = time.time()
            for other_lid, other in self._listeners.items():
                if other_lid == listener_id:
                    continue
                if other['name'] == clean['name']:
                    raise ListenerConflict(
                        f'a listener named {clean["name"]!r} '
                        f'already exists ({other_lid})')
            if listener_id in self._instances:
                if (clean['host'] != cfg.get('host')
                        or int(clean['port'])
                        != int(cfg.get('port', 0))):
                    raise ListenerStateError(
                        'cannot change host or port on a '
                        'running listener; stop it first')
            clean['status'] = cfg.get('status', 'stopped')
            clean['started_at'] = cfg.get('started_at')
            clean['error_message'] = cfg.get('error_message', '')
            self._listeners[listener_id] = clean
            try:
                self._save()
            except Exception:
                self._listeners[listener_id] = cfg
                raise
            self._log(
                f"updated {clean['name']} ({listener_id}) "
                f"by {by}")
            return dict(clean)

    # ------------------------------------------------------------------
    # Validation

    @staticmethod
    def _tls_roots():
        """Absolute roots a listener TLS path may live under."""
        here = os.path.dirname(os.path.abspath(__file__))
        repo = os.path.dirname(os.path.dirname(here))
        return [
            os.path.realpath(os.path.join(repo, 'tls_certs')),
            os.path.realpath(os.path.join(repo, 'mtls_certs')),
        ]

    def _validate_spec(self, spec):
        """Validate and normalize a listener spec.

        Returns a clean dict with only the fields the manager
        knows about. Unknown fields in the spec are silently
        dropped so a stale client cannot inject state.
        """
        if not isinstance(spec, dict):
            raise ListenerInvalid('spec must be an object')

        ltype = (spec.get('type') or '').strip().lower()
        if ltype not in _LISTENER_TYPES:
            raise ListenerInvalid(
                f'type must be one of '
                f'{", ".join(_LISTENER_TYPES)} (got {ltype!r})')

        name = (spec.get('name') or '').strip()
        if not name:
            raise ListenerInvalid('name is required')
        if len(name) > 64:
            raise ListenerInvalid(
                'name is too long (max 64 chars)')
        for ch in name:
            if not (ch.isalnum() or ch in '._-'):
                raise ListenerInvalid(
                    f'name {name!r} contains {ch!r}; only '
                    f'letters, digits, ".", "_" and "-" allowed')

        host = (spec.get('host') or '0.0.0.0').strip()

        try:
            port = int(spec.get('port', 0))
        except (TypeError, ValueError):
            raise ListenerInvalid('port must be an integer')

        # ICMP has no port; allow port 0 as "not applicable".
        # WireGuard defaults to 51820 when the operator does not
        # specify -- the agent's --wireguard-server-addr must
        # match, so this is a hint, not a hard requirement.
        if ltype == 'icmp':
            if port < 0 or port > 65535:
                raise ListenerInvalid(
                    f'port out of range: {port}')
        elif ltype == 'wireguard':
            if port == 0:
                port = 51820
            if not (1 <= port <= 65535):
                raise ListenerInvalid(
                    f'port out of range: {port}')
        else:
            if not (1 <= port <= 65535):
                raise ListenerInvalid(
                    f'port must be 1-65535 (got {port})')

        public_host = (spec.get('public_host') or '').strip()
        enabled = bool(spec.get('enabled', True))

        clean = {
            'name':        name,
            'type':        ltype,
            'host':        host,
            'port':        port,
            'public_host': public_host,
            'enabled':     enabled,
        }

        # ---- HTTP / QUIC / WebSocket ----
        if ltype in ('http', 'quic', 'websocket'):
            tls = spec.get('tls') or {}
            if not isinstance(tls, dict):
                raise ListenerInvalid('tls must be an object')
            mode = (tls.get('mode') or 'server').strip().lower()
            if mode not in ('server', 'mtls', 'none'):
                raise ListenerInvalid(
                    f'tls.mode must be server, mtls, or none '
                    f'(got {mode!r})')
            tls_clean = {'mode': mode}
            for key in ('cert_path', 'key_path', 'ca_path'):
                val = (tls.get(key) or '').strip()
                if val:
                    rp = os.path.realpath(
                        os.path.expanduser(val))
                    if not os.path.isfile(rp):
                        raise ListenerInvalid(
                            f'tls.{key} does not exist on the '
                            f'server: {val!r}')
                    if not any(
                            rp == root or rp.startswith(
                                root + os.sep)
                            for root in self._tls_roots()):
                        raise ListenerInvalid(
                            f'tls.{key} must live under '
                            f'tls_certs/ or mtls_certs/ '
                            f'(got {val!r})')
                    tls_clean[key] = val
            if ltype in ('http', 'quic'):
                # Both are TLS-only on the wire. `none` and a
                # missing path mean "use the handler bootstrap
                # cert", so persist that explicitly rather than
                # leaving an empty block that fails at bind time.
                if mode == 'none':
                    mode = 'server'
                    tls_clean['mode'] = 'server'
                for key, attr in (
                        ('cert_path', 'certfile'),
                        ('key_path', 'keyfile')):
                    if tls_clean.get(key):
                        continue
                    default = getattr(self.handler, attr, None)
                    if default and os.path.isfile(
                            os.path.expanduser(default)):
                        tls_clean[key] = default
                if (mode == 'mtls'
                        and not tls_clean.get('ca_path')):
                    default_ca = getattr(
                        self.handler, 'mtls_ca_cert', None)
                    if default_ca and os.path.isfile(
                            os.path.expanduser(default_ca)):
                        tls_clean['ca_path'] = default_ca
            if mode != 'none':
                if not tls_clean.get('cert_path'):
                    raise ListenerInvalid(
                        'tls.cert_path is required '
                        '(or mode="none")')
                if not tls_clean.get('key_path'):
                    raise ListenerInvalid(
                        'tls.key_path is required '
                        '(or mode="none")')
            if mode == 'mtls' and not tls_clean.get('ca_path'):
                raise ListenerInvalid(
                    'tls.ca_path is required for mode="mtls"')
            clean['tls'] = tls_clean

            profiles = spec.get('profiles')
            if profiles is not None:
                if not isinstance(profiles, list):
                    raise ListenerInvalid(
                        'profiles must be a list or null')
                cleaned = []
                for p in profiles:
                    if not isinstance(p, str) or not p.strip():
                        continue
                    cleaned.append(p.strip())
                if cleaned:
                    clean['profiles'] = cleaned

        # ---- DNS / ICMP ----
        if ltype in ('dns', 'icmp'):
            profiles = spec.get('profiles')
            if profiles is not None:
                if not isinstance(profiles, list):
                    raise ListenerInvalid(
                        'profiles must be a list or null')
                cleaned = [p.strip() for p in profiles
                           if isinstance(p, str) and p.strip()]
                if cleaned:
                    clean['profiles'] = cleaned

        if ltype == 'dns':
            domain = (spec.get('domain') or '').strip()
            if not domain:
                raise ListenerInvalid(
                    'domain is required for dns listeners')
            clean['domain'] = domain

        # ---- WireGuard ----
        if ltype == 'wireguard':
            subnet = (spec.get('subnet')
                      or '10.99.0.0/24').strip()
            server_ip = ((spec.get('server_tunnel_ip')
                          or spec.get('server_ip')
                          or '10.99.0.1').strip())
            iface = (spec.get('interface') or '').strip()
            clean['subnet'] = subnet
            clean['server_tunnel_ip'] = server_ip
            clean['server_ip'] = server_ip
            if iface:
                if len(iface) > 15:
                    raise ListenerInvalid(
                        'wireguard interface name too long '
                        '(max 15 chars)')
                clean['interface'] = iface

        return clean

    # ------------------------------------------------------------------
    # Conflict detection

    @staticmethod
    def _proto_set(ltype):
        """Return the set of socket protocols a listener type binds."""
        if ltype == 'dns':
            return {'udp', 'tcp'}
        if ltype in ('quic', 'wireguard', 'icmp'):
            return {'udp'}
        return {'tcp'}

    def _find_running_conflict(self, ltype, port, exclude_id=None):
        """Return a running listener that conflicts with (ltype, port).

        Two listeners conflict when their port values match and
        their protocol sets overlap. DNS binds both UDP and TCP,
        so it conflicts with any other listener on the same port
        that touches either protocol.
        """
        mine = self._proto_set(ltype)
        with self._lock:
            for lid in self._instances.keys():
                if lid == exclude_id:
                    continue
                other = self._listeners.get(lid)
                if other is None:
                    continue
                if int(other.get('port', 0)) != int(port):
                    continue
                theirs = self._proto_set(other['type'])
                if mine & theirs:
                    return other
        return None

    # ------------------------------------------------------------------
    # Transport construction

    def _resolve_engine(self):
        if self._engine is not None:
            return self._engine
        eng = getattr(self.handler, 'beacon', None)
        if eng is None:
            raise ListenerStartError(
                'beacon engine not yet constructed')
        return eng

    def _construct_transport(self, cfg):
        """Instantiate the transport for a listener config.

        Lazy imports per type so a missing optional dependency
        (aioquic, dnslib, pyroute2) only fails when a listener
        of that type is actually started -- the other listeners
        keep working.
        """
        ltype = cfg['type']
        engine = self._resolve_engine()
        host = cfg.get('host', '0.0.0.0')
        port = int(cfg['port'])

        # For DNS/ICMP, pre-load the dns_label block from the
        # first profile in the list. This keeps the transport
        # independent of the builder.
        tcfg = dict(cfg)
        if ltype in ('dns', 'icmp'):
            profiles = cfg.get('profiles') or []
            if profiles:
                try:
                    from .builder import load_c2_profile
                    prof = load_c2_profile(profiles[0]) or {}
                    dl = prof.get('dns_label') or {}
                    if dl:
                        tcfg['dns_label'] = dl
                except Exception:
                    pass

        try:
            if ltype == 'http':
                from .listener import BeaconListener
                return BeaconListener(engine, config=tcfg)
            if ltype == 'quic':
                from .transport.quic import QUICListener
                return QUICListener(engine, config=tcfg)
            if ltype == 'websocket':
                from .transport.websocket import WebSocketListener
                return WebSocketListener(engine, config=tcfg)
            if ltype == 'dns':
                from .transport.dns import DNSTransport
                return DNSTransport(
                    engine, host, port, config=tcfg)
            if ltype == 'icmp':
                from .transport.icmp import ICMPTransport
                return ICMPTransport(
                    engine, host, port, config=tcfg)
            if ltype == 'wireguard':
                from .transport.wireguard import WireGuardTransport
                return WireGuardTransport(
                    engine, host, port, config=tcfg)
        except ImportError as exc:
            raise ListenerStartError(
                f'{ltype} transport unavailable: {exc}')

        raise ListenerInvalid(
            f'unknown listener type: {ltype!r}')