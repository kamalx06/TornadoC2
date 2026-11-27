"""Listener reachability prober.

Runs on the team server and checks each running HTTP listener on a
schedule: TCP/TLS handshake, then a `GET /health`. Three consecutive
failures mark the listener `down`; a success returns it to `ok`.

State is in memory (the listener store is the source of truth for
configuration, not liveness) and is capped to the last 100 probes per
listener. Webhook event `listener-health` fires on a state change.
"""
from __future__ import annotations

import datetime
import os
import socket
import ssl
import threading
import time

STATES = ('unknown', 'ok', 'degraded', 'down')
FAIL_THRESHOLD = 3
HISTORY = 100


class HealthProber:
    def __init__(self, manager, fire=None, interval: float = 60.0,
                 timeout: float = 5.0):
        self._manager = manager          # callable -> manager or None
        self._fire = fire                # webhook dispatcher
        self._interval = max(5.0, interval)
        self._timeout = timeout
        self._lock = threading.RLock()
        self._state: dict = {}
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._loop, name='listener-health', daemon=True)

    # ------------------------------------------------------------------
    # Lifecycle

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._thread.join(timeout=5.0)
        except Exception:
            pass

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self.probe_all()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # State

    def _slot(self, lid: str) -> dict:
        return self._state.setdefault(lid, {
            'state': 'unknown', 'fails': 0, 'last_ok': 0.0,
            'last_error': '', 'probe_ms': 0, 'history': [],
        })

    def status(self, lid: str) -> dict:
        with self._lock:
            row = self._slot(lid)
            return {'state': row['state'],
                    'last_ok': row['last_ok'],
                    'last_error': row['last_error'],
                    'probe_ms': row['probe_ms'],
                    'history': list(row['history'][-20:])}

    def status_all(self) -> dict:
        with self._lock:
            return {lid: self.status(lid) for lid in self._state}

    def _set(self, lid, state, err='', ms=0) -> None:
        with self._lock:
            row = self._slot(lid)
            was = row['state']
            row.update(state=state, last_error=err, probe_ms=ms)
            if state == 'ok':
                row['last_ok'] = time.time()
            row['history'].append(
                {'ts': time.time(), 'state': state, 'error': err[:200],
                 'ms': ms})
            del row['history'][:-HISTORY]
        if was != state and self._fire is not None:
            try:
                self._fire('listener-health', {
                    'listener': lid, 'from': was, 'to': state,
                    'error': err[:200]})
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Probe

    def probe_all(self) -> None:
        mgr = self._manager()
        if mgr is None:
            return
        for cfg in mgr.list(running_only=True):
            if cfg.get('type') != 'http':
                continue
            self.probe(cfg)

    def probe(self, cfg) -> dict:
        lid = cfg.get('id', '')
        tls = cfg.get('tls') or {}
        host = cfg.get('public_host') or cfg.get('host') or '127.0.0.1'
        if host in ('0.0.0.0', '::', ''):
            host = '127.0.0.1'
        port = int(cfg.get('port') or 0)
        start = time.monotonic()
        err = ''
        ok = False
        try:
            ok, err = self._check(host, port, tls)
        except Exception as exc:
            err = f'{type(exc).__name__}: {exc}'
        ms = int((time.monotonic() - start) * 1000)

        with self._lock:
            row = self._slot(lid)
            if ok:
                row['fails'] = 0
                self._set(lid, 'ok', '', ms)
            else:
                row['fails'] += 1
                state = ('down' if row['fails'] >= FAIL_THRESHOLD
                         else 'degraded')
                self._set(lid, state, err, ms)
            return dict(self._slot(lid))

    def _check(self, host: str, port: int, tls: dict) -> tuple:
        if not port:
            return False, 'no port'
        raw = socket.create_connection((host, port), self._timeout)
        try:
            if tls.get('mode', 'server') == 'none':
                sock = raw
            else:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(raw, server_hostname=host)
            sock.settimeout(self._timeout)
            req = (f'GET /health HTTP/1.1\r\nHost: {host}\r\n'
                   f'Connection: close\r\n\r\n').encode()
            sock.sendall(req)
            buf = b''
            while len(buf) < 8192:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
            if b' 200 ' not in buf.split(b'\r\n', 1)[0]:
                head = buf.split(b'\r\n', 1)[0].decode(
                    'latin-1', 'replace')
                return False, f'health status: {head}'
            if b'"ok"' not in buf and b"'ok'" not in buf:
                return False, 'health body missing ok'
            return True, ''
        finally:
            try:
                raw.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Certificate

    @staticmethod
    def cert_days_left(cfg) -> int:
        """Days until the listener certificate expires, or -1."""
        path = (cfg.get('tls') or {}).get('cert_path')
        if not path or not os.path.isfile(path):
            return -1
        try:
            from cryptography import x509
            with open(path, 'rb') as fh:
                cert = x509.load_pem_x509_certificate(fh.read())
            delta = cert.not_valid_after_utc - \
                datetime.datetime.now(datetime.timezone.utc)
            return max(0, int(delta.total_seconds() // 86400))
        except Exception:
            return -1
