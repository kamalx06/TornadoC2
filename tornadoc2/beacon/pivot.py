"""SOCKS5 pivoting for the beacon subsystem.

The beacon is pull-based, so an interactive SOCKS5 proxy cannot ride
inside the task queue. The approach:

  1. Operator runs ``socks start <local_port>`` in the beacon console.
  2. The server binds a SOCKS5 proxy on ``127.0.0.1:<local_port>``.
  3. Each SOCKS5 connection allocates a channel ID and queues a
     ``pivot_connect`` task to the beacon.
  4. The beacon dials the requested target, then dials back to the
     **pivot listener** with the channel ID and a 32-byte session
     token.
  5. The pivot listener matches the incoming beacon connection to
     the waiting SOCKS5 client and bridges bytes.

The beacon must be polling frequently enough to pick up the
``pivot_connect`` task before the SOCKS5 client times out. Set
``sleep 0`` in the beacon console before using the proxy.
"""

import secrets
import select
import socket
import struct
import threading
import time

from . import constants


class _PendingProxy:
    """One active SOCKS5 proxy bound to a beacon session."""

    def __init__(self, beacon_id, local_port, pivot_token):
        self.beacon_id = beacon_id
        self.local_port = local_port
        self.pivot_token = pivot_token
        self.listener = None
        self.running = False
        self.thread = None
        self.lock = threading.Lock()


class PivotManager:
    """Owns the pivot listener and every SOCKS5 proxy the operator
    has started across all beacon sessions.

    The manager is created once, at handler startup. It binds the
    pivot listener immediately (so the port is reserved before the
    first beacon checks in) and starts a background thread that
    accepts beacon dial-backs.
    """

    def __init__(self, engine, host, port, advertise_host=None):
        self.engine = engine
        self.host = host
        self.port = port
        self.advertise_host = advertise_host or host
        self._incoming = {}
        self._incoming_cv = threading.Condition()
        self._proxies = {}
        self._lock = threading.Lock()
        self._beacon_tokens = {}
        self._channel_counter = secrets.randbelow(0x7FFFFFFF) + 1
        self._channel_tokens: dict = {}
        self._conns_by_host: dict = {}
        self._listener = None
        self._accept_thread = None
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle

    def start(self):
        """Bind the pivot listener and start accepting."""
        if self._running:
            return True
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(128)
            s.settimeout(1.0)
        except OSError:
            return False
        self._listener = s
        self._running = True
        self._accept_thread = threading.Thread(
            target=self._accept_loop, daemon=True)
        self._accept_thread.start()
        return True

    def stop(self):
        self._running = False
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
        with self._lock:
            proxies = list(self._proxies.values())
        for p in proxies:
            self._teardown_proxy(p)

    # ------------------------------------------------------------------
    # Beacon dial-back

    _MAX_PIVOT_CONNS_PER_HOST = 32

    def _accept_loop(self):
        while self._running:
            try:
                conn, addr = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return

            source = addr[0] if addr else '?'
            with self._lock:
                n = self._conns_by_host.get(source, 0)
                if n >= self._MAX_PIVOT_CONNS_PER_HOST:
                    try:
                        conn.close()
                    except OSError:
                        pass
                    continue
                self._conns_by_host[source] = n + 1

            threading.Thread(
                target=self._handle_beacon_conn,
                args=(conn, source), daemon=True).start()

    def _reap_incoming(self, channel_id, conn):
        """Drop a leased socket from _incoming if nobody claimed it."""
        time.sleep(60)
        with self._incoming_cv:
            if self._incoming.get(channel_id) is conn:
                self._incoming.pop(channel_id, None)
                try:
                    conn.close()
                except OSError:
                    pass

    def _handle_beacon_conn(self, conn, source='?'):
        """Read the 36-byte handshake, publish the socket, and wait
        for a matching SOCKS5 client to pick it up."""

        try:
            self._handle_beacon_conn_inner(conn)
        finally:
            with self._lock:
                n = self._conns_by_host.get(source, 1) - 1
                if n <= 0:
                    self._conns_by_host.pop(source, None)
                else:
                    self._conns_by_host[source] = n

    def _handle_beacon_conn_inner(self, conn):
        header = b''
        deadline = time.time() + 10.0
        while len(header) < 36 and time.time() < deadline:
            try:
                chunk = conn.recv(36 - len(header))
            except OSError:
                conn.close()
                return
            if not chunk:
                conn.close()
                return
            header += chunk

        if len(header) != 36:
            conn.close()
            return

        channel_id = struct.unpack('>I', header[:4])[0]
        token = header[4:]

        with self._lock:
            expected = self._channel_tokens.get(channel_id)
        if expected is None:
            conn.close()
            return
        if not secrets.compare_digest(expected, token):
            conn.close()
            return

        with self._incoming_cv:
            self._incoming[channel_id] = conn
            self._incoming_cv.notify_all()

        threading.Thread(
            target=self._reap_incoming,
            args=(channel_id, conn), daemon=True).start()

    # ------------------------------------------------------------------
    # SOCKS5 proxy

    def start_proxy(self, beacon_id, local_port):
        """Bind a SOCKS5 listener on 127.0.0.1:<local_port> for the
        given beacon. Returns the proxy object, or None on error."""
        with self._lock:
            if beacon_id in self._proxies:
                return None
            proxy = _PendingProxy(
                beacon_id, local_port, secrets.token_bytes(32))
            self._proxies[beacon_id] = proxy

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind(('127.0.0.1', local_port))
        except OSError:
            with self._lock:
                self._proxies.pop(beacon_id, None)
            try:
                listener.close()
            except OSError:
                pass
            return None
        listener.listen(64)
        listener.settimeout(1.0)
        proxy.listener = listener
        proxy.running = True
        proxy.thread = threading.Thread(
            target=self._socks5_loop, args=(proxy,), daemon=True)
        proxy.thread.start()
        return proxy

    def stop_proxy(self, beacon_id):
        with self._lock:
            proxy = self._proxies.pop(beacon_id, None)
        if proxy is None:
            return False
        self._teardown_proxy(proxy)
        return True

    def _teardown_proxy(self, proxy):
        proxy.running = False
        if proxy.listener is not None:
            try:
                proxy.listener.close()
            except OSError:
                pass

    def list_proxies(self):
        with self._lock:
            return list(self._proxies.values())

    # ------------------------------------------------------------------
    # Client-tunnel bridge

    def _beacon_token(self, beacon_id):
        """Return (creating on first use) a 32-byte token for
        `beacon_id`. Used by the client-tunnel path, which does not
        have a _PendingProxy to hold a token."""
        with self._lock:
            tok = self._beacon_tokens.get(beacon_id)
            if tok is None:
                tok = secrets.token_bytes(32)
                self._beacon_tokens[beacon_id] = tok
            return tok

    def forget_beacon(self, beacon_id):
        """Drop per-beacon state for a session that has been
        forgotten. Called by the engine's forget path so the token
        map does not grow without bound over a long engagement
        with many short-lived beacons.

        Safe to call for a beacon_id that has no state; the pop is
        a no-op."""
        with self._lock:
            self._beacon_tokens.pop(beacon_id, None)

    def bridge_to_beacon(self, beacon_id, rhost, rport, client_sock):
        """Bridge a client socket that has already been framed by
        someone else (the client-tunnel listener) to a beacon
        dial-back on the pivot listener.

        Blocks until the pipe closes. Returns True on a successful
        bridge, False if the beacon never dialed back or the session
        is unknown.
        """
        if self.engine.get(beacon_id) is None:
            self._close(client_sock)
            return False

        token = self._beacon_token(beacon_id)

        with self._lock:
            channel_id = self._channel_counter
            self._channel_counter += 1
            if self._channel_counter > 0x7FFFFFFF:
                self._channel_counter = 1
            self._channel_tokens[channel_id] = token

        try:
            task_id = self.engine.enqueue(
                beacon_id, 'pivot_connect',
                [self.advertise_host, str(self.port),
                 str(channel_id), token.hex(),
                 rhost, str(rport)],
                timeout=30, track=False)
            if task_id is None:
                self._close(client_sock)
                return False

            deadline = time.time() + constants.PIVOT_CONNECT_TIMEOUT
            pivot_conn = None
            with self._incoming_cv:
                while time.time() < deadline:
                    if channel_id in self._incoming:
                        pivot_conn = self._incoming.pop(channel_id)
                        break
                    self._incoming_cv.wait(timeout=0.5)

            if pivot_conn is None:
                self._close(client_sock)
                return False
        finally:
            with self._lock:
                self._channel_tokens.pop(channel_id, None)

        self._bridge(client_sock, pivot_conn)
        return True

    @staticmethod
    def _close(sock):
        try:
            sock.close()
        except OSError:
            pass

    def _socks5_loop(self, proxy):
        while proxy.running:
            try:
                client, _ = proxy.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(
                target=self._handle_socks5_client,
                args=(proxy, client), daemon=True).start()

    def _handle_socks5_client(self, proxy, client):
        try:
            self._negotiate_socks5(proxy, client)
        except Exception:
            pass
        finally:
            try:
                client.close()
            except OSError:
                pass

    def _negotiate_socks5(self, proxy, client):
        # ---- Greeting: VER NMETHODS METHODS...
        hdr = self._recv_exact(client, 2)
        if hdr is None or hdr[0] != 5:
            return
        nmethods = hdr[1]
        methods = self._recv_exact(client, nmethods)
        if methods is None:
            return
        if 0x00 not in methods:
            client.sendall(b'\x05\xff')
            return
        client.sendall(b'\x05\x00')

        # ---- Request: VER CMD RSV ATYP DST.ADDR DST.PORT
        req = self._recv_exact(client, 4)
        if req is None or req[0] != 5:
            return
        cmd = req[1]
        atyp = req[3]
        if cmd != 0x01:   # CONNECT only
            client.sendall(
                b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
            return

        if atyp == 0x01:           # IPv4
            raw = self._recv_exact(client, 4)
            if raw is None:
                return
            rhost = socket.inet_ntoa(raw)
        elif atyp == 0x03:         # Domain name
            raw = self._recv_exact(client, 1)
            if raw is None:
                return
            dlen = raw[0]
            name = self._recv_exact(client, dlen)
            if name is None:
                return
            rhost = name.decode('ascii', 'replace')
        elif atyp == 0x04:         # IPv6
            raw = self._recv_exact(client, 16)
            if raw is None:
                return
            rhost = socket.inet_ntop(socket.AF_INET6, raw)
        else:
            return

        rport_raw = self._recv_exact(client, 2)
        if rport_raw is None:
            return
        rport = struct.unpack('>H', rport_raw)[0]

        # ---- Allocate a channel ID from the manager-global counter.
        with self._lock:
            channel_id = self._channel_counter
            self._channel_counter += 1
            if self._channel_counter > 0x7FFFFFFF:
                self._channel_counter = 1
            self._channel_tokens[channel_id] = proxy.pivot_token

        try:
            # ---- Queue the pivot_connect task.
            task_id = self.engine.enqueue(
                proxy.beacon_id,
                'pivot_connect',
                [self.advertise_host, str(self.port),
                 str(channel_id), proxy.pivot_token.hex(),
                 rhost, str(rport)],
                timeout=30,
                track=False,
            )
            if task_id is None:
                client.sendall(
                    b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
                return

            # ---- Wait for the beacon to dial back.
            deadline = time.time() + constants.PIVOT_CONNECT_TIMEOUT
            pivot_conn = None
            with self._incoming_cv:
                while time.time() < deadline:
                    if channel_id in self._incoming:
                        pivot_conn = self._incoming.pop(channel_id)
                        break
                    self._incoming_cv.wait(timeout=0.5)

            if pivot_conn is None:
                # REP=0x04 (host unreachable), ATYP=0x01 (IPv4),
                # BND.ADDR=0.0.0.0, BND.PORT=0. Ten bytes total.
                client.sendall(
                    b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
                return
        finally:
            with self._lock:
                self._channel_tokens.pop(channel_id, None)
                
        # ---- Success reply, then bridge.
        client.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        self._bridge(client, pivot_conn)

    @staticmethod
    def _recv_exact(sock, n):
        buf = b''
        while len(buf) < n:
            try:
                chunk = sock.recv(n - len(buf))
            except OSError:
                return None
            if not chunk:
                return None
            buf += chunk
        return buf

    @staticmethod
    def _bridge(a, b):
        """Relay bytes between two sockets until either closes."""
        sockets = [a, b]
        try:
            while True:
                try:
                    r, _, _ = select.select(sockets, [], [], 1.0)
                except (OSError, ValueError):
                    return
                for s in r:
                    try:
                        data = s.recv(65536)
                    except OSError:
                        return
                    if not data:
                        return
                    other = b if s is a else a
                    try:
                        other.sendall(data)
                    except OSError:
                        return
        finally:
            for s in (a, b):
                try:
                    s.close()
                except OSError:
                    pass