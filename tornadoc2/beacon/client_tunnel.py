"""Client tunnel listener.

Accepts connections from remote operator clients that run their own
SOCKS5 proxy locally. Each connection carries a header identifying
the target beacon and the ultimate destination. The server bridges
the connection to a beacon dial-back using the same slot mechanism
the server-side SOCKS listener already uses.

Wire layout:
  TLS handshake (mTLS with the team CA)
  header: [TUN1][beacon_id BE32][host_len BE16][host][port BE16]
  then raw duplex bytes

Port: beacon_port + 2. The client learns it from /api/v1/identify.
"""

from __future__ import annotations

import socket
import ssl
import struct
import threading


class ClientTunnelListener:

    def __init__(self, engine, host, port,
                 certfile, keyfile, client_ca,
                 registry):
        self.engine = engine
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.client_ca = client_ca
        self.registry = registry
        self._sock = None
        self._ctx = None
        self._thread = None
        self._running = False
        self.max_conns_per_operator = 8
        self._conns_lock = threading.Lock()
        self._active_conns: dict = {}   # cn -> count

    def _acquire_slot(self, cn: str) -> bool:
        with self._conns_lock:
            n = self._active_conns.get(cn, 0)
            if n >= self.max_conns_per_operator:
                return False
            self._active_conns[cn] = n + 1
            return True

    def _release_slot(self, cn: str) -> None:
        with self._conns_lock:
            n = self._active_conns.get(cn, 1) - 1
            if n <= 0:
                self._active_conns.pop(cn, None)
            else:
                self._active_conns[cn] = n

    def start(self) -> bool:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self.certfile, self.keyfile)
            if self.client_ca:
                ctx.verify_mode = ssl.CERT_REQUIRED
                ctx.check_hostname = False
                ctx.load_verify_locations(cafile=self.client_ca)

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

            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(32)
        except OSError:
            return False
        self._sock = srv
        self._ctx = ctx
        self._running = True
        self._thread = threading.Thread(
            target=self._run, daemon=True)
        self._thread.start()
        return True

    def stop(self):
        self._running = False
        try:
            if self._sock:
                self._sock.close()
        except OSError:
            pass

    # ------------------------------------------------------------------

    def _run(self):
        while self._running:
            try:
                conn, addr = self._sock.accept()
            except OSError:
                break

            threading.Thread(
                target=self._handshake_and_handle,
                args=(conn, addr), daemon=True).start()

    def _handshake_and_handle(self, conn, addr):
        try:
            tls = self._ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            try:
                conn.close()
            except OSError:
                pass
            return
        self._handle(tls, addr)

    def _handle(self, tls, addr):
        try:
            der = tls.getpeercert(binary_form=True)
        except Exception:
            der = None
        cn = None
        if der and self.registry is not None:
            try:
                cn = self.registry.verify_cert(der)
            except Exception:
                cn = None
        if not cn:
            try:
                tls.close()
            except OSError:
                pass
            return
        entry = None
        try:
            entry = self.registry.get(cn)
        except Exception:
            entry = None
        if not entry or entry.get('revoked'):
            try:
                tls.close()
            except OSError:
                pass
            return
        role = entry.get('role', 'viewer')
        from ..team import constants as team_constants
        if not team_constants.has_capability(
                role, 'beacon.socks', is_local=False):
            self._reject(tls)
            return

        if not self._acquire_slot(cn):
            self._reject(tls)
            return
        try:
            try:
                tls.settimeout(10.0)
            except Exception:
                pass

            try:
                if self._read_exact(tls, 4) != b'TUN1':
                    tls.close()
                    return
                beacon_id = struct.unpack(
                    '>I', self._read_exact(tls, 4))[0]
                host_len = struct.unpack(
                    '>H', self._read_exact(tls, 2))[0]
                if host_len > 1024:
                    tls.close()
                    return
                dst_host = self._read_exact(
                    tls, host_len).decode('utf-8')
                dst_port = struct.unpack(
                    '>H', self._read_exact(tls, 2))[0]
            except Exception:
                try:
                    tls.close()
                except OSError:
                    pass
                return

            pivot = getattr(self.engine, 'pivot', None)
            if pivot is None:
                self._reject(tls)
                return

            try:
                tls.sendall(b'\x00')
            except Exception:
                try:
                    tls.close()
                except OSError:
                    pass
                return

            try:
                tls.settimeout(None)
            except Exception:
                pass

            try:
                pivot.bridge_to_beacon(
                    beacon_id, dst_host, dst_port, tls)
            except AttributeError:
                import sys
                print('[TUNNEL] PivotManager has no '
                      'bridge_to_beacon method; see AI.md for the '
                      'shim', file=sys.stderr)
                try:
                    tls.close()
                except OSError:
                    pass
            except Exception as exc:
                import sys
                print(f'[TUNNEL] bridge failed for beacon '
                      f'#{beacon_id}: {exc}', file=sys.stderr)
                try:
                    tls.close()
                except OSError:
                    pass
        finally:
            self._release_slot(cn)

    @staticmethod
    def _read_exact(sock, n):
        buf = b''
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError('eof')
            buf += chunk
        return buf

    @staticmethod
    def _reject(tls):
        """Send the reject byte and close. The client-side proxy
        reads one byte after sending the header; the reject
        distinguishes a policy refusal (revoked, missing
        capability, slot exhausted) from a network failure."""
        try:
            tls.sendall(b'\x01')
        except Exception:
            pass
        try:
            tls.close()
        except OSError:
            pass