"""Client-side SOCKS5 proxy.

Runs a SOCKS5 listener on 127.0.0.1:<port> on the operator's own
machine. Each accepted connection is bridged to the team server's
client-tunnel port, which pairs it with a beacon dial-back. The
operator's tools (browser, curl, proxychains) connect to
127.0.0.1:<port> and see a normal SOCKS5 proxy — the target network
is reached through the beacon.

Supports CONNECT only (RFC 1928, plus the domain-name and IPv6 atyp
extensions). No authentication methods other than NO-AUTH.
"""

from __future__ import annotations

import os
import socket
import ssl
import struct
import tempfile
import threading


class SocksProxy:

    def __init__(self, host, port, cfg, beacon_id, tunnel_port):
        self.host = host
        self.port = port
        self.cfg = cfg
        self.beacon_id = beacon_id
        self.tunnel_port = tunnel_port
        self._sock = None
        self._thread = None
        self._running = False
        self._live = set()
        self._live_lock = threading.Lock()
        self._ctx = self._build_ctx()

    # ------------------------------------------------------------------

    def start(self):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(32)
        except OSError as exc:
            return False, str(exc)
        self._sock = srv
        self._running = True
        self._thread = threading.Thread(
            target=self._run, daemon=True)
        self._thread.start()
        return True, None

    def stop(self):
        self._running = False
        try:
            if self._sock:
                self._sock.close()
        except OSError:
            pass
        with self._live_lock:
            live = list(self._live)
            self._live.clear()
        for a, b in live:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    s.close()
                except Exception:
                    pass
        for path in getattr(self, '_staged_paths', []):
            try:
                os.remove(path)
            except OSError:
                pass
        self._staged_paths = []

    # ------------------------------------------------------------------

    def _build_ctx(self):
        cfg = self.cfg
        self._staged_paths = []
        try:
            ca = self._stage(cfg['ca_pem'])
            self._staged_paths.append(ca)
            cert = self._stage(cfg['client_cert'])
            self._staged_paths.append(cert)
            key = self._stage(cfg['client_key'])
            self._staged_paths.append(key)
        except Exception:
            for path in self._staged_paths:
                try:
                    os.remove(path)
                except OSError:
                    pass
            self._staged_paths = []
            raise
        try:
            ctx = ssl.create_default_context(cafile=ca)
            ctx.check_hostname = False
            ctx.load_cert_chain(cert, key)
        except Exception:
            for path in self._staged_paths:
                try:
                    os.remove(path)
                except OSError:
                    pass
            self._staged_paths = []
            raise
        return ctx

    @staticmethod
    def _stage(pem):
        fd, path = tempfile.mkstemp(prefix='tc_socks_', suffix='.pem')
        try:
            with os.fdopen(fd, 'w') as fh:
                fh.write(pem)
            os.chmod(path, 0o600)
        except Exception:
            try:
                os.remove(path)
            except OSError:
                pass
            raise
        return path

    # ------------------------------------------------------------------

    def _run(self):
        while self._running:
            try:
                conn, addr = self._sock.accept()
            except OSError:
                break
            threading.Thread(
                target=self._handle, args=(conn, addr),
                daemon=True).start()

    def _handle(self, client, addr):
        try:
            dst_host, dst_port = self._socks5_handshake(client)
        except Exception:
            try:
                client.close()
            except OSError:
                pass
            return

        try:
            server = self._open_tunnel(dst_host, dst_port)
        except Exception:
            try:
                client.sendall(
                    b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            except Exception:
                pass
            try:
                client.close()
            except OSError:
                pass
            return

        try:
            client.sendall(
                b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        except Exception:
            try:
                server.close()
            except Exception:
                pass
            try:
                client.close()
            except OSError:
                pass
            return

        pair = (client, server)
        with self._live_lock:
            self._live.add(pair)

        def pump(src, dst):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception:
                pass
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    s.close()
                except Exception:
                    pass
            with self._live_lock:
                self._live.discard(pair)

        t1 = threading.Thread(
            target=pump, args=(client, server), daemon=True)
        t2 = threading.Thread(
            target=pump, args=(server, client), daemon=True)
        t1.start()
        t2.start()

    # ------------------------------------------------------------------
    # SOCKS5

    @staticmethod
    def _recv_exact(sock, n):
        buf = b''
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError('eof')
            buf += chunk
        return buf

    def _socks5_handshake(self, sock):
        # ---- method selection
        hdr = self._recv_exact(sock, 2)
        if hdr[0] != 0x05:
            raise ValueError('not socks5')
        nmethods = hdr[1]
        methods = self._recv_exact(sock, nmethods)
        if 0x00 not in methods:
            sock.sendall(b'\x05\xff')
            raise ValueError('no acceptable auth')
        sock.sendall(b'\x05\x00')

        # ---- request
        hdr = self._recv_exact(sock, 4)
        if hdr[0] != 0x05:
            raise ValueError('not socks5')
        if hdr[1] != 0x01:  # CONNECT
            sock.sendall(
                b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
            raise ValueError('only CONNECT supported')
        atyp = hdr[3]
        if atyp == 0x01:      # IPv4
            raw = self._recv_exact(sock, 4)
            host = '.'.join(str(b) for b in raw)
        elif atyp == 0x03:    # domain
            ln = self._recv_exact(sock, 1)[0]
            host = self._recv_exact(sock, ln).decode('utf-8')
        elif atyp == 0x04:    # IPv6
            raw = self._recv_exact(sock, 16)
            groups = struct.unpack('>8H', raw)
            host = ':'.join(f'{g:x}' for g in groups)
        else:
            sock.sendall(
                b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
            raise ValueError('bad atyp')
        port = struct.unpack(
            '>H', self._recv_exact(sock, 2))[0]

        return host, port

    # ------------------------------------------------------------------
    # Tunnel

    def _open_tunnel(self, dst_host, dst_port):
        cfg = self.cfg
        raw = socket.create_connection(
            (cfg['server_host'], self.tunnel_port), timeout=30)
        tls = self._ctx.wrap_socket(
            raw, server_hostname=cfg['server_host'])
        host_bytes = dst_host.encode('utf-8')
        header = (
            b'TUN1'
            + struct.pack('>I', self.beacon_id)
            + struct.pack('>H', len(host_bytes))
            + host_bytes
            + struct.pack('>H', dst_port)
        )
        tls.sendall(header)
        # Wait for the tunnel listener's accept/reject byte.
        #
        #   0x00 = the listener accepted the request and is
        #          queueing the pivot_connect task. The beacon
        #          dial-back has NOT yet happened; a failure to
        #          establish the bridge surfaces as an EOF on the
        #          tunnel after the server's PIVOT_CONNECT_TIMEOUT.
        #          The operator's SOCKS5 layer is told success on
        #          receipt of this byte.
        #   0x01 = policy refusal (revoked, missing capability,
        #          slots exhausted, no pivot manager). The SOCKS5
        #          layer is told the connect failed.
        #
        # The distinction lets the operator tell "the server
        # refused this pivot" from "the server accepted but the
        # beacon never dialled back". Without it, both look like
        # an immediate EOF at the SOCKS5 layer.
        tls.settimeout(10.0)
        try:
            status = tls.recv(1)
        except OSError as exc:
            raise RuntimeError(
                f'tunnel accept read failed: {exc}') from exc
        finally:
            tls.settimeout(None)
        if status != b'\x00':
            raise RuntimeError(
                'tunnel listener refused the pivot request')
        return tls