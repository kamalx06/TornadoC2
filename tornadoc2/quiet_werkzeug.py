"""Werkzeug request handler for the operator API.

Two jobs:

  * Suppress the noisy tracebacks caused by a client that closes the
    connection before the response is written. They are benign.
  * Route completed requests to a sink instead of printing them. The
    operator console stays quiet; the desktop renders the sink events
    in the Events pane.

A sink is ``callable(record)`` where record is a dict with method,
path, status, duration_ms, size, cn, ip and ua. Any sink failure is
swallowed: logging must never break a request.
"""

from __future__ import annotations

import ssl
import sys
import time

try:
    from werkzeug.serving import WSGIRequestHandler
except ImportError:
    WSGIRequestHandler = None


if WSGIRequestHandler is not None:

    class QuietWSGIRequestHandler(WSGIRequestHandler):
        """Base handler. ``log_sink`` is assigned by the factory."""

        log_sink = None

        def handle_one_request(self):
            self._t2_started = time.monotonic()
            super().handle_one_request()

        def log_request(self, code='-', size='-'):
            sink = getattr(self, 'log_sink', None)
            if sink is None:
                return
            started = getattr(self, '_t2_started', None)
            duration = ((time.monotonic() - started) * 1000
                        if started is not None else 0.0)
            path = str(getattr(self, 'path', '') or '').split('?', 1)[0]
            headers = getattr(self, 'headers', None)
            ua = ''
            if headers is not None:
                try:
                    ua = headers.get('User-Agent', '') or ''
                except Exception:
                    ua = ''
            try:
                sink({
                    'method': str(getattr(self, 'command', '') or ''),
                    'path': path,
                    'status': code,
                    'duration_ms': duration,
                    'size': size,
                    'cn': self._peer_cn(),
                    'ip': self.client_address[0]
                    if getattr(self, 'client_address', None) else '',
                    'ua': ua,
                })
            except Exception:
                pass

        def _peer_cn(self) -> str:
            try:
                cert = self.connection.getpeercert()
            except Exception:
                return ''
            if not cert:
                return ''
            for rdn in cert.get('subject', ()):  # type: ignore[union-attr]
                for key, value in rdn:
                    if key == 'commonName':
                        return str(value)[:120]
            return ''

        def handle_error(self):
            exc_type, exc_val, _ = sys.exc_info()

            if exc_type is None:
                return

            if issubclass(exc_type, (BrokenPipeError,
                                      ConnectionResetError)):
                return

            if issubclass(exc_type, ssl.SSLError):
                text = str(exc_val)
                if ('UNEXPECTED_EOF' in text
                        or 'EOF occurred' in text
                        or 'broken pipe' in text.lower()):
                    return

            try:
                super().handle_error()
            except AttributeError:
                import traceback
                print('-' * 40, file=sys.stderr)
                print('Exception during request processing',
                      file=sys.stderr)
                traceback.print_exc()


def make_request_handler(sink):
    """Return a request-handler class bound to ``sink``."""
    if WSGIRequestHandler is None:
        return None

    class _BoundHandler(QuietWSGIRequestHandler):
        log_sink = staticmethod(sink)

    return _BoundHandler
