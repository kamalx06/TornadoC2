"""Werkzeug request handler that suppresses client-disconnect noise.

A client that closes the connection before the server finishes
writing the response — Ctrl-C at the prompt, a short timeout, a
network drop — makes werkzeug's threaded HTTPS server print a full
traceback for what is, from the server's point of view, a completely
benign condition. Two exception shapes dominate:

  * ``BrokenPipeError`` on the response write
  * ``ssl.SSLError('UNEXPECTED_EOF_WHILE_READING')`` on the
    subsequent request-body drain

Neither is actionable. This module exposes a request handler that
swallows both and defers to werkzeug for anything else, so a real
server-side bug still gets logged.
"""

from __future__ import annotations

import ssl
import sys

try:
    from werkzeug.serving import WSGIRequestHandler
except ImportError:
    WSGIRequestHandler = None


if WSGIRequestHandler is not None:

    class QuietWSGIRequestHandler(WSGIRequestHandler):
        """Swallow client-disconnect exceptions during request
        processing. Everything else flows through to werkzeug's
        default logger."""

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
                print('-' * 40, file=sys.stderr)

else:
    QuietWSGIRequestHandler = None