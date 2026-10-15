"""Desktop notifications.

Tries one backend after another and silently does nothing if none
are available. The backend can be forced via TORNADO_NOTIFY:

    TORNADO_NOTIFY=off          disable entirely
    TORNADO_NOTIFY=auto         try all backends (default)
    TORNADO_NOTIFY=ntfy://topic  POST to https://ntfy.sh/<topic>
                                 (or NTFY_URL if set)
    TORNADO_NOTIFY=command:/path/to/script
                                run a shell command with two args
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading


def _run(argv):
    try:
        subprocess.run(argv, timeout=5,
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False)
        return True
    except Exception:
        return False


def _run_shell_words(words):
    """Split a command line into argv the way a shell would, then
    run it with the same 5-second cap as _run."""
    import shlex
    try:
        parts = shlex.split(words)
    except ValueError:
        return False
    if not parts:
        return False
    return _run(parts)


def _notify_send(title, body):
    if not shutil.which('notify-send'):
        return False
    return _run(['notify-send', '-u', 'normal',
                 '-a', 'TornadoC2', title, body])


def _terminal_notifier(title, body):
    if not shutil.which('terminal-notifier'):
        return False
    return _run(['terminal-notifier', '-title', title,
                 '-message', body])


def _as_str(s):
    """Escape a Python string for use as an AppleScript string
    literal. AppleScript's only in-string escape is backslash;
    double quotes and backslashes must be escaped, single quotes
    must not."""
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def _osascript(title, body):
    if sys.platform != 'darwin':
        return False
    if not shutil.which('osascript'):
        return False
    script = (f'display notification {_as_str(body)} '
              f'with title {_as_str(title)}')
    return _run(['osascript', '-e', script])


def _ntfy(title, body, url):
    try:
        import json
        import urllib.request
    except ImportError:
        return False
    try:
        payload = json.dumps({
            'title': title,
            'message': body,
        }).encode('utf-8')
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                'Content-Type': 'application/json; charset=utf-8',
            },
            method='POST')
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status < 400
    except Exception:
        return False


def send(title, body):
    """Fire a notification. Never raises."""
    backend = os.environ.get('TORNADO_NOTIFY', 'auto').strip()
    if backend == 'off':
        return
    if backend.startswith('ntfy://'):
        topic = backend[len('ntfy://'):].strip('/')
        if not topic:
            print('[notify] TORNADO_NOTIFY=ntfy:// has no topic',
                  file=sys.stderr)
            return
        base = os.environ.get('NTFY_URL', 'https://ntfy.sh')
        _ntfy(title, body, f'{base}/{topic}')
        return
    if backend.startswith('command:'):
        import shlex
        try:
            parts = shlex.split(backend[len('command:'):])
        except ValueError:
            return
        if not parts:
            return
        _run(parts + [title, body])
        return
    for fn in (_notify_send, _terminal_notifier, _osascript):
        try:
            if fn(title, body):
                return
        except Exception:
            continue