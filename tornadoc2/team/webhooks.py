"""Webhook registry and dispatcher.

Three backends: Slack incoming webhooks, Discord webhooks, and the
Telegram Bot API. Each has a different JSON body shape; the adapter
for each is a small function.

Dispatch is fire-and-forget on a worker thread so a slow or dead
endpoint never stalls an operator request. A queue caps in-flight
dispatches at 32; older events are dropped rather than queued
indefinitely.
"""

from __future__ import annotations

import ipaddress
import json
import os
import queue
import secrets
import socket
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse


_EVENT_KINDS = {
    'new-beacon', 'kill-deadline', 'schedule-complete',
    'beacon-identity-mismatch', 'beacon-signature-failure',
}

_VALID_SEVERITIES = frozenset(('info', 'warn', 'crit'))

_BLOCKED_METADATA_IPS = frozenset((
    '169.254.169.254',   # AWS, Azure, GCP, DigitalOcean
    '169.254.170.2',     # ECS task metadata
    '100.100.100.200',   # Alibaba
    'fd00:ec2::254',     # AWS IMDSv2 over IPv6
))

_BLOCKED_HOSTNAMES = frozenset((
    'localhost',
    'metadata',
    'metadata.google.internal',
))

def _check_ip(ip):
    """Return (ok, reason) for one ipaddress object."""
    s = str(ip)
    if s in _BLOCKED_METADATA_IPS:
        return False, 'cloud metadata service address'
    if ip.is_loopback:
        return False, 'loopback'
    if ip.is_link_local:
        return False, 'link-local'
    if ip.is_private:
        return False, 'private range'
    if ip.is_multicast:
        return False, 'multicast'
    if ip.is_reserved:
        return False, 'reserved range'
    if ip.is_unspecified:
        return False, 'unspecified address'
    if ip.version == 6:
        mapped = getattr(ip, 'ipv4_mapped', None)
        if mapped is not None:
            inner_ok, inner_why = _check_ip(mapped)
            if not inner_ok:
                return False, f'IPv4-mapped {inner_why}'
        if ip.is_site_local:
            return False, 'site-local'
    return True, None


def host_is_public(hostname):
    """Return (ok, reason) for a hostname about to be dialled.

    Resolves every address the name returns and refuses if any of
    them is non-public — a name that fans out to both a public A
    and a private A is treated as private, because the attacker
    only needs the private one to land.
    """
    if not hostname:
        return False, 'empty host'
    low = hostname.lower().strip('[]')
    if low in _BLOCKED_HOSTNAMES:
        return False, f'blocked hostname {hostname!r}'

    try:
        ip = ipaddress.ip_address(low)
    except ValueError:
        ip = None
    if ip is not None:
        return _check_ip(ip)

    try:
        infos = socket.getaddrinfo(hostname, None,
                                   proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return False, f'DNS resolution failed: {exc}'
    if not infos:
        return False, 'DNS returned no addresses'

    seen = set()
    for info in infos:
        addr = info[4][0].split('%', 1)[0]
        if addr in seen:
            continue
        seen.add(addr)
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False, f'unparseable address {addr!r}'
        ok, why = _check_ip(ip)
        if not ok:
            return False, f'{hostname} resolves to {addr}: {why}'
    return True, None


class WebhookStore:

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._q = queue.Queue(maxsize=32)
        self._stop = threading.Event()
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        self._worker = threading.Thread(
            target=self._dispatch_loop,
            name='webhook-dispatch', daemon=True)
        self._worker.start()

    # ------ CRUD ------

    def _load(self) -> list:
        try:
            with open(self.path, 'r', encoding='utf-8') as fh:
                d = json.load(fh)
            return d if isinstance(d, list) else []
        except (OSError, ValueError):
            return []

    def _save(self, lst: list) -> None:
        tmp = self.path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as fh:
            json.dump(lst, fh, indent=2)
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def list(self, requester=None, *, is_admin=False) -> list:
        """Return hooks visible to the caller.

        Admin (or a caller that passes requester=None) sees every
        hook. A non-admin sees only the hooks whose added_by
        matches requester. Used by the list endpoint so an
        operator's `webhooks list` shows what they own, and an
        admin's shows the whole registry.
        """
        with self._lock:
            rows = self._load()
        if is_admin or requester is None:
            return rows
        return [h for h in rows if h.get('added_by') == requester]

    def get(self, wid, requester=None, *, is_admin=False):
        """Return one hook by id, enforcing ownership.

        Returns None if not found. Raises PermissionError if the
        hook exists but belongs to another operator and the caller
        is not an admin.
        """
        with self._lock:
            for e in self._load():
                if e.get('id') != wid:
                    continue
                if not is_admin and requester is not None \
                        and e.get('added_by') != requester:
                    raise PermissionError(
                        'webhook belongs to another operator')
                return e
        return None

    def add(self, *, name, kind, url, events,
            chat_id='', min_severity='info',
            added_by) -> dict:
        if kind not in ('slack', 'discord', 'telegram'):
            raise ValueError(f'unsupported kind: {kind!r}')
        if not isinstance(url, str) or not url.startswith('https://'):
            raise ValueError('webhook url must be https://')
        if not isinstance(events, (list, tuple)) or not events:
            raise ValueError('events must be a non-empty list')
        for e in events:
            if e not in _EVENT_KINDS:
                raise ValueError(f'unknown event: {e!r}')
        if min_severity not in _VALID_SEVERITIES:
            raise ValueError(
                f'min_severity must be info, warn, or crit '
                f'(got {min_severity!r})')
        if kind == 'telegram' and not chat_id:
            raise ValueError('telegram hook requires chat_id')

        parsed = urlparse(url)
        ok, why = host_is_public(parsed.hostname or '')
        if not ok:
            raise ValueError(f'webhook host refused: {why}')

        entry = {
            'id': secrets.token_hex(4),
            'name': name or kind,
            'kind': kind,
            'url': url,
            'chat_id': chat_id,
            'events': list(events),
            'min_severity': min_severity,
            'added_by': added_by,
            'added_at': time.time(),
        }
        with self._lock:
            lst = self._load()
            lst.append(entry)
            self._save(lst)
        return entry

    def remove(self, wid: str,
               requester=None, *, is_admin=False) -> dict | None:
        """Delete a hook by id, enforcing ownership.

        Returns the removed entry, None if no such id exists, and
        raises PermissionError if the hook exists but belongs to
        another operator and the caller is not an admin.
        """
        with self._lock:
            lst = self._load()
            out = None
            new = []
            for e in lst:
                if e.get('id') == wid:
                    if not is_admin and requester is not None \
                            and e.get('added_by') != requester:
                        raise PermissionError(
                            'webhook belongs to another operator')
                    out = e
                else:
                    new.append(e)
            if out is not None:
                self._save(new)
        return out

    # ------ Dispatch ------

    def fire(self, event: str, payload: dict,
             severity: str = 'info') -> None:
        """Enqueue a notification. Never blocks, never raises."""
        if event not in _EVENT_KINDS:
            return
        with self._lock:
            hooks = [h for h in self._load()
                     if event in h.get('events', [])]
        if not hooks:
            return
        dropped = 0
        for h in hooks:
            if not _severity_ok(h.get('min_severity', 'info'),
                                severity):
                continue
            try:
                self._q.put_nowait((h, event, payload))
            except queue.Full:
                dropped += 1
        if dropped:
            try:
                print(f"[WEBHOOK] queue full, dropped {dropped} "
                      f"dispatch(es) for {event}", flush=True)
            except Exception:
                pass

    def _dispatch_loop(self) -> None:
        while not self._stop.is_set():
            try:
                h, event, payload = self._q.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                self._send(h, event, payload)
            except Exception:
                pass

    def send_to_hook(self, hook: dict, event: str,
                     payload: dict) -> None:
        """Dispatch to one specific hook, synchronously.

        Used by the webhooks test endpoint so it exercises the
        requested hook rather than every hook subscribed to the
        event. fire() remains the fan-out path used by real
        notifications.
        """
        try:
            self._send(hook, event, payload)
        except Exception:
            pass

    def _send(self, hook: dict, event: str,
              payload: dict) -> None:
        kind = hook.get('kind')
        url = hook.get('url', '')

        parsed = urlparse(url)
        if parsed.scheme != 'https':
            return
        ok, why = host_is_public(parsed.hostname or '')
        if not ok:
            try:
                print(f"[WEBHOOK] refused {hook.get('id', '?')} "
                      f"({url}): {why}", flush=True)
            except Exception:
                pass
            return

        text = _render_text(event, payload)
        if kind == 'slack':
            body = json.dumps({'text': text}).encode('utf-8')
        elif kind == 'discord':
            body = json.dumps({'content': text}).encode('utf-8')
        elif kind == 'telegram':
            body = json.dumps({
                'chat_id':    hook.get('chat_id', ''),
                'text':       _render_text_html(event, payload),
                'parse_mode': 'HTML',
                'disable_web_page_preview': True,
            }).encode('utf-8')
        else:
            return

        req = urllib.request.Request(
            url, data=body,
            headers={'Content-Type': 'application/json',
                     'User-Agent': 'TornadoC2-webhook/1.0'},
            method='POST')
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.status
                resp.read()
            if status >= 400:
                try:
                    print(f"[WEBHOOK] {hook.get('id', '?')} "
                          f"({kind}) HTTP {status}", flush=True)
                except Exception:
                    pass
        except urllib.error.HTTPError as exc:
            try:
                print(f"[WEBHOOK] {hook.get('id', '?')} "
                      f"({kind}) HTTP {exc.code}: {exc.reason}",
                      flush=True)
            except Exception:
                pass
        except (urllib.error.URLError, OSError) as exc:
            try:
                print(f"[WEBHOOK] {hook.get('id', '?')} "
                      f"({kind}) failed: {exc}", flush=True)
            except Exception:
                pass


def _severity_ok(threshold: str, severity: str) -> bool:
    order = {'info': 0, 'warn': 1, 'crit': 2}
    return order.get(severity, 0) >= order.get(threshold, 0)

def _html_escape(s: str) -> str:
    return (s.replace('&', '&amp;')
             .replace('<', '&lt;')
             .replace('>', '&gt;'))


def _render_text_html(event: str, payload: dict) -> str:
    """Telegram HTML-mode rendering. Same content as
    _render_text, but with the label wrapped in <b> and every
    payload-derived substring HTML-escaped. Any '<' a user or
    host puts into a payload is rendered literally instead of
    being parsed as a tag."""
    def g(key, default='?'):
        v = payload.get(key, default)
        return _html_escape('' if v is None else str(v))

    if event == 'new-beacon':
        return (f"<b>New beacon</b> #{g('id')} "
                f"{g('user')}@{g('host')} "
                f"({g('os')}/{g('arch')})")
    if event == 'kill-deadline':
        return (f"<b>Kill deadline</b> #{g('id')} "
                f"{g('host')} in {g('remaining_hours')}h")
    if event == 'schedule-complete':
        return (f"<b>Scheduled task</b> #{g('beacon')} "
                f"{g('verb')} run #{g('run')}")
    if event == 'beacon-identity-mismatch':
        return (f"<b>Identity mismatch</b> #{g('id')} "
                f"{g('host')} — presented key differs from "
                f"pinned key (attempts: {g('attempts', '1')})")
    if event == 'beacon-signature-failure':
        return (f"<b>Signature failure</b> #{g('id')} "
                f"task {g('task_id')} — rejected "
                f"{g('rejected_total', '1')} result(s) this "
                f"session")
    return (f"{_html_escape(event)}: "
            f"{_html_escape(json.dumps(payload))}")


def _render_text(event: str, payload: dict) -> str:
    if event == 'new-beacon':
        return (f"*New beacon* #{payload.get('id')} "
                f"{payload.get('user')}@{payload.get('host')} "
                f"({payload.get('os')}/{payload.get('arch')})")
    if event == 'kill-deadline':
        return (f"*Kill deadline* #{payload.get('id')} "
                f"{payload.get('host')} in "
                f"{payload.get('remaining_hours', '?')}h")
    if event == 'schedule-complete':
        return (f"*Scheduled task* "
                f"#{payload.get('beacon')} {payload.get('verb')} "
                f"run #{payload.get('run')}")
    if event == 'beacon-identity-mismatch':
        return (f"*Identity mismatch* #{payload.get('id')} "
                f"{payload.get('host')} — presented key differs "
                f"from pinned key (attempts: "
                f"{payload.get('attempts', 1)})")
    if event == 'beacon-signature-failure':
        return (f"*Signature failure* #{payload.get('id')} "
                f"task {payload.get('task_id')} — rejected "
                f"{payload.get('rejected_total', 1)} result(s) "
                f"this session")
    return f"{event}: {json.dumps(payload)}"