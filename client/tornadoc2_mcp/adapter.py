"""Client adapter.

The only file in the MCP package that touches
`tornado_client`. Every REST call goes through `_post`,
which wraps `client.tp.post()` — the same transport method
the REPL's `_cmd_*` handlers use. If the Client gains or
changes a transport method, only `_post` needs updating.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os

from .errors import (
    CapabilityError, NotFoundError, ServerError, TransportError,
)


class ClientAdapter:
    """Wraps a `tornado_client.repl.Client` for the MCP server
    and AI console.

    Every public method is async and runs the underlying
    `tp.post()` on a thread pool so the agent loop never
    blocks on a slow endpoint.
    """

    def __init__(self, client, *, timeout: float = 60.0):
        self._client = client
        self._timeout = timeout

        # Client exposes `.name`, `.role`, `.caps`. Older
        # drafts used `.identity` and `.capabilities`; support
        # both shapes without the adapter needing to know
        # which the caller supplies.
        ident = getattr(client, 'identity', None)
        if not isinstance(ident, dict) or not ident:
            ident = {
                'name': getattr(client, 'name', '?'),
                'role': getattr(client, 'role', '?'),
            }
        self.identity = ident

        caps = getattr(client, 'caps', None)
        if caps is None:
            caps = getattr(client, 'capabilities', None)
        self.capabilities = frozenset(caps or [])

    @property
    def current_beacon(self):
        """The beacon this REPL session is attached to, if any."""
        return getattr(self._client, 'current_beacon', None)

    # ---- The one and only bridge ------------------------------

    async def _post(self, path, body=None, timeout=None):
        """Run `client.tp.post(path, body, timeout=…)` on a
        worker thread. Returns the parsed JSON.

        Every method below is a thin wrapper around this.
        """
        to = timeout if timeout is not None else self._timeout
        body = body if body is not None else {}

        def _do():
            return self._client.tp.post(path, body, timeout=to)

        try:
            return await asyncio.wait_for(
                asyncio.to_thread(_do), timeout=to + 5.0)
        except asyncio.TimeoutError:
            raise TransportError(
                f'POST {path} timed out after {to}s')
        except RuntimeError as exc:
            raise _map_runtime(exc)
        except Exception as exc:
            raise TransportError(
                f'{type(exc).__name__}: {exc}')

    # ---- Beacons ----------------------------------------------

    async def list_beacons(self):
        return await self._post('/api/v1/beacons', {})

    async def beacon_info(self, bid):
        rows = await self._post('/api/v1/beacons', {})
        for b in rows or []:
            if b.get('id') == int(bid):
                return b
        raise NotFoundError(f'beacon #{bid} not in registry')

    async def queue_task(self, bid, verb, args, timeout=120):
        return await self._post(
            f'/api/v1/beacon/{int(bid)}/task',
            {'verb': verb, 'args': list(args),
             'timeout': int(timeout)},
            timeout=30.0)

    async def task_result(self, bid, tid, wait=0.0):
        if not tid:
            raise ServerError('task_result called without a task id')
        return await self._post(
            f'/api/v1/beacon/{int(bid)}/result/{tid}',
            {'wait': float(wait)},
            timeout=15.0)

    async def run_task(self, bid, verb, args=(), timeout=120,
                       *, grace=30.0):
        """Queue one task and block until its result is ready.

        Returns the result dict (with `output`, `error`, and
        `exit_code`). Servers that apply a verb locally may
        return `ready=True` straight from the enqueue call; that
        response is passed through unchanged.

        `grace` allows the result to arrive shortly after the
        server-side task timeout. The batch handler uses
        grace=0 so its deadline is exact.
        """
        info = await self.queue_task(
            bid, verb, list(args), timeout=timeout)
        audit_id = info.get('audit_id')
        if info.get('ready') or info.get('applied'):
            return _with_audit(info, audit_id)

        tid = info.get('task_id')
        if not tid:
            raise ServerError(
                f'{verb} on #{int(bid)}: server did not return '
                f'a task id',
                hint=f'server response: {info!r}')

        loop = asyncio.get_running_loop()
        deadline = loop.time() + float(timeout) + float(grace)
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise ServerError(
                    f'{verb} on #{int(bid)} timed out after '
                    f'{timeout}s (task {tid})')
            result = await self.task_result(
                bid, tid, wait=min(1.0, remaining))
            if result.get('ready'):
                return _with_audit(result, audit_id)
            await asyncio.sleep(min(0.2, max(0.0, remaining)))

    async def tasks(self, bid):
        r = await self._post(
            f'/api/v1/beacon/{int(bid)}/tasks', {})
        return list((r or {}).get('pending') or [])

    async def cancel(self, bid, tid):
        return await self._post(
            f'/api/v1/beacon/{int(bid)}/cancel/{tid}', {})

    async def killall(self, scope, **kw):
        payload = {'scope': scope, **kw}
        return await self._post(
            '/api/v1/beacon/kill', payload, timeout=30.0)

    async def beacon_dump(self, bid):
        return await self._post(
            f'/api/v1/beacon/{int(bid)}/dump', {})

    # ---- Metadata ---------------------------------------------

    async def audit(self, **filters):
        payload = {k: v for k, v in filters.items()
                   if v is not None}
        r = await self._post('/api/v1/audit', payload,
                             timeout=30.0)
        return list(r or [])

    async def alias(self, bid, alias):
        return await self._post(
            f'/api/v1/beacon/{int(bid)}/alias',
            {'alias': alias or ''})

    async def tag(self, bid, op, tag):
        return await self._post(
            f'/api/v1/beacon/{int(bid)}/tag',
            {'op': op, 'tag': tag})

    async def beacon_note(self, bid, op, text=''):
        payload = {'op': op}
        if text:
            payload['text'] = text
        return await self._post(
            f'/api/v1/beacon/{int(bid)}/note', payload)

    async def notes(self, op, text='', tags=None):
        payload = {'op': op}
        if text:
            payload['text'] = text
        if tags:
            payload['tags'] = list(tags)
        return await self._post('/api/v1/notes', payload)

    async def graph(self, mode, src=None, dst=None):
        payload = {'mode': mode}
        if src is not None:
            payload['src'] = int(src)
        if dst is not None:
            payload['dst'] = int(dst)
        r = await self._post('/api/v1/graph', payload)
        return (r or {}).get('text') or ''

    async def listeners(self):
        """No dedicated endpoint. Synthesise from the fields
        the Client cached at banner time."""
        return {
            'beacon_port':        getattr(self._client, 'beacon_port', None),
            'quic_port':          getattr(self._client, 'quic_port', None),
            'client_tunnel_port': getattr(self._client, 'client_tunnel_port', None),
        }

    async def commands(self, target_os=None):
        payload = {}
        if target_os:
            payload['target_os'] = target_os
        r = await self._post('/api/v1/commands', payload)
        return r or {'main': [], 'beacon': []}

    # ---- Chat -------------------------------------------------

    async def chat_send(self, text, kind='chat'):
        return await self._post(
            '/api/v1/chat/send',
            {'text': text, 'kind': kind})

    async def chat_history(self, limit=100, peer=None):
        payload = {'limit': int(limit)}
        if peer:
            payload['peer'] = peer
        r = await self._post('/api/v1/chat/history', payload)
        return list((r or {}).get('messages') or [])

    async def chat_who(self):
        r = await self._post('/api/v1/chat/who', {})
        return list((r or {}).get('operators') or [])

    # ---- Build / profiles / BOFs ------------------------------

    async def build(self, config):
        return await self._post(
            '/api/v1/beacon/build', config, timeout=300.0)

    async def build_chunk(self, bid, offset, size):
        import base64
        r = await self._post(
            f'/api/v1/beacon/build/{bid}/chunk',
            {'offset': int(offset), 'size': int(size)},
            timeout=60.0)
        try:
            return base64.b64decode((r or {}).get('data') or '')
        except Exception:
            raise ServerError(
                f'build chunk {bid}: bad base64')

    async def build_finish(self, bid):
        return await self._post(
            f'/api/v1/beacon/build/{bid}/finish', {})

    async def c2_profiles(self, name=None):
        payload = {}
        if name:
            payload['name'] = name
        return await self._post('/api/v1/c2-profiles', payload)

    async def bofs(self):
        r = await self._post('/api/v1/bofs', {})
        return list((r or {}).get('bofs') or [])

    async def bof_get(self, name):
        return await self._post(
            '/api/v1/bofs/get', {'name': name})

    async def bof_add(self, name, data_b64, **kw):
        payload = {'name': name, 'data_b64': data_b64}
        payload.update(kw)
        return await self._post('/api/v1/bofs/add', payload)

    async def bof_remove(self, name):
        return await self._post(
            '/api/v1/bofs/remove', {'name': name})

    # ---- File transfer / export ------------------------------

    def render_session_html(self, dump):
        """Render a `/dump` response with the Client's renderer.

        Returns None when the Client does not expose one, so the
        handler can fall back to writing the raw JSON dump.
        """
        if not isinstance(dump, dict) or 'session' not in dump:
            return None
        render = getattr(self._client, '_render_beacon_html', None)
        if render is None:
            render = getattr(
                self._client, 'render_session_html', None)
        if render is None:
            return None
        return render(
            dump.get('session') or {},
            dump.get('results') or [],
            dump.get('log'),
        )

    async def upload_file(self, bid, local_path, remote_path):
        """Chunked upload with remote SHA-256 verification."""
        size = os.path.getsize(local_path)
        digest = _sha256_file(local_path)

        r = await self.run_task(
            bid, 'truncate', [remote_path], timeout=120)
        _raise_task_error(r, 'truncate')

        with open(local_path, 'rb') as fh:
            while True:
                block = fh.read(32 * 1024)
                if not block:
                    break
                b64 = base64.b64encode(block).decode('ascii')
                r = await self.run_task(
                    bid, 'writechunk', [b64, remote_path],
                    timeout=300)
                _raise_task_error(r, 'writechunk')

        r = await self.run_task(
            bid, 'sha256file', [remote_path], timeout=120)
        _raise_task_error(r, 'sha256file')
        remote_hex = _decode_output(r).decode(
            'ascii', errors='replace').strip()
        if remote_hex.lower() != digest:
            raise ServerError(
                f'upload to #{int(bid)} failed hash verification '
                f'(local={digest[:16]}…, '
                f'remote={remote_hex[:16]}…)')
        return {
            'ok':       True,
            'path':     remote_path,
            'size':     size,
            'sha256':   digest,
            'audit_id': r.get('audit_id'),
        }

    async def download_to_loot(self, bid, remote_path, local_path,
                               *, display_name=None,
                               source_path=None):
        """Chunked download, local verification, loot upload."""
        r = await self.run_task(
            bid, 'filesize', [remote_path], timeout=60)
        _raise_task_error(r, 'filesize')
        try:
            total = int(_decode_output(r).decode(
                'ascii', errors='replace').strip())
        except (TypeError, ValueError):
            raise ServerError(
                f'could not parse remote size of {remote_path!r} '
                f'on #{int(bid)}')

        parent = os.path.dirname(os.path.abspath(local_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        part = local_path + '.part'
        sha = hashlib.sha256()
        offset = 0
        chunk = 256 * 1024
        try:
            with open(part, 'wb') as fh:
                while offset < total:
                    want = min(chunk, total - offset)
                    r = await self.run_task(
                        bid, 'readchunk',
                        [remote_path, str(offset), str(want)],
                        timeout=300)
                    _raise_task_error(
                        r, f'readchunk at {offset}')
                    data = _decode_output(r)
                    if not data and want:
                        raise ServerError(
                            f'readchunk at {offset} on '
                            f'#{int(bid)} returned no data')
                    fh.write(data)
                    sha.update(data)
                    offset += len(data)
        except Exception:
            try:
                os.unlink(part)
            except OSError:
                pass
            raise
        os.replace(part, local_path)

        digest = sha.hexdigest()
        name = display_name or _remote_basename(remote_path)
        loot = await self._loot_upload_file(
            local_path, digest, total,
            name=name,
            source_path=source_path or remote_path,
            source_beacon=int(bid),
        )
        return {
            'ok':       True,
            'path':     local_path,
            'size':     total,
            'sha256':   digest,
            'name':     name,
            'loot':     loot,
            'audit_id': (loot or {}).get('audit_id'),
        }

    async def _loot_upload_file(self, local_path, digest, size, *,
                                name, source_path, source_beacon):
        if size <= 16 * 1024 * 1024:
            with open(local_path, 'rb') as fh:
                data = fh.read()
            r = await self._post('/api/v1/loot/upload', {
                'sha256':        digest,
                'name':          name,
                'source_path':   source_path,
                'source_beacon': int(source_beacon),
                'data_b64':      base64.b64encode(data).decode('ascii'),
            }, timeout=600.0)
            if r.get('ok') is False:
                raise ServerError(
                    r.get('error') or 'loot upload refused')
            return r

        r = await self._post('/api/v1/loot/upload/init', {
            'sha256':        digest,
            'total_size':    int(size),
            'name':          name,
            'source_path':   source_path,
            'source_beacon': int(source_beacon),
        }, timeout=30.0)
        if r.get('ok') is False:
            raise ServerError(r.get('error') or 'loot upload refused')
        if r.get('deduped'):
            return r
        upload_id = r.get('upload_id')
        if not upload_id:
            raise ServerError(
                'loot upload init returned no upload_id')
        chunk_size = int(r.get('chunk_size') or 4 * 1024 * 1024)

        try:
            offset = 0
            with open(local_path, 'rb') as fh:
                while offset < size:
                    block = fh.read(chunk_size)
                    if not block:
                        break
                    cr = await self._post(
                        '/api/v1/loot/upload/chunk', {
                            'upload_id': upload_id,
                            'offset':    offset,
                            'data_b64':  base64.b64encode(
                                block).decode('ascii'),
                        }, timeout=300.0)
                    if cr.get('ok') is False:
                        raise ServerError(
                            cr.get('error') or 'loot chunk refused')
                    offset = int(cr.get('offset',
                                        offset + len(block)))
            fr = await self._post(
                '/api/v1/loot/upload/finish',
                {'upload_id': upload_id}, timeout=900.0)
            if fr.get('ok') is False:
                raise ServerError(
                    fr.get('error') or 'loot finish refused')
            return fr
        except Exception:
            try:
                await self._post('/api/v1/loot/upload/abort',
                                 {'upload_id': upload_id},
                                 timeout=10.0)
            except Exception:
                pass
            raise

    # ---- Vault / loot ----------------------------------------

    async def creds_list(self):
        r = await self._post('/api/v1/creds/list', {})
        return list((r or {}).get('creds') or [])

    async def creds_get(self, cid):
        return await self._post('/api/v1/creds/get', {'id': cid})

    async def creds_add(self, **kw):
        return await self._post('/api/v1/creds/add', kw)

    async def creds_validate(self, cid, from_beacon, target=None):
        cred_resp = await self._post('/api/v1/creds/get', {'id': cid})
        entry = (cred_resp or {}).get('cred') or {}
        kind = (entry.get('kind') or '').lower()
        user = entry.get('user') or ''
        domain = entry.get('domain') or ''
        value = entry.get('value') or ''
        args = [
            kind, user, domain,
            base64.b64encode(
                str(value).encode('utf-8')).decode('ascii'),
            target or '',
        ]
        valid_statuses = {
            'unvalidated', 'valid', 'invalid', 'locked',
            'expired', 'error', 'unsupported',
        }
        result = await self.run_task(
            int(from_beacon), 'cred_validate', args,
            timeout=120, grace=0)
        audit_id = result.get('audit_id')
        if result.get('error'):
            try:
                await self._post('/api/v1/creds/validate', {
                    'id':          cid,
                    'status':      'error',
                    'detail':      str(result['error'])[:512],
                    'from_beacon': int(from_beacon),
                })
            except Exception:
                pass
            return {
                'ok':       False,
                'error':    str(result['error']),
                'audit_id': audit_id,
            }
        try:
            text = _decode_output(result).decode(
                'utf-8', errors='replace').strip()
        except Exception:
            text = ''
        try:
            import json as _json
            parsed = _json.loads(text)
            status = str(
                parsed.get('status', 'error')).lower()
            detail = str(parsed.get('detail', ''))
        except Exception:
            status = 'error'
            detail = text or 'unparseable response from beacon'
        if status not in valid_statuses:
            status = 'error'
        r2 = await self._post('/api/v1/creds/validate', {
            'id':          cid,
            'status':      status,
            'detail':      detail[:512],
            'from_beacon': int(from_beacon),
        })
        return {
            'ok':       True,
            'status':   status,
            'detail':   detail,
            'cred':     (r2 or {}).get('cred'),
            'audit_id': (r2 or {}).get('audit_id', audit_id),
        }

    async def loot_list(self):
        r = await self._post('/api/v1/loot/list', {},
                             timeout=30.0)
        return list((r or {}).get('files') or [])

    async def loot_download(self, sha256):
        return await self._post(
            '/api/v1/loot/download', {'sha256': sha256},
            timeout=300.0)

    async def loot_delete(self, sha256):
        return await self._post(
            '/api/v1/loot/delete', {'sha256': sha256},
            timeout=30.0)


def _map_runtime(exc: RuntimeError):
    """Translate a `tp.post()` RuntimeError into the taxonomy."""
    msg = str(exc)
    code = None
    if msg.startswith('HTTP '):
        try:
            code = int(msg[5:].split(':', 1)[0])
        except (ValueError, IndexError):
            pass

    if code == 401:
        return TransportError(
            msg, hint='re-authenticate the operator .cfg')
    if code == 403:
        return CapabilityError(msg)
    if code in (404, 410):
        return NotFoundError(msg)
    if code == 429:
        return ServerError(
            msg, hint='server-side rate limit; wait and retry')
    if code == 413:
        return ServerError(
            msg, hint='the payload is too large for this '
                      'endpoint; reduce it or use the chunked path')
    if code is not None and 400 <= code < 600:
        return ServerError(msg)
    return TransportError(msg)


def _with_audit(result: dict, audit_id) -> dict:
    if audit_id and isinstance(result, dict) \
            and 'audit_id' not in result:
        result = dict(result)
        result['audit_id'] = audit_id
    return result


def _decode_output(result: dict) -> bytes:
    raw = (result or {}).get('output') or ''
    if not raw:
        return b''
    try:
        return base64.b64decode(raw)
    except Exception:
        raise ServerError('task result contained invalid base64')


def _raise_task_error(result: dict, what: str) -> None:
    if (result or {}).get('error'):
        raise ServerError(f'{what}: {result["error"]}')


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for block in iter(lambda: fh.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def _remote_basename(path: str) -> str:
    return os.path.basename(str(path).replace('\\', '/')) or 'download'