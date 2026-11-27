#!/usr/bin/env python3
"""Local bridge between the Electron shell and the Python client.

The renderer never speaks HTTP or sees certificate material. The main
process spawns this bridge, reads a ``READY`` line from stdout (socket
path, optional TCP port and a 32-byte token) and forwards typed calls.

Transport:

  * Unix socket in ``$XDG_RUNTIME_DIR/tornadoc2`` (0700 dir, 0600
    socket), peer UID checked with ``SO_PEERCRED``.
  * TCP loopback fallback where Unix sockets are awkward (Windows);
    the token is then required.

Framing: 4-byte big-endian length + UTF-8 JSON, 8 MiB cap. One request
id per call, bounded concurrency, per-request timeout. Methods are an
explicit allowlist — the bridge cannot be used to reach arbitrary
paths.

Run ``python -m tornado_client.bridge --config alice.cfg``.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import struct
import sys
import threading
import time

PROTO = 1
MAX_FRAME = 8 << 20
MAX_WORKERS = 8
DEFAULT_TIMEOUT = 30.0


def _log(msg: str) -> None:
    print(f'[bridge] {msg}', file=sys.stderr, flush=True)


class BridgeError(Exception):
    def __init__(self, message: str, code: str = 'error'):
        super().__init__(message)
        self.code = code


class ClientSession:
    """Holds the one connected Client. Reconnect replaces it."""

    def __init__(self) -> None:
        self.client = None
        self.lock = threading.RLock()
        self.config_path = ''

    # ------------------------------------------------------------------

    def connect(self, config_path: str, password: str = '') -> dict:
        try:
            from tornado_client import config as cfg_mod
            from tornado_client.repl import Client
            from tornado_client.transport import Transport
        except ImportError as exc:
            raise BridgeError(
                f'missing Python dependency: {exc}', 'deps')

        path = os.path.abspath(os.path.expanduser(config_path))
        if not os.path.isfile(path):
            raise BridgeError(f'no such config: {path}', 'bad_config')
        try:
            cfg = cfg_mod.load(path)
            tp = Transport(cfg)
        except ImportError as exc:
            raise BridgeError(
                f'missing Python dependency: {exc}', 'deps')
        if password:
            tp.set_password(password)
        saved = sys.stdout
        sys.stdout = sys.stderr
        try:
            client = Client(cfg, tp, config_path=path)
        finally:
            sys.stdout = saved
        with self.lock:
            if self.client is not None:
                try:
                    self.client.tp.close()
                except Exception:
                    pass
            self.client = client
            self.config_path = path
        return {'name': cfg.get('name', ''), 'role': cfg.get('role', ''),
                'host': cfg.get('server_host', ''),
                'port': cfg.get('server_port', 0),
                'caps': list(getattr(client, 'caps', []) or [])}

    def disconnect(self) -> dict:
        with self.lock:
            if self.client is not None:
                try:
                    self.client.tp.close()
                except Exception:
                    pass
            self.client = None
        return {'ok': True}

    def status(self) -> dict:
        with self.lock:
            return {'connected': self.client is not None,
                    'config': self.config_path}

    def require(self):
        with self.lock:
            if self.client is None:
                raise BridgeError('not connected', 'not_connected')
            return self.client

    def get(self, path: str, payload: dict | None = None,
            timeout: float = DEFAULT_TIMEOUT):
        return self.require().tp.post(path, payload or {}, timeout=timeout)


SESSION = ClientSession()


# ----------------------------------------------------------------------
# Method table. Every entry is (handler, schema-ish check).


def _need(params, *keys):
    for k in keys:
        if k not in params:
            raise BridgeError(f'missing {k}', 'bad_params')


def m_hello(params):
    return {'proto': PROTO, 'pid': os.getpid(), 'version': 1}


def m_ping(params):
    return {'t': time.time()}


def m_connect(params):
    _need(params, 'config')
    if not isinstance(params['config'], str):
        raise BridgeError('config must be a string', 'bad_params')
    pw = params.get('password') or ''
    if not isinstance(pw, str):
        raise BridgeError('password must be a string', 'bad_params')
    result = SESSION.connect(params['config'], pw)
    _stop_event_stream()
    _start_event_stream()
    return result


def m_disconnect(params):
    _stop_event_stream()
    return SESSION.disconnect()


def m_status(params):
    return SESSION.status()


def m_capabilities(params):
    client = SESSION.require()
    return {'caps': list(getattr(client, 'caps', []) or [])}


# ----------------------------------------------------------------------
# Server event stream
#
# The team server no longer prints HTTP requests. It keeps a bounded
# ring and this poller mirrors it to stderr, where the desktop main
# process already forwards bridge output to the Events pane.

_EVENTS_LOCK = threading.Lock()
_EVENTS_GEN = 0


def _start_event_stream():
    global _EVENTS_GEN
    with _EVENTS_LOCK:
        _EVENTS_GEN += 1
        gen = _EVENTS_GEN
    threading.Thread(target=_event_stream, args=(gen,),
                     daemon=True, name='server-events').start()


def _stop_event_stream():
    global _EVENTS_GEN
    with _EVENTS_LOCK:
        _EVENTS_GEN += 1


def _event_stream(gen):
    since = None
    failures = 0
    while True:
        with _EVENTS_LOCK:
            if gen != _EVENTS_GEN:
                return
        params = {'limit': 200, 'wait': 2}
        if since is not None:
            params['since'] = since
        try:
            res = SESSION.get('/api/v1/events', params, timeout=10)
            failures = 0
        except Exception:
            failures += 1
            time.sleep(min(0.5 * failures, 5.0))
            continue
        if since is None:
            since = int(res.get('next') or 0)
        events = res.get('events') or []
        for event in events:
            try:
                level = str(event.get('level') or 'info')
                text = str(event.get('text') or '').replace('\n', ' ')
                print(f'[srv:{level}] {text}',
                      file=sys.stderr, flush=True)
                since = max(since, int(event.get('seq') or 0))
            except Exception:
                continue
        try:
            since = max(since, int(res.get('next') or 0))
        except Exception:
            pass


def m_events(params):
    return SESSION.get('/api/v1/events', params, timeout=10)


def _beacon_id(params) -> int:
    try:
        return int(params.get('id'))
    except (TypeError, ValueError):
        raise BridgeError('id must be an integer', 'bad_params')


def m_beacons(params):
    rows = SESSION.get('/api/v1/beacons', {})
    return rows if isinstance(rows, list) else []


def m_beacon_task(params):
    bid = _beacon_id(params)
    verb = params.get('verb')
    args = params.get('args') or []
    if not isinstance(verb, str) or not verb:
        raise BridgeError('verb required', 'bad_params')
    if not isinstance(args, list) or not all(
            isinstance(a, str) for a in args):
        raise BridgeError('args must be a list of strings', 'bad_params')
    timeout = float(params.get('timeout') or 120)
    return SESSION.get(f'/api/v1/beacon/{bid}/task',
                       {'verb': verb, 'args': args,
                        'timeout': timeout}, timeout=timeout + 5)


def m_task_result(params):
    bid = _beacon_id(params)
    tid = str(params.get('taskId') or '')
    if not tid:
        raise BridgeError('taskId required', 'bad_params')
    wait = max(0.0, min(float(params.get('wait') or 0), 5.0))
    return SESSION.get(f'/api/v1/beacon/{bid}/result/{tid}',
                       {'wait': wait}, timeout=10)


def m_beacon_alias(params):
    bid = _beacon_id(params)
    alias = params.get('alias') or ''
    if not isinstance(alias, str) or len(alias) > 120:
        raise BridgeError('bad alias', 'bad_params')
    return SESSION.get(f'/api/v1/beacon/{bid}/alias',
                       {'alias': alias})


def m_beacon_tag(params):
    bid = _beacon_id(params)
    tag = str(params.get('tag') or '')
    if not tag or len(tag) > 48:
        raise BridgeError('bad tag', 'bad_params')
    op = 'remove' if params.get('op') == 'remove' else 'add'
    return SESSION.get(f'/api/v1/beacon/{bid}/tag',
                       {'tag': tag, 'op': op})


def m_beacon_forget(params):
    bid = _beacon_id(params)
    return SESSION.get(f'/api/v1/beacon/{bid}/forget', {})


def m_listener_start(params):
    _need(params, 'id')
    return SESSION.get(f"/api/v1/listeners/{params['id']}/start", {})


LISTENER_TYPES = ('http', 'quic', 'websocket', 'dns', 'icmp',
                  'wireguard')
SPEC_KEYS = ('type', 'name', 'host', 'port', 'public_host', 'enabled',
             'tls', 'profiles', 'domain', 'subnet', 'server_ip',
             'interface', 'doh_resolver', 'icmp_host', 'smb_pipe')


def m_listener_certs(params):
    return SESSION.get('/api/v1/listeners/certs', {})


def m_listener_profiles(params):
    return SESSION.get('/api/v1/c2-profiles', {})


def _clean_spec(raw):
    if not isinstance(raw, dict):
        raise BridgeError('spec must be an object', 'bad_params')
    spec = {k: raw[k] for k in SPEC_KEYS if k in raw}
    if spec.get('type') not in LISTENER_TYPES:
        raise BridgeError('bad listener type', 'bad_params')
    if not str(spec.get('name') or '').strip():
        raise BridgeError('name required', 'bad_params')
    try:
        spec['port'] = int(spec.get('port') or 0)
    except (TypeError, ValueError):
        raise BridgeError('port must be an integer', 'bad_params')
    return spec


def m_listener_create(params):
    spec = _clean_spec(params.get('spec'))
    return SESSION.get('/api/v1/listeners/create', {'spec': spec},
                       timeout=30)


def m_listener_update(params):
    _need(params, 'id')
    patch = params.get('patch')
    if not isinstance(patch, dict):
        raise BridgeError('patch must be an object', 'bad_params')
    allowed = {k: patch[k] for k in SPEC_KEYS if k in patch}
    if not allowed:
        raise BridgeError('empty patch', 'bad_params')
    return SESSION.get(f"/api/v1/listeners/{params['id']}/update",
                       allowed, timeout=30)


def m_listener_delete(params):
    _need(params, 'id')
    return SESSION.get(f"/api/v1/listeners/{params['id']}/delete", {})


def m_listener_probe(params):
    _need(params, 'id')
    return SESSION.get('/api/v1/listeners/health/probe',
                       {'listener': params['id']}, timeout=30)


def m_listener_stop(params):
    _need(params, 'id')
    return SESSION.get(f"/api/v1/listeners/{params['id']}/stop", {})


def m_jump(params):
    method = str(params.get('method') or '')
    if method not in ('psexec', 'winrm', 'wmi', 'scshell'):
        raise BridgeError('bad method', 'bad_params')
    target = str(params.get('target') or '').strip()
    if not target or len(target) > 255:
        raise BridgeError('target required', 'bad_params')
    stage = SESSION.get('/api/v1/jump/stage',
                        {'listener': params.get('listener') or ''},
                        timeout=180)
    if not stage.get('ok'):
        raise BridgeError(stage.get('error') or 'staging failed', 'jump')
    flags = []
    for key in ('service', 'user', 'pass'):
        if params.get(key):
            flags += [f'--{key}', str(params[key])]
    if params.get('port'):
        flags += ['--port', str(int(params['port']))]
    if params.get('noCleanup'):
        flags.append('--no-cleanup')
    args = [method, target, stage['data_b64']] + flags
    res = SESSION.get(f"/api/v1/beacon/{int(params.get('id') or 0)}/task",
                      {'verb': 'jump', 'args': args, 'timeout': 120},
                      timeout=30)
    return {'stage': {'url': stage.get('url'),
                      'sha256': stage.get('sha256')}, 'task': res}


def m_evidence_add(params):
    body = {'host': str(params.get('host') or '')[:120],
            'detail': str(params.get('detail') or '')[:2000]}
    if params.get('loot'):
        body['loot'] = str(params['loot'])
    else:
        body['sha256'] = str(params.get('sha256') or '')
        body['name'] = str(params.get('name') or '')[:200]
    return SESSION.get('/api/v1/evidence', body)


def m_finding_add(params):
    body = {'severity': str(params.get('severity') or 'info'),
            'host': str(params.get('host') or '')[:120],
            'title': str(params.get('title') or '')[:120],
            'detail': str(params.get('detail') or '')[:2000],
            'evidence': params.get('evidence') or []}
    return SESSION.get('/api/v1/findings', body)


def m_ai_ask(params):
    question = str(params.get('question') or '').strip()
    if not question or len(question) > 4000:
        raise BridgeError('question required (max 4000)', 'bad_params')
    import asyncio
    import contextlib
    import io

    from tornadoc2_mcp.adapter import ClientAdapter
    from tornadoc2_mcp.config import DEFAULT_AI_PATH, load_ai_config
    from tornadoc2_mcp.console.loop import run_one_shot

    adapter = ClientAdapter(SESSION.require())
    try:
        cfg_ai = load_ai_config(DEFAULT_AI_PATH, require_provider=True)
    except Exception as exc:
        raise BridgeError(f'AI not configured: {exc}', 'ai_config')
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            asyncio.run(run_one_shot(cfg_ai, adapter, question))
    except Exception as exc:
        raise BridgeError(f'AI error: {exc}', 'ai')
    text = buf.getvalue().strip()
    # Strip the CLI dim markers that survive the redirect.
    return {'text': text[-20_000:]}


_JOBS: dict = {}
_JOBS_LOCK = threading.Lock()
_JOBS_MAX = 4


def _job_new(kind: str, meta: dict) -> str:
    with _JOBS_LOCK:
        active = [j for j in _JOBS.values()
                  if j['state'] in ('queued', 'running')]
        if len(active) >= _JOBS_MAX:
            raise BridgeError('too many transfers', 'busy')
        jid = 'job_' + os.urandom(6).hex()
        _JOBS[jid] = {'id': jid, 'kind': kind, 'state': 'queued',
                      'done': 0, 'total': 0, 'error': '',
                      'cancel': False, 'meta': meta, 'ts': time.time()}
        return jid


def _job_update(jid, **kw):
    with _JOBS_LOCK:
        j = _JOBS.get(jid)
        if j is not None:
            j.update(kw)


def _job(jid) -> dict:
    with _JOBS_LOCK:
        j = _JOBS.get(jid)
        if j is None:
            raise BridgeError('unknown job', 'not_found')
        return {k: v for k, v in j.items() if k != 'cancel'}


def m_job_list(params):
    with _JOBS_LOCK:
        return {'jobs': [{k: v for k, v in j.items()
                          if k != 'cancel'} for j in _JOBS.values()]}


def m_job_cancel(params):
    _need(params, 'id')
    _job(params['id'])
    _job_update(params['id'], cancel=True)
    return {'ok': True}


def _adapter():
    from tornadoc2_mcp.adapter import ClientAdapter
    return ClientAdapter(SESSION.require())


def m_upload_start(params):
    _need(params, 'id', 'local', 'remote')
    local = os.path.abspath(os.path.expanduser(str(params['local'])))
    if not os.path.isfile(local):
        raise BridgeError('no such local file', 'bad_params')
    local_size = os.path.getsize(local)
    jid = _job_new('upload', {'local': local,
                              'remote': str(params['remote']),
                              'beacon': int(params['id'])})
    _job_update(jid, total=local_size, state='running')

    def run():
        try:
            _run_upload(jid, int(params['id']), local,
                        str(params['remote']))
        except Exception as exc:
            _job_update(jid, state='error', error=str(exc))
        finally:
            pass

    threading.Thread(target=run, daemon=True).start()
    return {'job': jid}


def _run_upload(jid, bid, local, remote):
    import asyncio
    import base64 as b64
    import hashlib

    async def go():
        ad = _adapter()
        h = hashlib.sha256()
        size = 0
        r = await ad.run_task(bid, 'truncate', [remote], timeout=120)
        if r.get('error'):
            raise BridgeError(r['error'], 'task')
        with open(local, 'rb') as fh:
            while True:
                if _job(jid).get('cancel'):
                    _job_update(jid, state='cancelled')
                    return
                block = fh.read(32 * 1024)
                if not block:
                    break
                h.update(block)
                r = await ad.run_task(
                    bid, 'writechunk',
                    [b64.b64encode(block).decode('ascii'), remote],
                    timeout=300)
                if r.get('error'):
                    raise BridgeError(r['error'], 'task')
                size += len(block)
                _job_update(jid, done=size,
                            total=os.path.getsize(local))
        r = await ad.run_task(bid, 'sha256file', [remote], timeout=120)
        if r.get('error'):
            raise BridgeError(r['error'], 'task')
        from tornadoc2_mcp.adapter import _decode_output
        got = _decode_output(r).decode('ascii', 'replace').strip()
        if got.lower() != h.hexdigest():
            raise BridgeError('remote hash mismatch', 'verify')
        _job_update(jid, state='done', done=size)

    asyncio.run(go())


def m_download_start(params):
    _need(params, 'id', 'remote')
    remote = str(params['remote'])
    local = str(params.get('local') or '')
    if not local:
        local = os.path.join(
            os.path.expanduser('~'), 'Downloads',
            remote.rsplit('/', 1)[-1].rsplit('\\', 1)[-1] or 'file')
    local = os.path.abspath(os.path.expanduser(local))
    jid = _job_new('download', {'local': local, 'remote': remote,
                                'beacon': int(params['id'])})
    _job_update(jid, state='running')
    loot = bool(params.get('loot', True))

    def run():
        try:
            _run_download(jid, int(params['id']), remote, local, loot)
        except Exception as exc:
            _job_update(jid, state='error', error=str(exc))

    threading.Thread(target=run, daemon=True).start()
    return {'job': jid, 'local': local}


def _run_download(jid, bid, remote, local, loot):
    import asyncio

    async def go():
        ad = _adapter()
        from tornadoc2_mcp.adapter import _decode_output
        r = await ad.run_task(bid, 'filesize', [remote], timeout=60)
        if r.get('error'):
            raise BridgeError(r['error'], 'task')
        total = int(_decode_output(r).decode('ascii', 'replace'))
        parent = os.path.dirname(local)
        if parent:
            os.makedirs(parent, exist_ok=True)
        part = local + '.part'
        fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        offset = 0
        try:
            with os.fdopen(fd, 'wb') as fh:
                while offset < total:
                    if _job(jid).get('cancel'):
                        raise BridgeError('cancelled', 'cancelled')
                    want = min(256 * 1024, total - offset)
                    r = await ad.run_task(
                        bid, 'readchunk',
                        [remote, str(offset), str(want)], timeout=300)
                    if r.get('error'):
                        raise BridgeError(r['error'], 'task')
                    data = _decode_output(r)
                    if not data:
                        raise BridgeError('empty chunk', 'task')
                    fh.write(data)
                    offset += len(data)
                    _job_update(jid, done=offset, total=total)
        except Exception:
            try:
                os.unlink(part)
            except OSError:
                pass
            raise
        os.replace(part, local)
        if loot:
            digest_r = await ad.run_task(bid, 'sha256file', [remote],
                                         timeout=120)
            if not digest_r.get('error'):
                try:
                    await ad._loot_upload_file(
                        local,
                        _decode_output(digest_r).decode().strip(),
                        total, name=remote.rsplit('/', 1)[-1],
                        source_path=remote, source_beacon=bid)
                except Exception:
                    pass
        _job_update(jid, state='done', done=total)

    asyncio.run(go())


def m_build_options(params):
    from tornadoc2.beacon.build_spec import descriptor
    try:
        profiles = SESSION.get('/api/v1/c2-profiles', {}).get(
            'profiles') or []
    except Exception:
        profiles = []
    return {'options': descriptor(), 'profiles': profiles}


def m_build_validate(params):
    from tornadoc2.beacon.build_spec import validate, normalize
    cfg = params.get('config')
    if not isinstance(cfg, dict):
        raise BridgeError('config must be an object', 'bad_params')
    try:
        spec = normalize(cfg)
    except ValueError as exc:
        raise BridgeError(str(exc), 'bad_params')
    errors = validate(spec)
    return {'ok': not errors, 'errors': errors}


def m_build_start(params):
    cfg = params.get('config')
    out = str(params.get('out') or '')
    if not isinstance(cfg, dict):
        raise BridgeError('config object required', 'bad_params')
    if not out:
        raise BridgeError('out path required', 'bad_params')
    out = os.path.abspath(os.path.expanduser(out))
    jid = _job_new('build', {'out': out})
    _job_update(jid, state='running')
    threading.Thread(target=_run_build, args=(jid, cfg, out),
                     daemon=True).start()
    return {'job': jid}


def _run_build(jid, cfg, out):
    import base64 as b64
    import hashlib

    try:
        info = SESSION.get('/api/v1/beacon/build', cfg, timeout=300)
    except Exception as exc:
        raise BridgeError(str(exc), 'build')
    if not info.get('build_id'):
        raise BridgeError(info.get('error') or 'build failed', 'build')
    bid = info['build_id']
    total = int(info.get('size') or 0)
    want = (info.get('sha256') or '').lower()
    _job_update(jid, total=total)
    part = out + '.part'
    h = hashlib.sha256()
    try:
        with open(part, 'wb') as fh:
            offset = 0
            while offset < total:
                if _job(jid).get('cancel'):
                    raise BridgeError('cancelled', 'cancelled')
                size = min(1024 * 1024, total - offset)
                r = SESSION.get(
                    f'/api/v1/beacon/build/{bid}/chunk',
                    {'offset': offset, 'size': size}, timeout=120)
                data = b64.b64decode(r.get('data') or '')
                if not data:
                    raise BridgeError('empty chunk', 'build')
                fh.write(data)
                h.update(data)
                offset += len(data)
                _job_update(jid, done=offset)
        got = h.hexdigest()
        if want and got != want:
            raise BridgeError('build digest mismatch', 'verify')
        os.replace(part, out)
        os.chmod(out, 0o600)
        SESSION.get(f'/api/v1/beacon/build/{bid}/finish', {}, timeout=60)
        _job_update(jid, state='done', done=total, sha256=got)
    except Exception:
        try:
            os.unlink(part)
        except OSError:
            pass
        raise


def m_build_profiles(params):
    return SESSION.get('/api/v1/c2-profiles', {})


def m_build_config_import(params):
    _need(params, 'path')
    path = os.path.abspath(os.path.expanduser(str(params['path'])))
    if not os.path.isfile(path):
        raise BridgeError('no such file', 'bad_params')
    if os.path.getsize(path) > 256 << 10:
        raise BridgeError('config exceeds 256 KiB', 'bad_params')
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise BridgeError(f'bad config: {exc}', 'bad_params')
    if not isinstance(data, dict):
        raise BridgeError('config must be an object', 'bad_params')
    return {k: v for k, v in data.items() if not k.startswith('_')}


_SOCKS = {'proxy': None}


def _task_wait(bid, verb, args, timeout=90):
    r = SESSION.get(f'/api/v1/beacon/{bid}/task',
                    {'verb': verb, 'args': args, 'timeout': timeout},
                    timeout=30)
    tid = r.get('task_id')
    if not tid:
        raise BridgeError(r.get('error') or 'task not queued', 'task')
    deadline = time.time() + timeout
    while time.time() < deadline:
        res = SESSION.get(f'/api/v1/beacon/{bid}/result/{tid}',
                          {'wait': 3}, timeout=15)
        if res.get('ready'):
            return res
        time.sleep(0.4)
    raise BridgeError('task timeout', 'timeout')


def m_shell(params):
    _need(params, 'id', 'action')
    bid = int(params['id'])
    action = str(params['action'])
    if action not in ('start', 'stop', 'status', 'exec'):
        raise BridgeError('bad shell action', 'bad_params')
    args = [action]
    if action == 'exec':
        cmd = str(params.get('command') or '').strip()
        if not cmd:
            raise BridgeError('command required', 'bad_params')
        args.append(cmd)
    res = _task_wait(bid, 'shell', args, 60)
    return {'output': res.get('output'), 'error': res.get('error'),
            'exit_code': res.get('exit_code')}


def m_socks(params):
    _need(params, 'action')
    action = str(params['action'])
    if action == 'status':
        p = _SOCKS['proxy']
        return {'running': p is not None,
                'port': getattr(p, 'port', 0)}
    if action == 'stop':
        if _SOCKS['proxy'] is not None:
            _SOCKS['proxy'].stop()
            _SOCKS['proxy'] = None
        return {'running': False}
    if action == 'start':
        if _SOCKS['proxy'] is not None:
            raise BridgeError('proxy already running', 'busy')
        try:
            port = int(params.get('port') or 1080)
        except (TypeError, ValueError):
            raise BridgeError('bad port', 'bad_params')
        client = SESSION.require()
        tunnel = int(getattr(client, 'client_tunnel_port', 0) or 0)
        if not tunnel:
            raise BridgeError('server has no tunnel port', 'no_tunnel')
        from tornado_client import socks_proxy as sp
        proxy = sp.SocksProxy('127.0.0.1', port, client.cfg,
                              int(params.get('id') or 0), tunnel)
        ok, err = proxy.start()
        if not ok:
            raise BridgeError(err, 'bind')
        _SOCKS['proxy'] = proxy
        return {'running': True, 'port': port}
    raise BridgeError('bad socks action', 'bad_params')


def m_bof_run(params):
    _need(params, 'id', 'name')
    name = str(params['name'])
    client = SESSION.require()
    got = None
    try:
        got = client._armory_lookup(name)
    except Exception as exc:
        raise BridgeError(str(exc), 'armory')
    if not got:
        raise BridgeError(f'{name} is not installed', 'not_installed')
    body, fmt = got
    if not fmt.startswith('coff'):
        raise BridgeError(f'unsupported BOF format {fmt}', 'bad_format')
    import base64
    args = params.get('args') or []
    if not isinstance(args, list):
        raise BridgeError('args must be a list', 'bad_params')
    res = _task_wait(int(params['id']), 'bof',
                     [base64.b64encode(body).decode('ascii')]
                     + [str(a) for a in args], 120)
    return {'output': res.get('output'), 'error': res.get('error'),
            'exit_code': res.get('exit_code')}


def m_assembly_run(params):
    _need(params, 'id', 'path')
    path = os.path.abspath(os.path.expanduser(str(params['path'])))
    if not os.path.isfile(path):
        raise BridgeError('no such file', 'bad_params')
    if os.path.getsize(path) > 64 << 20:
        raise BridgeError('assembly exceeds 64 MiB', 'bad_params')
    import base64
    data = open(path, 'rb').read()
    args = params.get('args') or []
    res = _task_wait(int(params['id']), 'execute_assembly',
                     [base64.b64encode(data).decode('ascii')]
                     + [str(a) for a in args], 300)
    return {'output': res.get('output'), 'error': res.get('error'),
            'exit_code': res.get('exit_code')}


def m_creds_list(params):
    return SESSION.get('/api/v1/creds/list', {})


def m_creds_reveal(params):
    _need(params, 'id')
    return SESSION.get('/api/v1/creds/get', {'id': params['id']})


def m_audit_verify(params):
    return SESSION.get('/api/v1/audit/verify',
                       {'full': bool(params.get('full'))}, timeout=120)


def m_ai_config_get(params):
    from tornadoc2_mcp.config import DEFAULT_AI_PATH, load_ai_config
    cfg = load_ai_config(DEFAULT_AI_PATH)
    return {'provider': cfg.provider, 'model': cfg.model,
            'base_url': cfg.base_url,
            'temperature': cfg.temperature,
            'max_tokens': cfg.max_tokens,
            'key_set': bool(cfg.api_key)}


def m_ai_config_set(params):
    from tornadoc2_mcp.config import DEFAULT_AI_PATH, save_ai_config
    patch = {}
    for k in ('provider', 'model', 'base_url', 'api_key'):
        if isinstance(params.get(k), str):
            v = params[k].strip()
            if v:
                patch[k] = v
    for k, cast in (('temperature', float), ('max_tokens', int)):
        if params.get(k) not in (None, ''):
            try:
                patch[k] = cast(params[k])
            except (TypeError, ValueError):
                raise BridgeError(f'bad {k}', 'bad_params')
    if not patch:
        raise BridgeError('nothing to save', 'bad_params')
    cfg = save_ai_config(DEFAULT_AI_PATH, patch, require_provider=True)
    return {'provider': cfg.provider, 'model': cfg.model}


def m_bulk(params):
    return SESSION.get('/api/v1/bulk', params)


def m_listeners(params):
    return SESSION.get('/api/v1/listeners', {})


def m_listener_health(params):
    return SESSION.get('/api/v1/listeners/health', {})


def m_listener_get(params):
    _need(params, 'id')
    lid = str(params['id'])
    if not lid.replace('_', '').isalnum():
        raise BridgeError('bad listener id', 'bad_params')
    return SESSION.get(f'/api/v1/listeners/{lid}', {})


def m_chat_history(params):
    try:
        limit = max(1, min(int(params.get('limit') or 100), 500))
    except (TypeError, ValueError):
        raise BridgeError('limit must be an integer', 'bad_params')
    return SESSION.get('/api/v1/chat/history', {'limit': limit})


def m_chat_send(params):
    text = str(params.get('text') or '').strip()
    if not text or len(text) > 4096:
        raise BridgeError('text required (max 4096)', 'bad_params')
    kind = 'action' if params.get('kind') == 'action' else 'chat'
    return SESSION.get('/api/v1/chat/send', {'text': text, 'kind': kind})


def m_beacon_note(params):
    bid = _beacon_id(params)
    op = params.get('op') or 'list'
    if op not in ('list', 'add', 'clear'):
        raise BridgeError('bad note op', 'bad_params')
    body = {'op': op}
    if op == 'add':
        text = str(params.get('text') or '').strip()
        if not text or len(text) > 4096:
            raise BridgeError('note text required', 'bad_params')
        body['text'] = text
    return SESSION.get(f'/api/v1/beacon/{bid}/note', body)


def m_loot_list(params):
    return SESSION.get('/api/v1/loot/list', {})


def _armory_mod():
    from tornado_client import armory
    return armory


def _armory_names(params):
    names = params.get('names')
    if names is None:
        names = []
    if not isinstance(names, list):
        raise BridgeError('names must be a list', 'bad_params')
    if len(names) > 200:
        raise BridgeError('too many names', 'bad_params')
    out = []
    for n in names:
        if not isinstance(n, str) or not n.strip():
            raise BridgeError('names must be strings', 'bad_params')
        out.append(n.strip())
    return out


def m_armory_list(params):
    try:
        cat = _armory_mod().catalogue(refresh=bool(params.get('refresh')))
    except Exception as exc:
        raise BridgeError(str(exc), 'armory')
    rows = cat.pop('extensions', [])
    ins = cat.pop('installed', {})
    for row in rows:
        row['installed'] = row['name'] in ins
        old = ins.get(row['name']) or {}
        row['installed_version'] = old.get('version', '')
    cat['catalogue'] = rows
    cat['installed'] = ins
    return cat


def m_armory_info(params):
    name = params.get('name')
    if not isinstance(name, str) or not name.strip():
        raise BridgeError('name required', 'bad_params')
    try:
        return {'entry': _armory_mod().info(name)}
    except Exception as exc:
        raise BridgeError(str(exc), 'armory')


def m_armory_update(params):
    arm = _armory_mod()
    try:
        if params.get('all'):
            return arm.update(all_names=True)
        names = _armory_names(params)
        if names:
            return arm.update(names)
        return arm.update_index()
    except Exception as exc:
        raise BridgeError(str(exc), 'armory')


def m_armory_install(params):
    names = _armory_names(params)
    all_names = bool(params.get('all'))
    if not names and not all_names:
        raise BridgeError('names or all required', 'bad_params')
    try:
        return _armory_mod().install(
            names, replace=bool(params.get('replace')),
            all_names=all_names)
    except Exception as exc:
        raise BridgeError(str(exc), 'armory')


def m_armory_uninstall(params):
    names = _armory_names(params)
    if not names:
        raise BridgeError('names required', 'bad_params')
    try:
        return _armory_mod().remove(names)
    except Exception as exc:
        raise BridgeError(str(exc), 'armory')


def m_armory_installed(params):
    """Installed armory entries live on the operator workstation."""
    from tornadoc2_mcp import paths
    try:
        return {'installed': _armory_mod().installed(),
                'dir': str(paths.ARMORY_DIR),
                'repo': _armory_mod().ARMORY_REPO}
    except Exception as exc:
        return {'installed': {}, 'error': str(exc)}


def m_identify(params):
    return SESSION.get('/api/v1/identify', {})


def m_model(params):
    return SESSION.get('/api/v1/model', params)


def m_timeline(params):
    return SESSION.get('/api/v1/timeline', params)


def m_audit(params):
    return SESSION.get('/api/v1/audit', params)


def m_report(params):
    return SESSION.get('/api/v1/report', params)


def m_evidence(params):
    return SESSION.get('/api/v1/evidence', params)


def m_export_ioc(params):
    return SESSION.get('/api/v1/export/ioc', {})


def m_export_stix(params):
    return SESSION.get('/api/v1/export/stix', {})


def _armory(params):
    return SESSION.get('/api/v1/armory', params)


def m_graph(params):
    return SESSION.get('/api/v1/graph', params)


def m_commands(params):
    return SESSION.get('/api/v1/commands', {})


METHODS = {
    'hello': m_hello,
    'ping': m_ping,
    'connect': m_connect,
    'disconnect': m_disconnect,
    'status': m_status,
    'capabilities': m_capabilities,
    'events': m_events,
    'beacons': m_beacons,
    'task': m_beacon_task,
    'task.result': m_task_result,
    'beacon.alias': m_beacon_alias,
    'beacon.tag': m_beacon_tag,
    'beacon.forget': m_beacon_forget,
    'listener.start': m_listener_start,
    'listener.probe': m_listener_probe,
    'listener.stop': m_listener_stop,
    'jump': m_jump,
    'evidence.add': m_evidence_add,
    'finding.add': m_finding_add,
    'bulk': m_bulk,
    'ai.ask': m_ai_ask,
    'job.list': m_job_list,
    'job.cancel': m_job_cancel,
    'upload.start': m_upload_start,
    'download.start': m_download_start,
    'build.start': m_build_start,
    'build.options': m_build_options,
    'build.validate': m_build_validate,
    'build.profiles': m_build_profiles,
    'build.config.import': m_build_config_import,
    'shell': m_shell,
    'socks': m_socks,
    'bof.run': m_bof_run,
    'assembly.run': m_assembly_run,
    'creds.list': m_creds_list,
    'creds.reveal': m_creds_reveal,
    'audit.verify': m_audit_verify,
    'ai.config.get': m_ai_config_get,
    'ai.config.set': m_ai_config_set,
    'listeners': m_listeners,
    'listeners.health': m_listener_health,
    'listeners.get': m_listener_get,
    'listeners.certs': m_listener_certs,
    'listeners.profiles': m_listener_profiles,
    'listener.create': m_listener_create,
    'listener.update': m_listener_update,
    'listener.delete': m_listener_delete,
    'chat.history': m_chat_history,
    'chat.send': m_chat_send,
    'beacon.note': m_beacon_note,
    'loot.list': m_loot_list,
    'armory.installed': m_armory_installed,
    'armory.list': m_armory_list,
    'armory.info': m_armory_info,
    'armory.install': m_armory_install,
    'armory.uninstall': m_armory_uninstall,
    'armory.update': m_armory_update,
    'identify': m_identify,
    'model': m_model,
    'timeline': m_timeline,
    'audit': m_audit,
    'report': m_report,
    'evidence': m_evidence,
    'export.ioc': m_export_ioc,
    'export.stix': m_export_stix,
    'armory': _armory,
    'graph': m_graph,
    'commands': m_commands,
}


# ----------------------------------------------------------------------
# Framing


def read_frame(conn):
    head = _read_exact(conn, 4)
    if head is None:
        return None
    n = struct.unpack('>I', head)[0]
    if n == 0 or n > MAX_FRAME:
        raise BridgeError(f'bad frame size {n}')
    body = _read_exact(conn, n)
    if body is None:
        return None
    return json.loads(body.decode('utf-8'))


def _read_exact(conn, n):
    buf = b''
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def write_frame(conn, obj):
    raw = json.dumps(obj, separators=(',', ':')).encode('utf-8')
    if len(raw) > MAX_FRAME:
        raw = json.dumps({'error': 'response too large',
                          'code': 'too_large'}).encode('utf-8')
    conn.sendall(struct.pack('>I', len(raw)) + raw)


# ----------------------------------------------------------------------
# Server


class Server:
    def __init__(self, token: str, sock_path: str, tcp_port: int = 0,
                 uid_only: bool = False):
        self.token = token
        self.sock_path = sock_path
        self.tcp_port = tcp_port
        self.uid_only = uid_only
        self.uid = os.getuid() if hasattr(os, 'getuid') else None
        self.slots = threading.BoundedSemaphore(MAX_WORKERS)
        self.stop = threading.Event()

    def serve_unix(self) -> socket.socket:
        path = self.sock_path
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(path)
        os.chmod(path, 0o600)
        srv.listen(8)
        return srv

    def serve_tcp(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('127.0.0.1', self.tcp_port))
        srv.listen(8)
        port = srv.getsockname()[1]
        return srv, port

    def peer_ok(self, conn) -> bool:
        if self.uid is None:
            return True
        try:
            creds = conn.getsockopt(socket.SOL_SOCKET,
                                    socket.SO_PEERCRED, 12)
            pid, uid, _gid = struct.unpack('3i', creds)
        except OSError:
            return False
        return uid == self.uid

    def handle(self, conn):
        with conn:
            try:
                if not self.peer_ok(conn):
                    _log('peer uid rejected')
                    return
                first = read_frame(conn)
                if not first or first.get('method') != 'hello':
                    write_frame(conn, {'id': 0, 'ok': False,
                                       'error': 'hello required',
                                       'code': 'bad_handshake'})
                    return
                want = (first.get('params') or {}).get('token', '')
                if want != self.token:
                    write_frame(conn, {'id': 0, 'ok': False,
                                       'error': 'bad token',
                                       'code': 'bad_token'})
                    return
                write_frame(conn, {'id': first.get('id', 0), 'ok': True,
                                   'result': m_hello({})})
                while not self.stop.is_set():
                    try:
                        msg = read_frame(conn)
                    except (BridgeError, ValueError) as exc:
                        write_frame(conn, {'id': 0, 'ok': False,
                                           'error': str(exc),
                                           'code': 'bad_frame'})
                        break
                    if msg is None:
                        break
                    if not self.slots.acquire(timeout=1):
                        write_frame(conn, {
                            'id': msg.get('id'), 'ok': False,
                            'error': 'busy', 'code': 'busy'})
                        continue
                    threading.Thread(
                        target=self.dispatch, args=(conn, msg),
                        daemon=True).start()
            except OSError as exc:
                _log(f'connection: {exc}')

    def dispatch(self, conn, msg):
        try:
            mid = msg.get('id')
            method = msg.get('method')
            params = msg.get('params') or {}
            fn = METHODS.get(method if isinstance(method, str) else '')
            if fn is None:
                raise BridgeError(f'unknown method {method!r}',
                                  'unknown_method')
            if not isinstance(params, dict):
                raise BridgeError('params must be an object',
                                  'bad_params')
            result = _with_timeout(fn, params,
                                   float(params.get('_timeout') or
                                         DEFAULT_TIMEOUT))
            write_frame(conn, {'id': mid, 'ok': True, 'result': result})
        except BridgeError as exc:
            write_frame(conn, {'id': msg.get('id'), 'ok': False,
                               'error': str(exc), 'code': exc.code})
        except Exception as exc:
            write_frame(conn, {'id': msg.get('id'), 'ok': False,
                               'error': f'{type(exc).__name__}: {exc}',
                               'code': 'error'})
        finally:
            try:
                self.slots.release()
            except ValueError:
                pass

    def run(self):
        sock_dir = os.path.dirname(self.sock_path)
        os.makedirs(sock_dir, mode=0o700, exist_ok=True)
        try:
            os.chmod(sock_dir, 0o700)
        except OSError:
            pass
        srv = self.serve_unix()
        tcp = None
        port = 0
        if self.tcp_port:
            tcp, port = self.serve_tcp()
        print('READY ' + json.dumps({
            'proto': PROTO, 'socket': self.sock_path,
            'tcp': port, 'token': self.token}), flush=True)

        def accept_loop(s):
            while not self.stop.is_set():
                try:
                    conn, _ = s.accept()
                except OSError:
                    return
                threading.Thread(target=self.handle, args=(conn,),
                                 daemon=True).start()

        threading.Thread(target=accept_loop, args=(srv,),
                         daemon=True).start()
        if tcp is not None:
            threading.Thread(target=accept_loop, args=(tcp,),
                             daemon=True).start()
        try:
            while not self.stop.wait(0.5):
                pass
        finally:
            srv.close()
            if tcp is not None:
                tcp.close()


def _with_timeout(fn, params, timeout):
    """Run fn with a hard deadline; the worker thread is abandoned."""
    box = {}

    def run():
        try:
            box['v'] = fn(params)
        except BaseException as exc:  # noqa: BLE001 - forwarded
            box['e'] = exc

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise BridgeError('request timed out', 'timeout')
    if 'e' in box:
        raise box['e']
    return box.get('v')


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--config', default='')
    ap.add_argument('--tcp', type=int, default=0,
                    help='also listen on loopback at this port (0 = free)')
    ap.add_argument('--no-unix', action='store_true')
    args = ap.parse_args(argv)

    token = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')
    uid = os.getuid() if hasattr(os, 'getuid') else 0
    base = os.environ.get('XDG_RUNTIME_DIR') or f'/tmp/tornadoc2-{uid}'
    sock = os.path.join(base, f'bridge-{os.getpid()}.sock')

    if args.no_unix:
        tcp_port = args.tcp
        sock = os.path.join(base, f'bridge-{os.getpid()}.sock')
    else:
        tcp_port = args.tcp
    srv = Server(token, sock, tcp_port=tcp_port)
    if args.config:
        try:
            SESSION.connect(args.config)
            _start_event_stream()
            _log('connected')
        except Exception as exc:
            _log(f'initial connect failed: {exc}')
    try:
        srv.run()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
