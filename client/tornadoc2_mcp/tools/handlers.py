"""Tool handlers.

Every handler has the signature:

    async def handler(ctx: ToolContext, args: dict) -> ToolResult

- ctx.client  is the ClientAdapter
- ctx.cfg     is the AiConfig
- args        is the validated argument dict

Handlers do not re-check capabilities, the allowlist, or
approval — the dispatcher already did. Handlers return a
ToolResult on success; on failure they raise from errors.py,
and the dispatcher wraps it.

The HANDLERS dict at the bottom must have one entry per tool
in schemas.TOOL_TABLE. tools/registry.py raises at import if
they disagree.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import struct

from .. import errors, logging
from ..dispatch import ToolContext, ToolResult


def _text_output(raw) -> str:
    """Decode a task result's base64 output into display text.

    The server always ships task output as base64. If a result
    ever carries plain text instead (older server, local verb),
    return it unchanged rather than failing the whole batch.
    """
    if raw is None:
        return ''
    if isinstance(raw, bytes):
        return raw.decode('utf-8', errors='replace')
    if not isinstance(raw, str):
        return str(raw)
    if not raw:
        return ''
    try:
        data = base64.b64decode(raw, validate=True)
    except Exception:
        return raw
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        return raw


def _pack_bof_args(args, fmt):
    """Pack BOF arguments with the registry's bof_pack format.

    Mirrors the REPL's `_pack_args_from_format`: this is wire
    data for the Windows loader, not a Client API.
    """
    if len(args) < len(fmt):
        raise ValueError(
            f'format needs {len(fmt)} args, got {len(args)}')
    out = bytearray()
    for ch, val in zip(fmt, args):
        if ch == 'z':
            body = val.encode('utf-8') + b'\x00'
            out += struct.pack('<I', len(body)) + body
        elif ch == 'Z':
            body = val.encode('utf-16-le') + b'\x00\x00'
            out += struct.pack('<I', len(body)) + body
        elif ch == 'i':
            out += struct.pack('<i', int(val))
        elif ch == 's':
            out += struct.pack('<h', int(val))
        elif ch == 'b':
            raw = base64.b64decode(val)
            out += struct.pack('<I', len(raw)) + raw
        else:
            raise ValueError(f'unsupported format char: {ch!r}')
    return bytes(out)


def _pack_bof_args_default(args):
    """Fallback packing when the BOF has no format string."""
    body = ' '.join(args).encode('utf-8') + b'\x00'
    return struct.pack('<I', len(body)) + body


# ---- T1 --------------------------------------------------------------

async def _list_beacons(ctx, args):
    rows = await ctx.client.list_beacons()
    return ToolResult(data={'beacons': rows})


async def _beacon_info(ctx, args):
    bid = int(args['id'])
    info, pending = await _gather(
        ctx.client.beacon_info(bid),
        ctx.client.tasks(bid),
    )
    return ToolResult(data={'info': info, 'pending': pending})


async def _beacon_result(ctx, args):
    bid = int(args['id'])
    tid = str(args['task_id'])
    wait = float(args.get('wait', 0.0))
    result = await ctx.client.task_result(bid, tid, wait)
    return ToolResult(data=result)


async def _beacon_tasks(ctx, args):
    bid = int(args['id'])
    rows = await ctx.client.tasks(bid)
    return ToolResult(data={'pending': rows})


async def _list_listeners(ctx, args):
    rows = await ctx.client.listeners()
    return ToolResult(data={'listeners': rows})


async def _list_profiles(ctx, args):
    name = args.get('name')
    if name:
        data = await ctx.client.c2_profiles(name)
        return ToolResult(
            data={'profile': data.get('profile') or data},
            audit_id=(data or {}).get('audit_id'))
    data = await ctx.client.c2_profiles()
    if isinstance(data, dict):
        rows = data.get('profiles') or []
        audit_id = data.get('audit_id')
    else:
        rows = data or []
        audit_id = None
    return ToolResult(data={'profiles': rows}, audit_id=audit_id)


async def _list_bofs(ctx, args):
    rows = await ctx.client.bofs()
    return ToolResult(data={'bofs': rows})


async def _list_loot(ctx, args):
    rows = await ctx.client.loot_list()
    return ToolResult(data={'files': rows})


async def _list_creds(ctx, args):
    rows = await ctx.client.creds_list()
    # Redact — the model must not see values it has not
    # explicitly revealed via creds_reveal.
    safe = []
    for r in rows:
        r = dict(r)
        r.pop('value', None)
        safe.append(r)
    return ToolResult(data={'creds': safe})


async def _list_notes(ctx, args):
    scope = args.get('scope', 'engagement')
    if scope == 'beacon':
        bid = int(args['beacon_id'])
        data = await ctx.client.beacon_note(bid, 'list')
    else:
        data = await ctx.client.notes('list')
    return ToolResult(data=data)


async def _audit_tail(ctx, args):
    data = await ctx.client.audit(
        limit=int(args.get('limit', 100)),
        operator=args.get('operator'),
        action=args.get('action'),
        beacon=args.get('beacon'),
        denied_only=bool(args.get('denied_only', False)),
    )
    return ToolResult(data={'entries': data})


async def _chat_history(ctx, args):
    rows = await ctx.client.chat_history(
        limit=int(args.get('limit', 100)),
        peer=args.get('peer'),
    )
    return ToolResult(data={'messages': rows})


async def _chat_who(ctx, args):
    rows = await ctx.client.chat_who()
    return ToolResult(data={'operators': rows})


async def _graph_view(ctx, args):
    mode = args['mode']
    src = args.get('src')
    dst = args.get('dst')
    text = await ctx.client.graph(mode, src, dst)
    return ToolResult(data={'text': text})


async def _get_command_catalogue(ctx, args):
    cat = await ctx.client.commands(args.get('target_os'))
    return ToolResult(data=cat)


# ---- T2 --------------------------------------------------------------

async def _run_on_many(ctx, verb, scope, tag, ids, timeout,
                       max_concurrent):
    """Run one read-only verb on many live beacons.

    Shared by ps_all/id_all/netstat_all. The verb is checked
    against the operator's local allowlist here as well as in
    the dispatcher, because this helper is also importable by
    callers that bypass dispatch.
    """
    if verb not in (ctx.cfg.mcp_allow_verbs or []):
        raise errors.AllowlistError(
            f'verb {verb!r} is not in mcp_allow_verbs',
            hint=('add the verb to mcp_allow_verbs in '
                  f'{ctx.cfg.source_path}'))

    try:
        timeout = int(timeout)
    except (TypeError, ValueError):
        timeout = 120
    timeout = max(1, min(timeout, 900))
    try:
        max_concurrent = int(max_concurrent)
    except (TypeError, ValueError):
        max_concurrent = 4
    limit = max(1, min(max_concurrent or 4, 5))

    rows = await ctx.client.list_beacons() or []
    live = []
    for b in rows:
        try:
            int(b.get('id'))
        except (TypeError, ValueError):
            continue
        if b.get('alive'):
            live.append(b)

    scope = str(scope or '').lower()
    if scope == 'all':
        selected = live
    elif scope == 'tag':
        wanted = str(tag or '').strip()
        if not wanted:
            raise errors.ValidationError(
                'scope=tag requires a non-empty tag')
        selected = [b for b in live
                    if wanted in (b.get('tags') or [])]
    elif scope == 'ids':
        if not isinstance(ids, list) or not ids:
            raise errors.ValidationError(
                'scope=ids requires a non-empty ids array')
        try:
            wanted_ids = {int(i) for i in ids}
        except (TypeError, ValueError):
            raise errors.ValidationError(
                'ids must contain integers')
        selected = [b for b in live
                    if int(b.get('id')) in wanted_ids]
    elif scope == 'attached':
        current = getattr(ctx.client, 'current_beacon', None)
        selected = [
            b for b in live
            if ((b.get('viewer_count') or 0) > 0
                or b.get('viewers')
                or b.get('id') == current)
        ]
    else:
        raise errors.ValidationError(
            f'unknown scope {scope!r}; use all, tag, ids, '
            f'or attached')

    sem = asyncio.Semaphore(limit)
    loop = asyncio.get_running_loop()

    async def _one(bid):
        async with sem:
            deadline = loop.time() + timeout
            try:
                info = await ctx.client.queue_task(
                    bid, verb, [], timeout=timeout)
                if info.get('error'):
                    raise errors.ServerError(
                        f'enqueue failed: {info["error"]}')
                if info.get('ready') or info.get('applied'):
                    result = info
                else:
                    tid = info.get('task_id')
                    if not tid:
                        raise errors.ServerError(
                            f'server did not return a task id '
                            f'for {verb} on #{bid}')
                    while True:
                        remaining = deadline - loop.time()
                        if remaining <= 0:
                            raise errors.ServerError(
                                f'{verb} on #{bid} timed out '
                                f'after {timeout}s (task {tid})')
                        result = await ctx.client.task_result(
                            bid, tid, wait=min(1.0, remaining))
                        if result.get('ready'):
                            break
                        await asyncio.sleep(
                            min(0.1, max(0.0, remaining)))

                result = result or {}
                err = result.get('error')
                entry = {'ok': not bool(err)}
                if err:
                    entry['error'] = str(err)
                else:
                    entry['output'] = _text_output(
                        result.get('output'))
                entry['exit_code'] = result.get('exit_code')
                return bid, entry
            except Exception as exc:
                return bid, {
                    'ok':        False,
                    'error':     f'{type(exc).__name__}: {exc}',
                    'exit_code': None,
                }

    pairs = await asyncio.gather(
        *(_one(int(b.get('id'))) for b in selected))
    results = {str(bid): entry for bid, entry in pairs}
    completed = sum(1 for e in results.values() if e['ok'])
    return ToolResult(data={
        'verb':      verb,
        'scope':     scope,
        'matched':   len(selected),
        'completed': completed,
        'failed':    len(results) - completed,
        'results':   results,
    })


async def _ps_all(ctx, args):
    return await _run_on_many(
        ctx, 'ps', args.get('scope'), args.get('tag'),
        args.get('ids'), args.get('timeout', 120),
        args.get('max_concurrent', 4))


async def _id_all(ctx, args):
    return await _run_on_many(
        ctx, 'id', args.get('scope'), args.get('tag'),
        args.get('ids'), args.get('timeout', 120),
        args.get('max_concurrent', 4))


async def _netstat_all(ctx, args):
    return await _run_on_many(
        ctx, 'netstat', args.get('scope'), args.get('tag'),
        args.get('ids'), args.get('timeout', 120),
        args.get('max_concurrent', 4))


async def _queue_task(ctx, args):
    bid = int(args['beacon_id'])
    verb = args['verb']
    targs = [str(a) for a in (args.get('args') or [])]
    result = await ctx.client.queue_task(bid, verb, targs)
    return ToolResult(
        data=result,
        audit_id=result.get('audit_id'),
    )


async def _cancel_task(ctx, args):
    bid = int(args['beacon_id'])
    tid = str(args['task_id'])
    result = await ctx.client.cancel(bid, tid)
    return ToolResult(
        data=result,
        audit_id=result.get('audit_id'),
    )


async def _sleep_set(ctx, args):
    bid = int(args['beacon_id'])
    interval = int(args['interval'])
    jitter = float(args.get('jitter', 0.3))
    result = await ctx.client.queue_task(
        bid, 'sleep', [str(interval), str(jitter)])
    return ToolResult(
        data=result,
        audit_id=result.get('audit_id'),
    )


async def _workhours_set(ctx, args):
    bid = int(args['beacon_id'])
    start = str(args['start']).strip()
    if start.lower() in ('off', 'disable', 'none'):
        targs = [start]
    else:
        end = args.get('end')
        if end is None or not str(end).strip():
            raise errors.ValidationError(
                'workhours_set requires "end" unless start="off"')
        targs = [start, str(end).strip()]
    result = await ctx.client.queue_task(bid, 'workhours', targs)
    return ToolResult(
        data=result,
        audit_id=result.get('audit_id'),
    )


async def _alias_set(ctx, args):
    bid = int(args['beacon_id'])
    alias = (args.get('alias') or '').strip()
    result = await ctx.client.alias(bid, alias)
    return ToolResult(
        data=result,
        audit_id=result.get('audit_id'),
    )


async def _tag_op(ctx, args):
    bid = int(args['beacon_id'])
    result = await ctx.client.tag(
        bid, args['op'], args['tag'])
    return ToolResult(
        data=result,
        audit_id=result.get('audit_id'),
    )


async def _note_add(ctx, args):
    scope = args['scope']
    text = args['text']
    tags = args.get('tags') or []
    if scope == 'beacon':
        bid = int(args['beacon_id'])
        result = await ctx.client.beacon_note(bid, 'add', text)
    else:
        result = await ctx.client.notes('add', text, tags)
    return ToolResult(
        data=result,
        audit_id=result.get('audit_id'),
    )


async def _chat_send(ctx, args):
    result = await ctx.client.chat_send(
        args['text'], args.get('kind', 'chat'))
    return ToolResult(
        data=result,
        audit_id=result.get('audit_id'),
    )


async def _build_agent(ctx, args):
    cfg = args['config_json']
    if isinstance(cfg, str):
        cfg = json.loads(cfg)
    # Kick off the build.
    info = await ctx.client.build(cfg)
    build_id = info['build_id']
    size = int(info['size'])

    # Stream the binary in chunks and save locally.
    out_dir = ctx.cfg.build_output_dir
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, info['filename'])

    offset = 0
    chunk = 512 * 1024
    part = out_path + '.part'
    try:
        with open(part, 'wb') as fh:
            while offset < size:
                data = await ctx.client.build_chunk(
                    build_id, offset, chunk)
                if not data:
                    raise errors.ServerError(
                        f'build {build_id} ended after '
                        f'{offset} of {size} bytes')
                fh.write(data)
                offset += len(data)
        if offset != size:
            raise errors.ServerError(
                f'build {build_id} produced {offset} of '
                f'{size} bytes')
        os.replace(part, out_path)
    except Exception:
        try:
            os.unlink(part)
        except OSError:
            pass
        raise

    # Tell the server we are done with the staging copy.
    try:
        await ctx.client.build_finish(build_id)
    except Exception:
        # The binary is already local and verified; a failed
        # cleanup must not turn a successful build into an error.
        logging.warn('build.finish_failed', build=str(build_id))

    return ToolResult(data={
        'path':   out_path,
        'size':   size,
        'sha256': info.get('sha256'),
        'filename': info.get('filename'),
    })


async def _export_beacon(ctx, args):
    bid = int(args['beacon_id'])
    dump = await ctx.client.beacon_dump(bid)
    html = ctx.client.render_session_html(dump)
    if not html:
        path = os.path.join(
            ctx.cfg.build_output_dir,
            f'beacon-{bid}.json')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(dump, fh, indent=2, default=str)
        return ToolResult(
            data={'path': path, 'format': 'json'},
            audit_id=(dump or {}).get('audit_id'))
    path = os.path.join(
        ctx.cfg.build_output_dir, f'beacon-{bid}.html')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(html)
    return ToolResult(
        data={'path': path, 'format': 'html'},
        audit_id=(dump or {}).get('audit_id'))


# ---- T3 --------------------------------------------------------------

async def _run_bof(ctx, args):
    bid = int(args['beacon_id'])
    name = str(args['name']).strip()
    bargs = [str(a) for a in (args.get('args') or [])]
    entry = await ctx.client.bof_get(name)
    if entry.get('ok') is False:
        raise errors.ServerError(
            entry.get('error') or f'BOF {name!r} not available',
            audit_id=entry.get('audit_id'))
    data_b64 = entry.get('data_b64')
    if not data_b64:
        raise errors.ServerError(
            f'BOF {name!r} returned no payload bytes',
            audit_id=entry.get('audit_id'))
    fmt = entry.get('format') or ''
    if bargs:
        try:
            if fmt:
                packed = _pack_bof_args(bargs, fmt)
            else:
                packed = _pack_bof_args_default(bargs)
        except (ValueError, TypeError, base64.binascii.Error) as exc:
            raise errors.ValidationError(
                f'could not pack BOF args for {name!r}: {exc}')
        args_b64 = base64.b64encode(packed).decode('ascii')
    else:
        args_b64 = base64.b64encode(b'').decode('ascii')
    result = await ctx.client.queue_task(
        bid, 'bof', [data_b64, '', args_b64])
    return ToolResult(
        data=result,
        audit_id=result.get('audit_id'),
    )


async def _creds_add(ctx, args):
    result = await ctx.client.creds_add(
        user=args['user'],
        domain=args.get('domain', ''),
        kind=args['kind'],
        value=args['value'],
        source_beacon=int(args.get('source_beacon', 0)),
        source_path=args.get('source_path', ''),
    )
    return ToolResult(
        data=result,
        audit_id=result.get('audit_id'),
    )


async def _creds_reveal(ctx, args):
    result = await ctx.client.creds_get(args['id'])
    return ToolResult(
        data=result,
        audit_id=result.get('audit_id'),
    )


async def _creds_validate(ctx, args):
    result = await ctx.client.creds_validate(
        args['id'],
        int(args['from_beacon']),
        target=args.get('target'),
    )
    return ToolResult(
        data=result,
        audit_id=result.get('audit_id'),
    )


async def _download_beacon_file(ctx, args):
    bid = int(args['beacon_id'])
    remote = args['remote_path']
    remote_name = os.path.basename(
        str(remote).replace('\\', '/'))
    local_name = f'{bid}-{remote_name or "download"}'
    local_path = os.path.join(
        ctx.cfg.build_output_dir, 'downloads', local_name)
    result = await ctx.client.download_to_loot(
        bid, remote, local_path)
    return ToolResult(data=result,
                      audit_id=result.get('audit_id'))


async def _upload_beacon_file(ctx, args):
    bid = int(args['beacon_id'])
    local = os.path.expanduser(args['local_path'])
    if not os.path.isfile(local):
        raise errors.NotFoundError(
            f'local file not found: {local}')
    remote = args['remote_path']
    fn = getattr(ctx.client, 'upload_file', None)
    if fn is None:
        raise errors.ServerError(
            'upload_file is not implemented on the Client',
            hint=('add an `upload_file(beacon_id, local_path, '
                  'remote_path)` method to your Client'))
    result = await fn(bid, local, remote)
    return ToolResult(data=result,
                      audit_id=result.get('audit_id'))


async def _kill_beacon(ctx, args):
    bid = int(args['beacon_id'])
    result = await ctx.client.killall(scope='ids', ids=[bid])
    return ToolResult(
        data=result,
        audit_id=result.get('audit_id'),
    )


async def _killall_beacons(ctx, args):
    scope = str(args['scope']).strip().lower()
    kw = {}
    if scope == 'tag':
        tag = (args.get('tag') or '').strip()
        if not tag:
            raise errors.ValidationError(
                'scope=tag requires a non-empty tag')
        kw['tag'] = tag
    elif scope == 'ids':
        ids = args.get('ids') or []
        if not isinstance(ids, list) or not ids:
            raise errors.ValidationError(
                'scope=ids requires a non-empty ids array')
        try:
            kw['ids'] = [int(i) for i in ids]
        except (TypeError, ValueError):
            raise errors.ValidationError(
                'ids must contain integers')
    elif scope in ('all', 'stale'):
        pass
    else:
        raise errors.ValidationError(
            f'unknown scope {scope!r}; use all, stale, tag, '
            f'or ids')
    result = await ctx.client.killall(scope=scope, **kw)
    return ToolResult(
        data=result,
        audit_id=result.get('audit_id'),
    )


async def _screenshot_beacon(ctx, args):
    bid = int(args['beacon_id'])
    result = await ctx.client.run_task(
        bid, 'screenshot', [], timeout=120, grace=0)
    if result.get('error'):
        raise errors.ServerError(
            str(result['error']),
            audit_id=result.get('audit_id'))
    try:
        png = base64.b64decode(
            result.get('output') or '', validate=True)
    except Exception:
        raise errors.ServerError(
            'screenshot result contained invalid base64',
            audit_id=result.get('audit_id'))
    if not png:
        raise errors.ServerError(
            'screenshot produced no data',
            audit_id=result.get('audit_id'))
    out_dir = os.path.join(
        ctx.cfg.build_output_dir, 'screenshots')
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f'beacon-{bid}.png')
    with open(path, 'wb') as fh:
        fh.write(png)
    return ToolResult(
        data={'path': path, 'size': len(png)},
        audit_id=result.get('audit_id'),
    )


# ---- Helper ----------------------------------------------------------

async def _gather(*coros):
    import asyncio
    return await asyncio.gather(*coros)


HANDLERS = {
    'list_beacons':          _list_beacons,
    'beacon_info':           _beacon_info,
    'beacon_result':         _beacon_result,
    'beacon_tasks':          _beacon_tasks,
    'list_listeners':        _list_listeners,
    'list_profiles':         _list_profiles,
    'list_bofs':             _list_bofs,
    'list_loot':             _list_loot,
    'list_creds':            _list_creds,
    'list_notes':            _list_notes,
    'audit_tail':            _audit_tail,
    'chat_history':          _chat_history,
    'chat_who':              _chat_who,
    'graph_view':            _graph_view,
    'get_command_catalogue': _get_command_catalogue,

    'queue_task':            _queue_task,
    'cancel_task':           _cancel_task,
    'sleep_set':             _sleep_set,
    'workhours_set':         _workhours_set,
    'alias_set':             _alias_set,
    'tag_op':                _tag_op,
    'note_add':              _note_add,
    'chat_send':             _chat_send,
    'build_agent':           _build_agent,
    'export_beacon':         _export_beacon,

    'ps_all':                _ps_all,
    'id_all':                _id_all,
    'netstat_all':           _netstat_all,

    'run_bof':               _run_bof,
    'creds_add':             _creds_add,
    'creds_reveal':          _creds_reveal,
    'creds_validate':        _creds_validate,
    'download_beacon_file':  _download_beacon_file,
    'upload_beacon_file':    _upload_beacon_file,
    'kill_beacon':           _kill_beacon,
    'killall_beacons':       _killall_beacons,
    'screenshot_beacon':     _screenshot_beacon,
}