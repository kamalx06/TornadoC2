"""Operator-local armory backed by one pinned repository.

There is no signing and no operator-supplied URL. The repository, branch
and derived endpoints below are constants. Tests patch the endpoint
constants; production always resolves the same host.

Trust comes from TLS, the pinned host and a SHA-256 digest for every
payload. The archive is read member-by-member (no ``extractall``), so
symlinks, device nodes and path tricks are never materialised.

Layout cache: ``<state>/cache.json`` (index snapshot), installs under
``<state>/installed/<name>``. Every write is atomic and 0600.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import PurePosixPath

from tornadoc2_mcp import paths

ARMORY_REPO = 'https://github.com/kamalx06/tornadoc2-armory'
ARMORY_BRANCH = 'main'
ARMORY_RAW_BASE = (
    'https://raw.githubusercontent.com/kamalx06/tornadoc2-armory/main')
ARMORY_MANIFEST_URL = ARMORY_RAW_BASE + '/index.json'
ARMORY_ARCHIVE_URL = (
    'https://codeload.github.com/kamalx06/tornadoc2-armory/'
    'tar.gz/refs/heads/main')

ALLOWED_HOSTS = frozenset({
    'github.com', 'raw.githubusercontent.com', 'codeload.github.com',
})
FORMATS = frozenset({'coff-x64', 'coff-x86', 'coff-arm64'})
NAME_RE = re.compile(r'^[a-z0-9][a-z0-9._-]{0,63}$')
HASH_RE = re.compile(r'^[0-9a-f]{64}$')
FILE_RE = re.compile(r'^[A-Za-z0-9._-]+\.o$')

MANIFEST_CAP = 4 * 1024 * 1024
ARCHIVE_CAP = 16 * 1024 * 1024
FILE_CAP = 4 * 1024 * 1024
MAX_FILES = 400
MAX_INSTALL = 200
CACHE_MAX_AGE = 7 * 86400
USER_AGENT = 'TornadoC2-armory/1.0'

_LOCK = threading.RLock()


class ArmoryError(RuntimeError):
    pass


# ----------------------------------------------------------------------
# State


def state_dir() -> str:
    paths.ensure_state_dir()
    root = str(paths.ARMORY_DIR)
    os.makedirs(root, mode=0o700, exist_ok=True)
    os.makedirs(os.path.join(root, 'installed'), mode=0o700,
                exist_ok=True)
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    return root


def _installed_path() -> str:
    return os.path.join(state_dir(), 'installed.json')


def _cache_path() -> str:
    return os.path.join(state_dir(), 'cache.json')


def _atomic_write(path: str, data: bytes) -> None:
    tmp = path + '.tmp'
    with open(tmp, 'wb') as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def installed() -> dict:
    try:
        with open(_installed_path(), encoding='utf-8') as fh:
            raw = json.loads(fh.read())
    except (OSError, ValueError):
        return {}
    if not isinstance(raw, dict):
        return {}
    out = {}
    for name, meta in raw.items():
        if not isinstance(name, str) or not isinstance(meta, dict):
            continue
        item = dict(meta)
        item.setdefault('version', '')
        item.setdefault('repo_commit', '')
        out[name] = item
    return out


def _save_installed(data: dict) -> None:
    _atomic_write(
        _installed_path(),
        json.dumps(data, indent=2, sort_keys=True).encode('utf-8'))


def log(action: str, name: str, detail: str = '') -> None:
    try:
        with open(os.path.join(state_dir(), 'armory.log'),
                  'a', encoding='utf-8') as fh:
            fh.write(json.dumps({
                'ts': time.time(), 'action': action,
                'name': name, 'detail': detail}) + '\n')
    except OSError:
        pass


# ----------------------------------------------------------------------
# HTTP


class _Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        host = parsed.hostname or ''
        if parsed.scheme != 'https' or host not in ALLOWED_HOSTS:
            raise ArmoryError(
                f'redirect to untrusted URL {newurl!r}')
        return super().redirect_request(
            req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_Redirect())


def _read_url(url: str, cap: int, timeout: float) -> bytes:
    req = urllib.request.Request(url, headers={
        'User-Agent': USER_AGENT,
        'Accept': 'application/json, application/gzip, */*',
    })
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            data = resp.read(cap + 1)
    except urllib.error.HTTPError as exc:
        raise ArmoryError(f'{url}: HTTP {exc.code}') from exc
    except urllib.error.URLError as exc:
        raise ArmoryError(f'{url}: {exc.reason}') from exc
    except (OSError, ValueError) as exc:
        raise ArmoryError(f'{url}: {exc}') from exc
    if len(data) > cap:
        raise ArmoryError(f'{url} exceeds {cap} bytes')
    return data


# ----------------------------------------------------------------------
# Paths and shapes


def _rel(value: str) -> str:
    raw = str(value or '').strip()
    if not raw or len(raw) > 240 or '\x00' in raw or '\\' in raw:
        raise ArmoryError(f'bad path {raw!r}')
    path = PurePosixPath(raw)
    if path.is_absolute() or any(p in ('', '.', '..')
                                 for p in path.parts):
        raise ArmoryError(f'unsafe path {raw!r}')
    return str(path)


def _fetch_name(name: str) -> str:
    name = str(name or '').strip().lower()
    if not NAME_RE.match(name):
        raise ArmoryError(f'bad extension name {name!r}')
    return name


def _entry(row: dict) -> dict:
    name = _fetch_name(row.get('name'))
    fmt = str(row.get('format') or '')
    if fmt not in FORMATS:
        raise ArmoryError(f'{name}: unsupported format {fmt!r}')
    digest = str(row.get('sha256') or '').lower()
    if not HASH_RE.match(digest):
        raise ArmoryError(f'{name}: bad sha256')
    file = str(row.get('file') or '')
    if not FILE_RE.match(file):
        raise ArmoryError(f'{name}: bad file {file!r}')
    out = {
        'name': name,
        'format': fmt,
        'description': str(row.get('description') or '')[:200],
        'version': str(row.get('version') or '')[:32],
        'file': file,
        'sha256': digest,
    }
    if row.get('path'):
        out['path'] = _rel(row['path'])
    if row.get('cna'):
        cna = _rel(row['cna'])
        if not cna.endswith('.cna'):
            raise ArmoryError(f'{name}: cna must end .cna')
        out['cna'] = cna
    if row.get('size') is not None:
        try:
            out['size'] = int(row['size'])
        except (TypeError, ValueError):
            pass
    return out


def normalize_index(data: dict) -> list:
    if not isinstance(data, dict):
        raise ArmoryError('index must be an object')
    version = data.get('version')
    rows = data.get('extensions')
    if version == 1 or rows is None:
        rows = data.get('bofs')
    if not isinstance(rows, list):
        raise ArmoryError('index has no extension list')
    out, seen = [], set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            item = _entry(row)
        except ArmoryError:
            continue
        if item['name'] in seen:
            continue
        seen.add(item['name'])
        out.append(item)
    return out


def _archive_files(data: bytes) -> tuple:
    """Return (index_bytes_or_None, members, metas)."""
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode='r:gz')
    except (tarfile.TarError, OSError) as exc:
        raise ArmoryError(f'archive is not a tar.gz: {exc}') from exc
    index = None
    files, metas = {}, {}
    total = 0
    count = 0
    with tf:
        for member in tf:
            if not member.isreg():
                continue
            raw = member.name
            if raw.startswith('./'):
                raw = raw[2:]
            try:
                rel = _rel(raw)
            except ArmoryError:
                continue
            if rel in ('index.json', 'index.v2.json'):
                try:
                    if member.size > MANIFEST_CAP:
                        continue
                    fh = tf.extractfile(member)
                    if fh is None:
                        continue
                    index = fh.read(MANIFEST_CAP + 1)
                    if len(index) > MANIFEST_CAP:
                        index = None
                except (OSError, tarfile.TarError):
                    index = None
                continue
            if not (rel.startswith('bofs/')
                    and (rel.endswith('.o') or rel.endswith('.cna')
                         or rel.endswith('/meta.json'))):
                continue
            if count >= MAX_FILES:
                raise ArmoryError('archive has too many files')
            try:
                fh = tf.extractfile(member)
                if fh is None:
                    continue
                blob = fh.read(FILE_CAP + 1)
            except (OSError, tarfile.TarError) as exc:
                raise ArmoryError(f'{rel}: {exc}') from exc
            if len(blob) > FILE_CAP:
                raise ArmoryError(f'{rel} exceeds {FILE_CAP} bytes')
            total += len(blob)
            if total > ARCHIVE_CAP:
                raise ArmoryError('archive expands past the cap')
            count += 1
            if rel.endswith('/meta.json'):
                try:
                    metas[rel] = json.loads(blob.decode('utf-8'))
                except (ValueError, UnicodeDecodeError):
                    continue
            else:
                files[rel] = blob
    return index, files, metas


def _derive_entries(metas: dict, files: dict) -> list:
    out = []
    for rel, meta in metas.items():
        parts = PurePosixPath(rel).parts
        if len(parts) < 3:
            continue
        name = parts[1]
        row = dict(meta) if isinstance(meta, dict) else {}
        row['name'] = name
        file = row.get('file')
        if not file:
            candidates = [k for k in files
                          if k.startswith(f'bofs/{name}/')
                          and k.endswith('.o')]
            if len(candidates) != 1:
                continue
            file = PurePosixPath(candidates[0]).name
            row['file'] = file
        if not row.get('path'):
            row['path'] = f'bofs/{name}/{file}'
        blob = files.get(f'bofs/{name}/{file}')
        if blob is not None and not row.get('sha256'):
            row['sha256'] = hashlib.sha256(blob).hexdigest()
        try:
            out.append(_entry(row))
        except ArmoryError:
            continue
    return out


# ----------------------------------------------------------------------
# Cache / refresh


def _read_cache() -> dict | None:
    try:
        with open(_cache_path(), encoding='utf-8') as fh:
            raw = json.loads(fh.read())
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict) or not isinstance(
            raw.get('extensions'), list):
        return None
    try:
        rows = normalize_index({
            'version': 2, 'extensions': raw['extensions']})
    except ArmoryError:
        return None
    return {
        'extensions': rows,
        'fetched_at': float(raw.get('fetched_at') or 0),
        'commit': str(raw.get('commit') or ''),
    }


def _save_cache(rows: list, commit: str) -> None:
    _atomic_write(_cache_path(), json.dumps({
        'version': 1,
        'fetched_at': time.time(),
        'commit': commit,
        'extensions': rows,
    }, indent=2).encode('utf-8'))


def _fetch_manifest() -> tuple:
    """Refresh from the archive, falling back to the raw manifest."""
    errors = []
    try:
        archive = _read_url(ARMORY_ARCHIVE_URL, ARCHIVE_CAP, 30)
        index, files, metas = _archive_files(archive)
        rows = []
        if index is not None:
            try:
                rows = normalize_index(json.loads(index.decode('utf-8')))
            except (ValueError, UnicodeDecodeError) as exc:
                errors.append(f'index: {exc}')
        if not rows and metas:
            rows = _derive_entries(metas, files)
        if not rows:
            raise ArmoryError('archive carries no usable entries')
        return rows, hashlib.sha256(archive).hexdigest()[:12], errors
    except ArmoryError as exc:
        errors.append(str(exc))

    try:
        raw = _read_url(ARMORY_MANIFEST_URL, MANIFEST_CAP, 20)
        rows = normalize_index(json.loads(raw.decode('utf-8')))
        if not rows:
            raise ArmoryError('manifest carries no usable entries')
        return rows, hashlib.sha256(raw).hexdigest()[:12], errors
    except (ArmoryError, ValueError, UnicodeDecodeError) as exc:
        errors.append(str(exc))
    raise ArmoryError('; '.join(errors) or 'armory refresh failed')


def _ensure_cache(refresh: bool = False) -> tuple:
    with _LOCK:
        cache = _read_cache()
        if not refresh and cache is not None:
            return cache, False, ''
        try:
            rows, commit, errors = _fetch_manifest()
            _save_cache(rows, commit)
            return ({'extensions': rows, 'fetched_at': time.time(),
                     'commit': commit}, False, '; '.join(errors))
        except ArmoryError as exc:
            if cache is not None:
                return cache, True, str(exc)
            raise


def catalogue(refresh: bool = False) -> dict:
    cache, stale, error = _ensure_cache(refresh)
    age = max(0.0, time.time() - cache['fetched_at'])
    return {
        'repo': ARMORY_REPO,
        'branch': ARMORY_BRANCH,
        'commit': cache.get('commit', ''),
        'fetched_at': cache['fetched_at'],
        'stale': stale or age > CACHE_MAX_AGE,
        'error': error,
        'extensions': cache['extensions'],
        'installed': installed(),
    }


def update_index() -> dict:
    cache, _stale, error = _ensure_cache(refresh=True)
    return {'count': len(cache['extensions']),
            'fetched_at': cache['fetched_at'], 'error': error}


# ----------------------------------------------------------------------
# Install


def _payload(meta: dict) -> tuple:
    name = meta['name']
    rel = meta.get('path') or f"bofs/{name}/{meta['file']}"
    rel = _rel(rel)
    try:
        body = _read_url(f'{ARMORY_RAW_BASE}/{rel}', FILE_CAP, 30)
    except ArmoryError:
        # A codeload redirect may serve a different raw host; the
        # allowlist covers it and the caller sees the real error.
        raise
    digest = hashlib.sha256(body).hexdigest()
    if digest != meta['sha256']:
        raise ArmoryError(f'{name}: sha256 mismatch')
    if meta.get('size') is not None and len(body) != int(meta['size']):
        raise ArmoryError(f'{name}: size mismatch')
    return body, rel


def _install_one(meta: dict, current: dict, commit: str) -> bool:
    name = meta['name']
    body, _rel = _payload(meta)
    root = os.path.join(state_dir(), 'installed', name)
    tmp = root + '.tmp'
    if os.path.isdir(tmp):
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp, mode=0o700, exist_ok=True)
    try:
        dst = os.path.join(tmp, meta['file'])
        with open(dst, 'wb') as fh:
            fh.write(body)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(dst, 0o600)
        if meta.get('cna'):
            cna_rel = meta['cna']
            if '/' not in cna_rel:
                cna_rel = f"bofs/{name}/{cna_rel}"
            cna = _read_url(f'{ARMORY_RAW_BASE}/{cna_rel}',
                            FILE_CAP, 30)
            with open(os.path.join(tmp, 'script.cna'), 'wb') as fh:
                fh.write(cna)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(os.path.join(tmp, 'script.cna'), 0o600)
        if os.path.isdir(root):
            import shutil
            shutil.rmtree(root, ignore_errors=True)
        os.replace(tmp, root)
    except BaseException:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    current[name] = {
        'format': meta['format'],
        'version': meta.get('version', ''),
        'sha256': meta['sha256'],
        'size': len(body),
        'file': meta['file'],
        'installed_at': time.time(),
        'repo_commit': commit,
    }
    log('install', name, meta['sha256'])
    return True


def install(names, replace: bool = False, all_names: bool = False) -> dict:
    if all_names:
        cache, _stale, _error = _ensure_cache(refresh=True)
        names = [r['name'] for r in cache['extensions']]
    if isinstance(names, str):
        names = [names]
    names = [str(n).strip().lower() for n in (names or []) if n]
    if not names:
        raise ArmoryError('names required')
    if len(names) > MAX_INSTALL:
        raise ArmoryError('too many names')
    with _LOCK:
        cache, _stale, _error = _ensure_cache()
        by_name = {r['name']: r for r in cache['extensions']}
        current = installed()
        done, failed = [], []
        for name in names:
            meta = by_name.get(name)
            if meta is None:
                failed.append({'name': name, 'error': 'not in armory'})
                continue
            if name in current and not replace:
                done.append({'name': name, 'skipped': True})
                continue
            try:
                _install_one(meta, current, cache.get('commit', ''))
                done.append({'name': name})
            except (ArmoryError, OSError) as exc:
                failed.append({'name': name, 'error': str(exc)})
        _save_installed(current)
        return {'done': done, 'failed': failed}


def remove(names) -> dict:
    if isinstance(names, str):
        names = [names]
    with _LOCK:
        current = installed()
        done = []
        for name in names or []:
            name = str(name).strip().lower()
            if name not in current:
                continue
            import shutil
            shutil.rmtree(os.path.join(
                state_dir(), 'installed', name), ignore_errors=True)
            current.pop(name, None)
            log('uninstall', name)
            done.append(name)
        _save_installed(current)
        return {'done': done}


def update(names=None, all_names: bool = False) -> dict:
    with _LOCK:
        current = installed()
        if all_names:
            names = list(current)
        if isinstance(names, str):
            names = [names]
        names = [str(n).strip().lower() for n in (names or []) if n]
        if not names:
            raise ArmoryError('names required')
        cache, _stale, _error = _ensure_cache(refresh=True)
        by_name = {r['name']: r for r in cache['extensions']}
        done, skipped, failed = [], [], []
        for name in names:
            meta = by_name.get(name)
            old = current.get(name)
            if old is None:
                failed.append({'name': name, 'error': 'not installed'})
                continue
            if meta is None:
                failed.append({'name': name, 'error': 'not in armory'})
                continue
            same = (old.get('sha256') == meta['sha256']
                    and not meta.get('version')
                    or (old.get('sha256') == meta['sha256']
                        and old.get('version') == meta.get('version')))
            if same:
                skipped.append({'name': name})
                continue
            try:
                _install_one(meta, current, cache.get('commit', ''))
                done.append({'name': name})
            except (ArmoryError, OSError) as exc:
                failed.append({'name': name, 'error': str(exc)})
        _save_installed(current)
        return {'done': done, 'skipped': skipped, 'failed': failed}


def info(name: str) -> dict | None:
    name = str(name or '').strip().lower()
    ins = installed().get(name)
    if ins is not None:
        return {'name': name, 'installed': True, **ins}
    cache, _stale, _error = _ensure_cache()
    return next(({**r, 'installed': False}
                 for r in cache['extensions'] if r['name'] == name),
                None)


def lookup(name: str):
    """Return (bytes, format) for an installed BOF, or None."""
    meta = installed().get(name)
    if not meta:
        return None
    path = os.path.join(state_dir(), 'installed', name,
                        meta.get('file') or f'{name}.o')
    try:
        with open(path, 'rb') as fh:
            return fh.read(), meta.get('format', '')
    except OSError:
        return None
