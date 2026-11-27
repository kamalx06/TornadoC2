"""At-rest encryption for operator-owned state.

Credentials, notes, the engagement model and similar files are
encrypted with AES-256-GCM under a server key. The point is a disk
or backup copy of ``logs/`` no longer yields reusable secrets.

The key lives in ``logs/at_rest.key`` (mode 0600) and is created on
first use. ``TORNADOC2_AT_REST_KEY`` may supply it as base64
instead, so an operator can keep it out of the backup; a copy of the
key is required to restore encrypted state. ``TORNADOC2_AT_REST=off``
disables encryption entirely.

Files written before encryption existed are still plain JSON. They
are read normally and re-written encrypted on the next save, so an
upgrade migrates lazily. ``is_encrypted`` distinguishes the two.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import threading

_MAGIC = b'T2ENC2\n'
_MAGIC_V1 = b'T2ENC1\n'
_AAD_V1 = b'tornadoc2/atrest/v1'
_AAD_PREFIX = b'tornadoc2/atrest/v2\x00'
_KEY_BYTES = 32
_lock = threading.Lock()
_cached: tuple[str, bytes] | None = None


class AtRestError(ValueError):
    pass


def enabled() -> bool:
    return os.environ.get('TORNADOC2_AT_REST', 'on').lower() not in (
        'off', '0', 'false', 'no')


def _key_path() -> str:
    return os.environ.get(
        'TORNADOC2_AT_REST_KEY_FILE', 'logs/at_rest.key')


def key() -> bytes:
    global _cached
    env = os.environ.get('TORNADOC2_AT_REST_KEY', '').strip()
    if env:
        try:
            raw = base64.b64decode(env, validate=True)
        except Exception as exc:
            raise AtRestError(f'bad TORNADOC2_AT_REST_KEY: {exc}') from exc
        if len(raw) != _KEY_BYTES:
            raise AtRestError('TORNADOC2_AT_REST_KEY must be 32 bytes')
        return raw
    path = _key_path()
    with _lock:
        if _cached and _cached[0] == path:
            return _cached[1]
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        if not os.path.isfile(path):
            raw = secrets.token_bytes(_KEY_BYTES)
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                             0o600)
            except FileExistsError:
                raw = b''
                fd = -1
            if fd != -1:
                try:
                    os.write(fd, raw)
                finally:
                    os.close(fd)
        if not raw:
            with open(path, 'rb') as fh:
                raw = fh.read()
        if len(raw) != _KEY_BYTES:
            raise AtRestError(f'{path} is not a 32-byte key')
        _cached = (path, raw)
        return raw


def reset_cache() -> None:
    global _cached
    _cached = None


def is_encrypted(path: str) -> bool:
    try:
        with open(path, 'rb') as fh:
            h = fh.read(8)
            return h.startswith(_MAGIC) or h.startswith(_MAGIC_V1)
    except OSError:
        return False


def _aad_candidates(path: str):
    """Path spellings accepted for older seals (abs, given, base)."""
    out = []
    for cand in (os.path.abspath(path) if path else '',
                 path, os.path.basename(path)):
        b = cand.encode('utf-8', 'replace')
        if b and b not in out:
            out.append(b)
    return out or [b'']


def _aad(path: str) -> bytes:
    # Absolute so the same file sealed from a different working
    # directory still authenticates.
    norm = os.path.abspath(path) if path else ''
    return _AAD_PREFIX + norm.encode('utf-8', 'replace')


def encrypt(raw: bytes, path: str = '') -> bytes:
    """Seal ``raw``; ``path`` is bound as AAD.

    Binding the path means an attacker cannot swap two encrypted
    files of the same server: the AAD no longer matches.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = secrets.token_bytes(12)
    blob = AESGCM(key()).encrypt(nonce, raw, _aad(path))
    return _MAGIC + base64.b64encode(nonce + blob)


def decrypt(raw: bytes, path: str = '') -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if raw.startswith(_MAGIC_V1):
        body = base64.b64decode(raw[len(_MAGIC_V1):])
        if len(body) < 13:
            raise AtRestError('truncated encrypted file')
        return AESGCM(key()).decrypt(body[:12], body[12:], _AAD_V1)
    if not raw.startswith(_MAGIC):
        return raw
    body = base64.b64decode(raw[len(_MAGIC):])
    if len(body) < 13:
        raise AtRestError('truncated encrypted file')
    last = None
    for cand in _aad_candidates(path):
        try:
            return AESGCM(key()).decrypt(body[:12], body[12:],
                                         _AAD_PREFIX + cand)
        except Exception as exc:
            last = exc
    raise AtRestError(f'cannot authenticate {path}: {last}')


def read_bytes(path: str) -> bytes:
    with open(path, 'rb') as fh:
        raw = fh.read()
    if raw.startswith(_MAGIC) or raw.startswith(_MAGIC_V1):
        return decrypt(raw, path)
    return raw


def load_json(path: str, default):
    """Read JSON, decrypting when needed. Missing file -> default."""
    try:
        raw = read_bytes(path)
    except FileNotFoundError:
        return default
    return json.loads(raw.decode('utf-8'))


def save_json(path: str, obj, *, indent: int = 2, mode: int = 0o600) -> None:
    """Atomically write JSON, encrypted unless disabled."""
    data = json.dumps(obj, indent=indent, sort_keys=True).encode('utf-8')
    body = encrypt(data, path) if enabled() else data
    tmp = path + '.tmp'
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(tmp, 'wb') as fh:
        fh.write(body)
        fh.flush()
        try:
            os.fsync(fh.fileno())
        except OSError:
            pass
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _marker_path() -> str:
    return os.environ.get('TORNADOC2_AT_REST_MARKER',
                          'logs/.atrest-v2')


def _fingerprint() -> str:
    import hashlib
    return hashlib.sha256(key()).hexdigest()[:32]


def needs_migration() -> bool:
    """True when the store has never seen this key at v2."""
    if not enabled():
        return False
    try:
        with open(_marker_path(), 'r', encoding='ascii') as fh:
            return fh.read().strip() != _fingerprint()
    except OSError:
        return True


def mark_migrated() -> None:
    path = _marker_path()
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='ascii') as fh:
        fh.write(_fingerprint() + '\n')
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def scan(roots, extra=()) -> list[str]:
    """Return state files that are still plaintext."""
    bad = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                if name.endswith(('.txt', '.log', '.key', '.corrupt',
                                  '.tmp', '.sha256')) or name in (
                        'checkpoint.json', 'anchor.json'):
                    continue
                p = os.path.join(dirpath, name)
                try:
                    if os.path.getsize(p) == 0:
                        continue
                except OSError:
                    continue
                if not is_encrypted(p):
                    bad.append(p)
    for p in extra:
        if os.path.isfile(p) and not is_encrypted(p):
            bad.append(p)
    return bad


def migrate_all(paths) -> list[str]:
    """Encrypt every plaintext file in ``paths``. Returns what changed."""
    done = []
    for path in paths:
        try:
            if migrate(path):
                done.append(path)
        except (OSError, AtRestError):
            continue
    return done


def migrate(path: str) -> bool:
    """Encrypt one plaintext file in place. True if it changed."""
    if not enabled() or not os.path.isfile(path):
        return False
    if is_encrypted(path):
        return False
    raw = read_bytes(path)
    tmp = path + '.tmp'
    with open(tmp, 'wb') as fh:
        fh.write(encrypt(raw, path))
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return True
