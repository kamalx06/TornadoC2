"""Server-side BOF registry.

SECURITY INVARIANT — READ BEFORE MODIFYING THIS FILE.

    This module stores and serves COFF bytes. It NEVER executes
    them. There is no subprocess, no ctypes, no importlib, no
    eval, and no os.system anywhere in this file — and there must
    never be. A BOF runs only when a beacon agent on a target
    receives a `bof` task and hands the COFF to its in-process
    C# loader. The team server is a blob broker between the
    operator's client and the target's beacon. If you find
    yourself wanting to add code here that "just tests" or
    "verifies" a BOF by running it, stop: that capability does
    not belong on the team server, and its existence would turn
    every remote operator with `beacon.build` into a remote code
    execution primitive against the server host itself.

Registered BOFs live in two places:

  * bofs/<name>.o                — the raw COFF bytes
  * logs/.tornadoc2_bofs.json — metadata (format, description, sha256)

The registry is shared across every operator on the team server, so
"register a BOF once" is the same operation for everyone. Adding and
removing are audited; reading the list is not.

The name is the operator-facing identifier. It is validated against
a strict character class so a hostile client cannot smuggle a path
separator or a dot-dot into the filename used on disk.
"""

import hashlib
import json
import os
import re
import threading


BOF_DIR       = 'bofs'
REGISTRY_PATH = os.path.join('logs', '.tornadoc2_bofs.json')
MAX_BOF_BYTES = 10 * 1024 * 1024
MAX_BOF_COUNT = 512
_NAME_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,63}$')

_ARCH_BY_MACHINE = {
    0x8664: 'x64',    # AMD64
    0x014c: 'x86',    # I386
}

_lock = threading.Lock()


# ----------------------------------------------------------------------
# Registry I/O

def _ensure_dirs():
    os.makedirs(BOF_DIR, mode=0o700, exist_ok=True)
    _d = os.path.dirname(REGISTRY_PATH)
    if _d:
        os.makedirs(_d, mode=0o700, exist_ok=True)
    for d in (BOF_DIR, _d or '.'):
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass


def _load_registry():
    _ensure_dirs()
    try:
        if os.path.isfile(REGISTRY_PATH):
            with open(REGISTRY_PATH, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                return data
    except (OSError, ValueError):
        pass
    return {}


def _save_registry(reg):
    _ensure_dirs()
    tmp = REGISTRY_PATH + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(reg, fh, indent=2, sort_keys=True)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, REGISTRY_PATH)


# ----------------------------------------------------------------------
# Public API

def list_all():
    """Return {name: meta} for every registered BOF.

    Entries whose backing file is missing are still returned, with
    `missing: True` on the meta, so an operator sees that the
    registry knows about the BOF even if the blob was deleted.
    """
    with _lock:
        reg = _load_registry()
    out = {}
    for name, meta in reg.items():
        entry = dict(meta)
        entry['name'] = name
        path = os.path.join(BOF_DIR, name + '.o')
        entry['path'] = path
        entry['missing'] = not os.path.isfile(path)
        out[name] = entry
    return out


def get(name):
    """Return one entry, or None."""
    if not _valid_name(name):
        return None
    reg = _load_registry()
    meta = reg.get(name)
    if meta is None:
        return None
    entry = dict(meta)
    entry['name'] = name
    entry['path'] = os.path.join(BOF_DIR, name + '.o')
    entry['missing'] = not os.path.isfile(entry['path'])
    return entry


def add(name, data, fmt='', description='', source='', origin='upload'):
    """Register or replace a BOF.

    Returns (meta, replaced: bool). Raises ValueError on any input
    the caller should see as a 400.
    """
    if not _valid_name(name):
        raise ValueError(
            'name must match ^[A-Za-z_][A-Za-z0-9_]{0,63}$')

    if not isinstance(data, (bytes, bytearray)):
        raise ValueError('data must be bytes')

    if len(data) < 20:
        raise ValueError('BOF too small to be a COFF object')

    if len(data) > MAX_BOF_BYTES:
        raise ValueError(
            f'BOF too large ({len(data)} bytes; limit is '
            f'{MAX_BOF_BYTES})')

    machine = int.from_bytes(data[:2], 'little')
    arch = _ARCH_BY_MACHINE.get(machine)
    if arch is None:
        raise ValueError(
            f'unsupported COFF machine 0x{machine:04X}; '
            f'only AMD64 (0x8664) and I386 (0x014C) are accepted')

    with _lock:
        reg = _load_registry()
        replaced = name in reg
        if not replaced and len(reg) >= MAX_BOF_COUNT:
            raise ValueError(
                f'registry full ({MAX_BOF_COUNT} BOFs); '
                f'remove some before adding more')

        _ensure_dirs()
        path = os.path.join(BOF_DIR, name + '.o')
        tmp = path + '.tmp'
        with open(tmp, 'wb') as fh:
            fh.write(data)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)

        digest = hashlib.sha256(data).hexdigest()
        meta = {
            'sha256':      digest,
            'size':        len(data),
            'arch':        arch,
            'format':      fmt or '',
            'description': description or '',
            'source':      source or '',
            'origin':      origin,
        }
        reg[name] = meta
        _save_registry(reg)

    return meta, replaced


def remove(name):
    """Remove a registration and delete the blob.

    Returns the removed meta, or None if the name is unknown or
    invalid. The blob is deleted after the registry update so a
    crash between the two leaves a stale registration that still
    errors cleanly ('missing') rather than a dangling file.
    """
    if not _valid_name(name):
        return None
    with _lock:
        reg = _load_registry()
        meta = reg.pop(name, None)
        if meta is None:
            return None
        _save_registry(reg)

        path = os.path.join(BOF_DIR, name + '.o')
        try:
            os.remove(path)
        except OSError:
            pass

    return meta


# ----------------------------------------------------------------------
# Helpers
def read_bytes(name):
    """Read a registered BOF's bytes safely.

    Returns the raw COFF bytes, or raises:
      * FileNotFoundError — no registration, or blob deleted
      * IsADirectoryError — path is not a regular file
      * OSError — read failure
      * ValueError — file is a symlink, or the on-disk bytes do
        not match the sha256 recorded at registration time

    The symlink and hash checks close two attack paths that the
    naive `open()` would allow:
      * A local attacker who can create a symlink at bofs/<name>.o
        could otherwise make the server serve any file on disk
        under the guise of a registered BOF.
      * A local attacker who can overwrite bofs/<name>.o could
        otherwise deliver a substituted payload to every operator
        who later runs the BOF by name.
    """
    if not _valid_name(name):
        raise ValueError('invalid name')

    path = os.path.join(BOF_DIR, name + '.o')

    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        raise
    except OSError as exc:
        if getattr(exc, 'errno', None) == getattr(
                __import__('errno'), 'ELOOP', None):
            raise ValueError('refusing to read symlinked BOF')
        raise

    try:
        st = os.fstat(fd)
        if not os.path.isfile(path) or not (
                st.st_mode & 0o170000) == 0o100000:
            raise IsADirectoryError(
                'BOF path is not a regular file')
        with os.fdopen(fd, 'rb', closefd=False) as fh:
            data = fh.read(MAX_BOF_BYTES + 1)
    finally:
        os.close(fd)

    if len(data) > MAX_BOF_BYTES:
        raise ValueError('BOF blob exceeds size cap')

    reg = _load_registry()
    meta = reg.get(name) or {}
    want = meta.get('sha256', '')
    if want:
        got = hashlib.sha256(data).hexdigest()
        if got != want:
            raise ValueError(
                'on-disk BOF hash does not match the registry '
                f'(want {want[:16]}, got {got[:16]})')

    return data

def _valid_name(name):
    return bool(name) and bool(_NAME_RE.match(name))