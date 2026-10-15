"""Operator config file.

Raw JSON containing the CA, client cert, and client key. File
mode 0600. This is the format the server's `operators export`
endpoint and the local console's `operator export` command both
write.

An earlier revision wrote base64-encoded JSON. The loader still
accepts that form for backward compatibility — see the
`raw.startswith('{')` branch in `load()` — but nothing writes it
any more. `save()` is retained for tooling that constructs config
files programmatically; it writes base64, matching what the old
exporter produced.

This file is a bearer credential. Anyone who reads it can act as
the operator. If the operator also has a password on record, the
password is a second factor and is not stored here — it travels
out of band. Store the file accordingly.
"""

import base64
import json
import os
import time


REQUIRED_FIELDS = (
    'name', 'role', 'server_host', 'server_port',
    'ca_pem', 'client_cert', 'client_key',
)


def load(path: str) -> dict:
    try:
        import stat as _stat
        mode = os.stat(path).st_mode
        if mode & (_stat.S_IRWXG | _stat.S_IRWXO):
            import sys as _sys
            print(f"warning: {path} is readable by group/other "
                  f"(mode {oct(mode & 0o777)}) — should be 0600",
                  file=_sys.stderr)
    except OSError:
        pass
    with open(path, 'r', encoding='utf-8') as fh:
        raw = fh.read().strip()
    if raw.startswith('{'):
        blob = raw
    else:
        try:
            blob = base64.b64decode(raw).decode('utf-8')
        except Exception:
            raise ValueError('config is not valid base64 or JSON')
    try:
        cfg = json.loads(blob)
    except ValueError:
        raise ValueError('config JSON parse failed')
    for field in REQUIRED_FIELDS:
        if not cfg.get(field):
            raise ValueError(f'config missing field: {field}')
    if cfg['role'] == 'local':
        raise ValueError(
            'refusing to load a config with local role — this file '
            'is either corrupt or was minted by mistake')

    # server_cert_sha256 is optional (older configs do not carry
    # it), but when present it must be 64 lowercase hex. A config
    # with a truncated or uppercase value would load and then fail
    # on every request with a cryptic "server certificate
    # fingerprint mismatch" — the check catches it here, at load
    # time, where the message names the actual problem.
    fp = (cfg.get('server_cert_sha256') or '').lower()
    if fp:
        if len(fp) != 64:
            raise ValueError(
                f'config server_cert_sha256 is {len(fp)} '
                f'characters; expected 64 hex')
        if any(c not in '0123456789abcdef' for c in fp):
            raise ValueError(
                'config server_cert_sha256 is not lowercase hex')
        cfg['server_cert_sha256'] = fp

    return cfg


def save(path: str, cfg: dict) -> None:
    """DEPRECATED — writes the legacy base64 form.

    Do not call from new code. The server, the local console,
    and the client all read and write raw JSON. Retained only
    for external tooling that constructs config files
    programmatically and has not been updated.

    A future release will delete this function. If you find
    yourself reaching for it, write raw JSON instead:

        import json
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(cfg, fh, indent=2, sort_keys=True)
        os.chmod(path, 0o600)
    """
    blob = json.dumps(cfg, separators=(',', ':'))
    b64 = base64.b64encode(blob.encode('utf-8')).decode('ascii')
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(b64)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def age_days(path: str) -> float:
    """Return the file's age in days, or 0.0 if it is not statable.

    The caller uses this only to decide whether to print a warning.
    A missing file is not the caller's problem to solve here — the
    load path will produce its own error — so a deleted or
    renamed-under-us config returns 0.0 rather than raising
    FileNotFoundError through the caller's stack.
    """
    try:
        return (time.time() - os.path.getmtime(path)) / 86400.0
    except OSError:
        return 0.0