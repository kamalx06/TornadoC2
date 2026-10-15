"""Malleable response shaping.

Renders outbound bodies into a template the C2 profile defines, and
extracts inbound bodies from the same template. A profile without a
`shaping` block is passed through untouched — the wire format is
unchanged.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import time


_PLACEHOLDER = re.compile(r'^\{\{(\w+)\}\}$')
_PATH_SEG = re.compile(r'^(\w+)(?:\[(\d+)\])?$')


def _encode_payload(raw: bytes, encoding: str) -> str:
    """Apply the profile's encoding transform to raw bytes.

    Empty or unrecognised encoding falls back to standard base64,
    matching the framework's historical wire format. The four
    recognised values mirror the Go side's encodePayload exactly —
    the two must produce byte-identical output for the same input
    or the agent and listener will not round-trip.
    """
    enc = (encoding or '').strip().lower()
    if enc == 'base64url':
        return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')
    if enc == 'hex':
        return raw.hex()
    if enc == 'netbios':
        out = []
        for b in raw:
            out.append(chr(ord('a') + (b & 0x0f)))
            out.append(chr(ord('a') + ((b >> 4) & 0x0f)))
        return ''.join(out)
    return base64.b64encode(raw).decode('ascii')


def _decode_payload(encoded: str, encoding: str) -> bytes:
    """Reverse _encode_payload. Empty or unrecognised encoding
    falls back to standard base64, matching the Go side."""
    enc = (encoding or '').strip().lower()
    if enc == 'base64url':
        pad = (-len(encoded)) % 4
        return base64.urlsafe_b64decode(encoded + '=' * pad)
    if enc == 'hex':
        return bytes.fromhex(encoded)
    if enc == 'netbios':
        if len(encoded) % 2 != 0:
            raise ValueError('netbios payload has odd length')
        out = bytearray(len(encoded) // 2)
        for i in range(0, len(encoded), 2):
            low = ord(encoded[i]) - ord('a')
            high = ord(encoded[i + 1]) - ord('a')
            if not (0 <= low <= 15 and 0 <= high <= 15):
                raise ValueError(
                    f'netbios payload out of range at {i}')
            out[i // 2] = low | (high << 4)
        return bytes(out)
    return base64.b64decode(encoded)


def _render(node, ctx):
    if isinstance(node, dict):
        return {k: _render(v, ctx) for k, v in node.items()}
    if isinstance(node, list):
        return [_render(v, ctx) for v in node]
    if isinstance(node, str):
        m = _PLACEHOLDER.match(node)
        if m:
            return ctx.get(m.group(1), node)
        return node
    return node


def wrap(template, payload, encoding='base64'):
    """Return a dict where `{{payload}}` is the encoded form of the
    JSON serialisation of `payload`. Other placeholders are
    substituted from a per-call context.

    `encoding` names the transform applied to the payload before it
    is placed in the template. Defaults to base64, matching the
    historical wire format. The listener passes the profile's
    per-shape `encoding` field here; a shape without one keeps the
    default.
    """
    inner = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    ctx = {
        'payload': _encode_payload(inner, encoding),
        'ts':      int(time.time()),
        'nonce':   secrets.token_hex(8),
    }
    return _render(template, ctx)


def _walk(obj, path):
    """Walk a dotted/indexed path like 'data' or 'events[0]'."""
    cur = obj
    for part in path.split('.'):
        m = _PATH_SEG.match(part)
        if not m:
            raise KeyError(f'bad path segment: {part!r}')
        key, idx = m.group(1), m.group(2)
        cur = cur[key]
        if idx is not None:
            cur = cur[int(idx)]
    return cur


def unwrap(body, extract_path, encoding='base64'):
    """Walk `extract_path` inside `body`, decode the value found
    there, and return the decoded JSON.

    `encoding` names the transform the wrapped value carries.
    Defaults to base64, matching the historical wire format. The
    listener passes the profile's per-shape `encoding` field here.

    The return type follows the payload: a check-in response
    unwraps to a dict, a tasks response unwraps to a list. The
    caller is expected to know which shape it asked for.
    """
    value = _walk(body, extract_path)
    if not isinstance(value, str):
        raise ValueError(f'extracted value is not a string: {type(value)}')
    raw = _decode_payload(value, encoding)
    return json.loads(raw)

def validate(shaping: dict) -> tuple[list[str], list[str]]:
    """Round-trip the shaping block through wrap+unwrap with a
    probe payload. Returns (errors, warnings).

    Errors are fatal — the profile cannot be built against this
    version. Warnings are advisory — the block will build, but
    the operator should know something is off.

    Unknown keys are warnings, not errors: a profile written
    against a newer version of the tool may carry shaping keys
    this version does not know about, and refusing the build
    would make a forward-compatible profile unusable. A misspelt
    known key is still caught — its `extract` will not resolve
    against the template, and the round-trip below produces an
    error.

    The round-trip catches extract paths that do not resolve
    against the template. A profile where `extract` says
    'events[0]' but the template writes to 'results[0]' builds
    fine but fails on the first check-in. Better to catch it
    now.
    """
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(shaping, dict):
        return (['shaping must be a JSON object'], [])

    valid_keys = {'checkin_response', 'tasks_response', 'results_request'}
    unknown = set(shaping) - valid_keys
    for k in sorted(unknown):
        warnings.append(f'shaping.{k}: unknown key (valid: '
                        f'{", ".join(sorted(valid_keys))})')

    for key in valid_keys:
        spec = shaping.get(key)
        if spec is None:
            continue
        if not isinstance(spec, dict):
            errors.append(f'shaping.{key}: must be an object')
            continue
        tmpl = spec.get('template')
        extract = spec.get('extract')
        if not isinstance(tmpl, dict):
            errors.append(f'shaping.{key}.template: must be an object')
            continue
        if not isinstance(extract, str) or not extract:
            errors.append(
                f'shaping.{key}.extract: required, non-empty string')
            continue

        probe = {'__probe__': 'ok', 'n': 1}
        try:
            rendered = wrap(tmpl, probe)
        except Exception as exc:
            errors.append(
                f'shaping.{key}: template render failed: {exc}')
            continue
        try:
            recovered = unwrap(rendered, extract)
        except Exception as exc:
            errors.append(
                f'shaping.{key}: extract {extract!r} does not '
                f'resolve against the rendered template: {exc}')
            continue
        if recovered != probe:
            errors.append(
                f'shaping.{key}: round-trip mismatch — extract '
                f'{extract!r} returned {recovered!r}, expected {probe!r}')

    return (errors, warnings)