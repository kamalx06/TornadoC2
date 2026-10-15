"""Client-side BOF file parsing.

Reads a .cna script or a compiled .o/.obj and returns one or more
records ready for POST /api/v1/bofs/add. The server never reads a
path the client names; the client sends bytes.

Lifted (and simplified) from the standalone bofloader extension.
"""

import base64
import os
import re
import struct


MAX_BOF_BYTES = 10 * 1024 * 1024

_BOF_LIT_RE  = re.compile(r'\bbof\s*\(\s*(["\'])([^"\']+)\1')
_BOFPACK_RE  = re.compile(r'\bbof_pack\s*\(\s*[^,]+,\s*(["\'])(.*?)\1')
_RESOURCE_RE = re.compile(r'\bscript_resource\s*\(\s*(["\'])([^"\']+)\1')
_ALIAS_RE    = re.compile(r'\balias\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{')
_BCR_RE      = re.compile(
    r'\bbeacon_command_register\s*\(\s*(["\'])([^"\']+)\1\s*,\s*'
    r'(["\'])([^"\']*)\3', re.DOTALL)

_CONCAT_DQ_RE = re.compile(r'"((?:[^"\\]|\\.)*)"\s*\.\s*"((?:[^"\\]|\\.)*)"')
_CONCAT_SQ_RE = re.compile(r"'((?:[^'\\]|\\.)*)'\s*\.\s*'((?:[^'\\]|\\.)*)'")


def _collapse_concat(src):
    def dq(m): return '"' + m.group(1) + m.group(2) + '"'
    def sq(m): return "'" + m.group(1) + m.group(2) + "'"
    prev = None
    while prev != src:
        prev = src
        src = _CONCAT_DQ_RE.sub(dq, src)
        src = _CONCAT_SQ_RE.sub(sq, src)
    return src


def _read_text(path):
    try:
        with open(path, 'rb') as f:
            raw = f.read()
    except OSError:
        return None
    if not raw:
        return ''
    if raw[:3] == b'\xef\xbb\xbf':
        try:    return raw[3:].decode('utf-8')
        except UnicodeDecodeError: pass
    if raw[:2] in (b'\xff\xfe', b'\xfe\xff'):
        try:    return raw.decode('utf-16')
        except UnicodeDecodeError: pass
    for enc in ('utf-8', 'latin-1'):
        try:    return raw.decode(enc)
        except UnicodeDecodeError: pass
    return None


def _find_matching_brace(text, open_idx):
    depth = 0
    i = open_idx
    in_str = None
    while i < len(text):
        c = text[i]
        if in_str:
            if c == '\\': i += 2; continue
            if c == in_str: in_str = None
        else:
            if c in ('"', "'"): in_str = c
            elif c == '{': depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0: return i
        i += 1
    return -1


def _derive_name(path):
    """WhoAmI.x64.o -> whoami;  dir-list.x86.obj -> dir_list."""
    base = os.path.basename(path)
    for ext in ('.o', '.obj'):
        if base.lower().endswith(ext):
            base = base[:-len(ext)]; break
    for suf in ('.x64', '.x86'):
        if base.lower().endswith(suf):
            base = base[:-len(suf)]; break
    name = re.sub(r'[^A-Za-z0-9_]', '_', base).strip('_')
    if not name: return None
    if name[0].isdigit(): name = 'bof_' + name
    return name


def _detect_arch(data):
    """Return 'x64' | 'x86' | None."""
    if len(data) < 2: return None
    m = struct.unpack_from('<H', data, 0)[0]
    return {0x8664: 'x64', 0x014c: 'x86'}.get(m)


def _read_object(path):
    """Read and sanity-check a .o/.obj. Returns bytes, or raises."""
    with open(path, 'rb') as f:
        data = f.read()
    if len(data) < 20:
        raise ValueError(f'{path}: file too small to be a COFF object')
    if len(data) > MAX_BOF_BYTES:
        raise ValueError(
            f'{path}: file is {len(data)} bytes; limit is {MAX_BOF_BYTES}')
    if _detect_arch(data) is None:
        machine = struct.unpack_from('<H', data, 0)[0]
        raise ValueError(
            f'{path}: unsupported COFF machine 0x{machine:04X}')
    return data


def _resolve_object_path(cna_dir_abs, rel, cna_path):
    """Resolve a .cna's referenced object path against the .cna's
    own directory, refusing both absolute paths and relative paths
    that escape the directory.

    A .cna from an untrusted source would otherwise be a local file
    disclosure primitive: `script_resource("../../../../etc/shadow")`
    resolves to a real path, the loader reads it, and while the COFF
    check in `_read_object` rejects most non-COFF files, a binary
    whose first two bytes happen to match a known COFF machine type
    would be uploaded to the team server.

    Refusing absolute paths is deliberate — a .cna that ships with
    its .o files beside it uses relative paths, and an operator who
    needs an absolute path can copy the object next to the .cna.
    """
    if os.path.isabs(rel):
        raise ValueError(
            f'{cna_path}: script_resource path must be relative '
            f'to the .cna directory; got {rel!r}')
    resolved = os.path.normpath(os.path.join(cna_dir_abs, rel))
    resolved_abs = os.path.abspath(resolved)
    if not (resolved_abs == cna_dir_abs
            or resolved_abs.startswith(cna_dir_abs + os.sep)):
        raise ValueError(
            f'{cna_path}: script_resource path escapes the .cna '
            f'directory: {rel!r}')
    return resolved_abs


def _parse_cna(cna_path):
    """Return a list of dicts, one per BOF referenced by the CNA.

    Each dict: {name, path, format, description}.
    """
    src = _read_text(cna_path)
    if src is None:
        raise OSError(f'cannot read {cna_path}')
    src = _collapse_concat(src)

    cna_dir = os.path.dirname(os.path.abspath(cna_path))
    cna_dir_abs = os.path.abspath(cna_dir)

    cmd_meta = {}
    for m in _BCR_RE.finditer(src):
        cmd_meta[m.group(2)] = (m.group(4) or '').strip()

    out = []
    for m in _ALIAS_RE.finditer(src):
        alias = m.group(1)
        ob = m.end() - 1
        cb = _find_matching_brace(src, ob)
        if cb < 0: continue
        body = src[ob + 1:cb]

        rel = None
        rm = _RESOURCE_RE.search(body)
        if rm: rel = rm.group(2)
        else:
            lm = _BOF_LIT_RE.search(body)
            if lm: rel = lm.group(2)
        if not rel: continue

        try:
            path = _resolve_object_path(cna_dir_abs, rel, cna_path)
        except ValueError as exc:
            raise ValueError(str(exc))

        fmt = ''
        pm = _BOFPACK_RE.search(body)
        if pm: fmt = pm.group(2)

        out.append({
            'name':        alias,
            'path':        path,
            'format':      fmt,
            'description': cmd_meta.get(alias, ''),
        })

    if not out and cmd_meta:
        rm = _RESOURCE_RE.search(src)
        lm = None if rm else _BOF_LIT_RE.search(src)
        rel = rm.group(2) if rm else (lm.group(2) if lm else None)
        if rel:
            path = _resolve_object_path(cna_dir_abs, rel, cna_path)
            fmt = ''
            pm = _BOFPACK_RE.search(src)
            if pm: fmt = pm.group(2)
            for n, d in cmd_meta.items():
                out.append({'name': n, 'path': path,
                            'format': fmt, 'description': d})

    if not out:
        for lm in _BOF_LIT_RE.finditer(src):
            rel = lm.group(2)
            path = _resolve_object_path(cna_dir_abs, rel, cna_path)
            n = _derive_name(path)
            if n:
                out.append({
                    'name': n, 'path': path, 'format': '',
                    'description': f'(from {os.path.basename(cna_path)})',
                })

    return out


def build_upload_payloads(local_path, replace=False):
    """Turn a local path into a list of /api/v1/bofs/add bodies.

    Accepts:
      · a .o / .obj file
      · a .cna file
      · a directory containing .cna and .o/.obj files

    Returns a list of dicts, each suitable as the JSON body of a
    POST to /api/v1/bofs/add. Raises ValueError on unreadable input.
    """
    if not os.path.exists(local_path):
        raise ValueError(f'path not found: {local_path}')

    if os.path.isdir(local_path):
        return _payloads_from_dir(local_path, replace)

    low = local_path.lower()
    if low.endswith(('.o', '.obj')):
        return [_payload_for_object(local_path, None, replace)]
    if low.endswith('.cna'):
        return _payloads_from_cna(local_path, replace)

    raise ValueError(
        f'unsupported file type: {local_path} '
        f'(expected .o, .obj, .cna, or a directory)')


def _payload_for_object(path, forced_name, replace):
    data = _read_object(path)
    name = forced_name or _derive_name(path)
    if not name:
        raise ValueError(
            f'cannot derive a name from {os.path.basename(path)}; '
            f'rename the file or use --as <name>')
    return {
        'name':        name,
        'data_b64':    base64.b64encode(data).decode('ascii'),
        'format':      '',
        'description': f'(from {os.path.basename(path)})',
        'source':      os.path.basename(path),
        'replace':     bool(replace),
    }


def _payloads_from_cna(cna_path, replace):
    entries = _parse_cna(cna_path)
    if not entries:
        raise ValueError(f'no BOF references found in {cna_path}')

    out = []
    for e in entries:
        path = e['path']
        if not os.path.isfile(path):
            raise ValueError(
                f'{cna_path}: references missing object {path}')
        data = _read_object(path)
        out.append({
            'name':        e['name'],
            'data_b64':    base64.b64encode(data).decode('ascii'),
            'format':      e.get('format', ''),
            'description': e.get('description', ''),
            'source':      os.path.basename(cna_path),
            'replace':     bool(replace),
        })
    return out


def _payloads_from_dir(directory, replace):
    """Import every .cna and .o/.obj in a directory.

    When both Foo.x64.o and Foo.x86.o exist, only x64 is imported
    under the plain name; the x86 variant is registered under
    Foo_x86 so both are reachable.
    """
    entries = sorted(os.listdir(directory))
    cnas = [os.path.join(directory, f) for f in entries
            if f.lower().endswith('.cna')]
    objs = [os.path.join(directory, f) for f in entries
            if f.lower().endswith(('.o', '.obj'))]

    if not cnas and not objs:
        raise ValueError(f'no .cna or .o/.obj files in {directory}')

    out = []
    for cna in cnas:
        out.extend(_payloads_from_cna(cna, replace))

    grouped = {}
    for o in objs:
        n = _derive_name(o)
        if not n: continue
        grouped.setdefault(n, []).append(o)

    def _rank(p):
        low = p.lower()
        if low.endswith(('.x64.o', '.x64.obj')):  return 0
        if low.endswith(('.o', '.obj')): return 1
        if low.endswith(('.x86.o', '.x86.obj')):  return 2
        return 3

    for base, paths in grouped.items():
        paths_sorted = sorted(paths, key=_rank)
        out.append(_payload_for_object(paths_sorted[0], base, replace))
        for p in paths_sorted[1:]:
            low = p.lower()
            if low.endswith('.x86.o') or low.endswith('.x86.obj'):
                out.append(_payload_for_object(p, base + '_x86', replace))
            elif low.endswith('.x64.o') or low.endswith('.x64.obj'):
                out.append(_payload_for_object(p, base + '_x64', replace))
            else:
                suffix = '_' + re.sub(
                    r'[^A-Za-z0-9_]', '_',
                    os.path.basename(p)).strip('_')
                out.append(_payload_for_object(p, base + suffix, replace))

    return out