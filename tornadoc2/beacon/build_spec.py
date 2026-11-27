"""Authoritative build transport and cross-field rules.

`BeaconBuilder`, the remote build loader and the CLI wizard all speak
this module. It is pure: no filesystem access except reading a named
OPSEC profile through the caller, and no subprocess.

The descriptor is the contract the Agent Builder form renders. Every
rule here mirrors one that previously lived twice (builder and loader),
so the GUI cannot drift from what the compiler actually accepts.
"""

from __future__ import annotations

ARCHES = ('amd64', 'arm64', '386')
OSES = ('linux', 'windows')
FORMATS = {
    'linux': ('elf', 'shellcode', 'stager'),
    'windows': ('exe', 'dll', 'shellcode', 'stager'),
}
TLS_PROFILES = ('go', 'chrome', 'firefox', 'safari')
SLEEP_MASKS = ('', 'none', 'rc4', 'aes-ctr', 'cronos', 'hwbp')
SYSCALL_METHODS = ('direct', 'indirect')
INJECT_METHODS = ('default', 'apc', 'threadpool', 'fiber', 'callback')
JUMP_METHODS = ('psexec', 'winrm', 'wmi', 'scshell')
PERSISTENCE = ('systemd', 'cron', 'profile', 'registry', 'task',
               'service')
EVASION_BOOLS = (
    'antisanbox', 'amsi_bypass', 'etw_patch', 'unhook', 'stomp',
    'stack_spoof', 'string_obfuscation', 'garble', 'upx',
    'ppid_spoof', 'antidebug', 'antivm', 'verbose',
)

# Fields each transport needs beyond the shared target block.
_TRANSPORT_FIELDS = {
    'http': ['url', 'tls_profile', 'c2_profile',
             'transport_failover_after'],
    'quic': ['url', 'tls_profile', 'c2_profile'],
    'websocket': ['url', 'tls_profile', 'c2_profile'],
    'dns': ['dns_domain', 'dns_resolver', 'c2_profile'],
    'doh': ['dns_domain', 'doh_resolver', 'doh_host_header',
            'doh_user_agent', 'c2_profile'],
    'icmp': ['icmp_host', 'c2_profile'],
    'smb': ['smb_pipe', 'pivot_key_path'],
    'tcp': ['tcp_bind_addr', 'tcp_bind_token', 'pivot_key_path'],
    'tcprev': ['tcp_rev_target', 'tcp_rev_token', 'pivot_key_path'],
    'wireguard': ['wireguard_server_pubkey', 'wireguard_server_addr',
                  'wireguard_agent_privkey', 'wireguard_tunnel_ip',
                  'wireguard_server_tunnel_ip', 'wireguard_inner_port'],
}

TRANSPORTS = [
    {'id': 'http', 'label': 'HTTP', 'platforms': ['linux', 'windows'],
     'exclusive': False, 'fields': _TRANSPORT_FIELDS['http'],
     'description': 'HTTPS + JSON; the default pull transport.'},
    {'id': 'quic', 'label': 'QUIC', 'platforms': ['linux', 'windows'],
     'exclusive': True, 'fields': _TRANSPORT_FIELDS['quic'],
     'description': 'HTTP/3 over UDP; cannot combine in this version.'},
    {'id': 'websocket', 'label': 'WebSocket',
     'platforms': ['linux', 'windows'], 'exclusive': True,
     'fields': _TRANSPORT_FIELDS['websocket'],
     'description': 'wss:// transport; not available as a DLL.'},
    {'id': 'dns', 'label': 'DNS', 'platforms': ['linux', 'windows'],
     'exclusive': False, 'fields': _TRANSPORT_FIELDS['dns'],
     'description': 'DNS TXT; needs an authoritative zone.'},
    {'id': 'doh', 'label': 'DoH', 'platforms': ['linux', 'windows'],
     'exclusive': False, 'fields': _TRANSPORT_FIELDS['doh'],
     'description': 'DNS over HTTPS; needs a zone and resolver.'},
    {'id': 'icmp', 'label': 'ICMP', 'platforms': ['linux'],
     'exclusive': False, 'fields': _TRANSPORT_FIELDS['icmp'],
     'description': 'ICMP echo; Linux only, CAP_NET_RAW.'},
    {'id': 'smb', 'label': 'SMB', 'platforms': ['windows'],
     'exclusive': True, 'fields': _TRANSPORT_FIELDS['smb'],
     'description': 'Named-pipe pivot child; Windows only.'},
    {'id': 'tcp', 'label': 'TCP bind', 'platforms': ['linux', 'windows'],
     'exclusive': True, 'fields': _TRANSPORT_FIELDS['tcp'],
     'description': 'Inbound TCP pivot child.'},
    {'id': 'tcprev', 'label': 'TCP reverse',
     'platforms': ['linux', 'windows'], 'exclusive': True,
     'fields': _TRANSPORT_FIELDS['tcprev'],
     'description': 'Outbound TCP pivot child to a listening parent.'},
    {'id': 'wireguard', 'label': 'WireGuard',
     'platforms': ['linux', 'windows'], 'exclusive': True,
     'fields': _TRANSPORT_FIELDS['wireguard'],
     'description': 'WireGuard UDP tunnel; exclusive in this version.'},
]
BY_ID = {t['id']: t for t in TRANSPORTS}
MODES = tuple(BY_ID)

# Parent-side relay fields, valid on any non-pivot transport.
RELAY_FIELDS = ('smb_relay_pipe', 'tcp_relay_target',
                'tcp_relay_token', 'tcp_rev_listen', 'tcp_rev_token')

FIELD_TYPES = {
    'url': 'url', 'tls_profile': 'choice', 'c2_profile': 'profile',
    'transport_failover_after': 'int', 'dns_domain': 'text',
    'dns_resolver': 'text', 'doh_resolver': 'url',
    'doh_host_header': 'text', 'doh_user_agent': 'text',
    'icmp_host': 'ipv4', 'smb_pipe': 'text',
    'pivot_key_path': 'server_path', 'tcp_bind_addr': 'hostport',
    'tcp_bind_token': 'hex64', 'tcp_rev_target': 'hostport',
    'tcp_rev_token': 'hex64', 'wireguard_server_pubkey': 'base64',
    'wireguard_server_addr': 'hostport',
    'wireguard_agent_privkey': 'base64',
    'wireguard_tunnel_ip': 'ipv4',
    'wireguard_server_tunnel_ip': 'ipv4',
    'wireguard_inner_port': 'port',
    'smb_relay_pipe': 'pipe', 'tcp_relay_target': 'hostport',
    'tcp_relay_token': 'hex64', 'tcp_rev_listen': 'hostport',
}


def _e(field: str, message: str) -> dict:
    return {'field': field, 'message': message}


def _modes(spec: dict) -> list[str]:
    raw = spec.get('transport_mode')
    if raw is None:
        raw = spec.get('transport') or 'http'
    return [m.strip().lower() for m in str(raw).split(',') if m.strip()]


def _is_hex64(value) -> bool:
    value = str(value or '')
    if len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
        return True
    except ValueError:
        return False


def _is_ipv4(value) -> bool:
    parts = str(value or '').split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return False
    return True


def _has_colon(value) -> bool:
    return ':' in str(value or '')


def normalize(spec: dict) -> dict:
    """Return a copy with modes, opsec defaults and types normalized."""
    if not isinstance(spec, dict):
        raise ValueError('build spec must be an object')
    out = dict(spec)
    modes = _modes(out)
    out['transport_mode'] = ','.join(modes) if modes else 'http'
    out.setdefault('target_os', 'linux')
    out.setdefault('target_arch', 'amd64')
    out.setdefault(
        'output_format',
        'exe' if out['target_os'] == 'windows' else 'elf')
    out.setdefault('transport_failover_after', 3)
    try:
        out['kill_days'] = int(out.get('kill_days', 30))
    except (TypeError, ValueError):
        out['kill_days'] = 30
    try:
        out['transport_failover_after'] = max(
            0, int(out['transport_failover_after']))
    except (TypeError, ValueError):
        out['transport_failover_after'] = 3
    out.setdefault('tls_profile', 'go')
    out.setdefault('sleep_mask', 'none')
    out.setdefault('syscall_method', 'direct')
    out.setdefault('inject_method', 'default')
    out.setdefault('opsec_profile', 'default')
    return out


def validate(spec: dict, *, remote: bool = False) -> list[dict]:
    """Return every field error. Empty means the build is acceptable.

    Path existence is the caller's job (the loader has the server
    roots); this covers shape and cross-field rules.
    """
    if not isinstance(spec, dict):
        return [_e('', 'spec must be an object')]
    errors: list[dict] = []

    def bad(field, message):
        errors.append(_e(field, message))

    modes = _modes(spec)
    if not modes:
        bad('transport_mode', 'transport_mode is empty')
    for mode in modes:
        if mode not in MODES:
            bad('transport_mode',
                f'unknown transport {mode!r}; valid: {", ".join(MODES)}')
    if len(set(modes)) != len(modes):
        bad('transport_mode', 'duplicate transport mode')

    exclusive = [m for m in modes if m in BY_ID and BY_ID[m]['exclusive']]
    if exclusive and len(modes) > 1:
        bad('transport_mode',
            f"{exclusive[0]!r} cannot be combined with other transports")

    os_name = spec.get('target_os') or 'linux'
    if os_name not in OSES:
        bad('target_os', f'unsupported target_os {os_name!r}')
    arch = spec.get('target_arch') or 'amd64'
    if arch not in ARCHES:
        bad('target_arch', f'unsupported target_arch {arch!r}')
    fmt = spec.get('output_format') or (
        'exe' if os_name == 'windows' else 'elf')
    allowed_formats = FORMATS.get(os_name, ())
    if fmt not in allowed_formats:
        bad('output_format',
            f'{fmt!r} is not valid for target_os={os_name!r}')

    for mode in modes:
        t = BY_ID.get(mode)
        if t and os_name not in t['platforms']:
            bad('transport_mode',
                f'{mode!r} is not supported on {os_name!r}')

    url = str(spec.get('url') or '')
    if ('http' in modes or 'quic' in modes or 'websocket' in modes) \
            and not url:
        bad('url', 'url is required for this transport')
    if url and not url.startswith(('https://', 'http://')):
        bad('url', 'url must start with https:// (or http://)')

    if 'smb' in modes:
        if os_name != 'windows':
            bad('target_os', "transport_mode 'smb' requires windows")
        pipe = str(spec.get('smb_pipe') or '').strip()
        if not pipe:
            bad('smb_pipe', 'smb_pipe is required')
        elif pipe.startswith('\\\\'):
            if '\\pipe\\' not in pipe:
                bad('smb_pipe',
                    'UNC pipe must contain \\pipe\\')
        else:
            for ch in pipe:
                if not (ch.isalnum() or ch in '._-'):
                    bad('smb_pipe',
                        'bare pipe may use only letters, digits, . _ -')
                    break

    relay_pipe = str(spec.get('smb_relay_pipe') or '').strip()
    if relay_pipe and not all(
            c.isalnum() or c in '._-' for c in relay_pipe):
        bad('smb_relay_pipe', 'invalid parent relay pipe')

    if 'tcp' in modes:
        if not str(spec.get('tcp_bind_addr') or '').strip():
            bad('tcp_bind_addr', 'tcp_bind_addr is required')
        elif not _has_colon(spec.get('tcp_bind_addr')):
            bad('tcp_bind_addr', 'tcp_bind_addr must be host:port')
        if not _is_hex64(spec.get('tcp_bind_token')):
            bad('tcp_bind_token', 'tcp_bind_token must be 64 hex chars')

    if 'tcprev' in modes:
        if not str(spec.get('tcp_rev_target') or '').strip():
            bad('tcp_rev_target', 'tcp_rev_target is required')
        elif not _has_colon(spec.get('tcp_rev_target')):
            bad('tcp_rev_target', 'tcp_rev_target must be host:port')
        if not _is_hex64(spec.get('tcp_rev_token')):
            bad('tcp_rev_token', 'tcp_rev_token must be 64 hex chars')

    relay_target = str(spec.get('tcp_relay_target') or '').strip()
    relay_token = str(spec.get('tcp_relay_token') or '').strip()
    if relay_target and not relay_token:
        bad('tcp_relay_token',
            'tcp_relay_target requires tcp_relay_token')
    if relay_token and not _is_hex64(relay_token):
        bad('tcp_relay_token', 'tcp_relay_token must be 64 hex chars')
    if relay_target and not _has_colon(relay_target):
        bad('tcp_relay_target', 'tcp_relay_target must be host:port')

    rev_listen = str(spec.get('tcp_rev_listen') or '').strip()
    if rev_listen:
        if not _has_colon(rev_listen):
            bad('tcp_rev_listen', 'tcp_rev_listen must be host:port')
        if not _is_hex64(spec.get('tcp_rev_token')):
            bad('tcp_rev_token',
                'tcp_rev_listen requires a 64-hex tcp_rev_token')

    is_parent = bool(relay_pipe or relay_target or rev_listen)
    is_child = any(m in modes for m in ('smb', 'tcp', 'tcprev'))
    if is_parent and is_child:
        bad('transport_mode',
            'a pivot child cannot also carry parent relay fields')
    if (is_parent or is_child) and not str(
            spec.get('pivot_key_path') or '').strip():
        bad('pivot_key_path', 'pivot_key_path is required for pivots')

    if 'websocket' in modes:
        if os_name == 'windows' and fmt == 'dll':
            bad('output_format',
                'websocket is not supported for a Windows DLL')
        if not url:
            bad('url', 'websocket requires a URL')

    if 'wireguard' in modes:
        for field, label in (
                ('wireguard_server_pubkey', 'server public key'),
                ('wireguard_server_addr', 'server UDP address'),
                ('wireguard_agent_privkey', 'agent private key'),
                ('wireguard_tunnel_ip', 'tunnel IP')):
            if not str(spec.get(field) or '').strip():
                bad(field, f'{label} is required')
        if not _has_colon(spec.get('wireguard_server_addr')):
            bad('wireguard_server_addr',
                'wireguard_server_addr must be host:port')
        if spec.get('wireguard_tunnel_ip') and not _is_ipv4(
                spec.get('wireguard_tunnel_ip')):
            bad('wireguard_tunnel_ip', 'must be a dotted-quad IPv4')

    if 'dns' in modes or 'doh' in modes:
        if not str(spec.get('dns_domain') or '').strip():
            bad('dns_domain',
                'dns_domain is required for dns/doh')
    doh = str(spec.get('doh_resolver') or '').strip()
    if doh and not doh.startswith('https://'):
        bad('doh_resolver', 'doh_resolver must be an https:// URL')

    if 'icmp' in modes:
        if os_name == 'windows':
            bad('target_os', "transport_mode 'icmp' is not supported "
                              "on Windows")
        if not _is_ipv4(spec.get('icmp_host')):
            bad('icmp_host', 'icmp_host must be a dotted-quad IPv4')

    if fmt == 'stager':
        if spec.get('use_mtls') or (
                isinstance(spec.get('mtls'), dict)
                and spec['mtls'].get('enabled')):
            bad('output_format', 'a stager cannot use mTLS')
        if modes != ['http']:
            bad('transport_mode', "a stager requires transport_mode "
                                  "'http' only")
        if not url.startswith('https://'):
            bad('url', 'a stager requires an https:// URL')
        if not str(spec.get('stage_name') or '').strip():
            bad('stage_name', 'stage_name is required for a stager')

    tls = spec.get('tls_profile') or 'go'
    if tls not in TLS_PROFILES:
        bad('tls_profile', f'tls_profile must be one of '
                           f'{", ".join(TLS_PROFILES)}')

    sleep = spec.get('sleep_mask', 'none')
    if sleep not in SLEEP_MASKS:
        bad('sleep_mask', 'invalid sleep mask')
    elif sleep in ('cronos', 'hwbp'):
        if os_name != 'windows':
            bad('sleep_mask', f'{sleep!r} is Windows-only')
        if arch != 'amd64':
            bad('sleep_mask', f'{sleep!r} requires amd64')

    syscall = spec.get('syscall_method', 'direct')
    if syscall not in SYSCALL_METHODS:
        bad('syscall_method', 'syscall_method must be direct or indirect')
    elif syscall == 'indirect' and os_name != 'windows':
        bad('syscall_method', 'indirect is Windows-only')

    inject_method = str(
        spec.get('inject_method') or 'default').lower()
    if inject_method not in INJECT_METHODS:
        bad('inject_method', 'invalid inject_method')
    elif inject_method in ('threadpool', 'fiber', 'callback'):
        bad('inject_method',
            f'{inject_method!r} is not usable for migrate yet')
    elif inject_method == 'apc':
        if os_name != 'windows' or not spec.get('inject'):
            bad('inject_method',
                'apc requires Windows and inject=true')

    if spec.get('inject'):
        if os_name == 'windows' and fmt not in ('exe', 'shellcode'):
            bad('output_format',
                'inject requires exe or shellcode on Windows')
        elif os_name == 'linux' and fmt != 'elf':
            bad('output_format', 'inject requires elf on Linux')

    for jm in str(spec.get('jump_methods') or '').split(','):
        jm = jm.strip()
        if jm and jm not in JUMP_METHODS:
            bad('jump_methods', f'unknown jump method {jm!r}')
    for pm in str(spec.get('persistence') or '').split(','):
        pm = pm.strip()
        if pm and pm not in PERSISTENCE:
            bad('persistence', f'unknown persistence method {pm!r}')

    if remote and spec.get('c2_profile') and (
            '/' in spec['c2_profile'] or '\\' in spec['c2_profile']):
        bad('c2_profile', 'c2_profile must be a name, not a path')

    return errors


def first_error(spec: dict, **kw) -> str | None:
    errors = validate(spec, **kw)
    if not errors:
        return None
    return f"{errors[0]['field']}: {errors[0]['message']}"


def descriptor() -> dict:
    """Machine-readable form contract for the Agent Builder."""
    fields = []
    for transport in TRANSPORTS:
        for name in transport['fields']:
            fields.append({
                'name': name,
                'type': FIELD_TYPES.get(name, 'text'),
                'required': name in (
                    'url', 'dns_domain', 'icmp_host', 'smb_pipe',
                    'tcp_bind_addr', 'tcp_bind_token',
                    'tcp_rev_target', 'tcp_rev_token',
                    'wireguard_server_pubkey',
                    'wireguard_server_addr',
                    'wireguard_agent_privkey', 'wireguard_tunnel_ip'),
            })
    seen, unique = set(), []
    for field in fields:
        if field['name'] in seen:
            continue
        seen.add(field['name'])
        unique.append(field)
    return {
        'version': 1,
        'oses': list(OSES),
        'arches': list(ARCHES),
        'formats': {k: list(v) for k, v in FORMATS.items()},
        'transports': [dict(t) for t in TRANSPORTS],
        'relay_fields': list(RELAY_FIELDS),
        'fields': unique,
        'tls_profiles': list(TLS_PROFILES),
        'sleep_masks': list(SLEEP_MASKS),
        'syscall_methods': list(SYSCALL_METHODS),
        'inject_methods': list(INJECT_METHODS),
        'jump_methods': list(JUMP_METHODS),
        'persistence': list(PERSISTENCE),
        'evasion': list(EVASION_BOOLS),
        'defaults': {
            'target_os': 'linux',
            'target_arch': 'amd64',
            'output_format': 'elf',
            'transport_mode': 'http',
            'kill_days': 30,
            'work_hours_start': '08:00',
            'work_hours_end': '19:00',
            'tls_profile': 'go',
            'sleep_mask': 'none',
            'syscall_method': 'direct',
            'inject_method': 'default',
        },
    }
