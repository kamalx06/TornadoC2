#!/usr/bin/env python3
"""Generate a hardened redirector config for a listener.

Three targets:

  nginx --tls passthrough   L4 stream proxy, SNI allowlist (no cert)
  nginx --tls terminate     L7 proxy, Host allowlist, TLS termination
  caddy --tls terminate     L7 proxy, Host allowlist
  cloudflare                Worker script, Host allowlist

The upstream is the team server listener. TLS is bring-your-own: a
terminating redirector needs `--cert/--key`, a passthrough one does
not. Unknown hosts get 421 (nginx/caddy) or 421 from the Worker, so
scanning the IP directly does not reveal the listener.

`--check` runs the native validator when it is installed.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys


def _hosts(values):
    out = []
    for v in values:
        for part in v.split(','):
            part = part.strip().lower()
            if part:
                out.append(part)
    if not out:
        raise SystemExit('at least one --host is required')
    for h in out:
        if '/' in h or ' ' in h:
            raise SystemExit(f'bad host {h!r}')
    return out


def nginx_passthrough(hosts, upstream, port=443):
    host = upstream.split('//', 1)[-1].split(':')[0]
    up_port = upstream.rsplit(':', 1)[-1] if ':' in upstream else '443'
    snis = ' '.join(hosts)
    return f"""# TornadoC2 redirector — nginx stream, TLS passthrough
# Unknown SNI is dropped before a handshake reaches the listener.
stream {{
    map $ssl_preread_server_name $t2_backend {{
        {snis}  {host}:{up_port};
        default              127.0.0.1:1;
    }}
    server {{
        listen {port};
        proxy_pass $t2_backend;
        ssl_preread on;
        proxy_connect_timeout 5s;
        proxy_timeout 300s;
    }}
}}
"""


def nginx_terminate(hosts, upstream, cert, key):
    names = ' '.join(hosts)
    return f"""# TornadoC2 redirector — nginx, TLS termination
server {{
    listen 443 ssl;
    http2 on;
    server_name {names};
    server_tokens off;

    ssl_certificate     {cert};
    ssl_certificate_key {key};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    add_header Strict-Transport-Security "max-age=31536000" always;

    location / {{
        proxy_pass {upstream};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_connect_timeout 5s;
        proxy_read_timeout 300s;
        proxy_buffering off;
    }}
}}

server {{
    listen 443 ssl default_server;
    server_name _;
    ssl_certificate     {cert};
    ssl_certificate_key {key};
    return 421;
}}
"""


def caddy(hosts, upstream, cert, key):
    names = ', '.join(hosts)
    return f"""# TornadoC2 redirector — Caddy, TLS termination
{{
    servers {{
        protocols h1 h2
    }}
}}

{names} {{
    tls {cert} {key}
    reverse_proxy {upstream} {{
        header_up Host {{host}}
        transport http {{
            read_timeout 300s
            dial_timeout 5s
        }}
    }}
    header Strict-Transport-Security "max-age=31536000"
}}

:443 {{
    tls {cert} {key}
    respond 421
}}
"""


def cloudflare(hosts, upstream):
    allow = ', '.join(repr(h) for h in hosts)
    host = upstream.split('//', 1)[-1]
    return f"""// TornadoC2 redirector — Cloudflare Worker
// Deploy, then bind the route for each host below.
const ALLOW = new Set([{allow}]);
const UPSTREAM = 'https://{host}';

export default {{
  async fetch(req) {{
    const host = (req.headers.get('Host') || '').toLowerCase();
    if (!ALLOW.has(host)) {{
      return new Response('unknown host', {{ status: 421 }});
    }}
    const url = new URL(req.url);
    url.protocol = 'https:';
    url.host = UPSTREAM.replace('https://', '');
    return fetch(new Request(url, req));
  }}
}};
"""


def render(kind, tls, hosts, upstream, cert='', key=''):
    if kind == 'nginx':
        if tls == 'passthrough':
            return nginx_passthrough(hosts, upstream)
        return nginx_terminate(hosts, upstream, cert or '/etc/ssl/c2.pem',
                               key or '/etc/ssl/c2.key')
    if kind == 'caddy':
        return caddy(hosts, upstream, cert or '/etc/ssl/c2.pem',
                     key or '/etc/ssl/c2.key')
    return cloudflare(hosts, upstream)


def check(kind, text):
    exe = {'nginx': 'nginx', 'caddy': 'caddy'}.get(kind)
    if not exe or shutil.which(exe) is None:
        return f'{exe or kind}: validator not on PATH'
    import tempfile
    suffix = '.conf' if exe == 'nginx' else 'Caddyfile'
    with tempfile.NamedTemporaryFile('w', suffix=suffix,
                                     delete=False) as fh:
        fh.write(text)
        path = fh.name
    try:
        if exe == 'nginx':
            cmd = ['nginx', '-t', '-c', path]
        else:
            cmd = ['caddy', 'validate', '--config', path,
                   '--adapter', 'caddyfile']
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            return (res.stderr or res.stdout).strip() or 'invalid'
        return 'ok'
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--kind', required=True,
                    choices=('nginx', 'caddy', 'cloudflare'))
    ap.add_argument('--tls', default='passthrough',
                    choices=('passthrough', 'terminate'))
    ap.add_argument('--host', action='append', default=[],
                    help='allowed hostname (repeat or comma-separate)')
    ap.add_argument('--upstream', required=True,
                    help='https://host:port of the listener')
    ap.add_argument('--cert', default='')
    ap.add_argument('--key', default='')
    ap.add_argument('--out', default='-')
    ap.add_argument('--check', action='store_true')
    args = ap.parse_args(argv)

    if not args.upstream.startswith('https://'):
        raise SystemExit('--upstream must be https://')
    if args.tls == 'terminate' and args.kind != 'cloudflare' \
            and not (args.cert and args.key):
        raise SystemExit('termination needs --cert and --key')
    if args.tls == 'passthrough' and args.kind == 'caddy':
        raise SystemExit('caddy requires --tls terminate')

    text = render(args.kind, args.tls, _hosts(args.host),
                  args.upstream, args.cert, args.key)
    if args.out == '-':
        sys.stdout.write(text)
    else:
        with open(args.out, 'w', encoding='utf-8') as fh:
            fh.write(text)
        os.chmod(args.out, 0o600)
        print(f'wrote {args.out}')
    if args.check:
        print(f'check: {check(args.kind, text)}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
