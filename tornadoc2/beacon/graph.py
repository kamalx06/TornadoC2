"""Session graph.

Builds a view of which beacons share attributes — same user, same
domain, same subnet — so the operator can see the shape of the
engagement at a glance. The graph is derived, not stored: it is
recomputed on every request from the current session registry.

Three render modes:

  tree     — grouped by domain then user (the original view)
  flat     — one line per beacon, tag-column format for grep
  summary  — counts only, grouped by each attribute kind

A `find_path` helper answers "how are #1001 and #1005 connected?"
by walking the shared-attribute edges.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple


def _identity(s) -> dict:
    return s.identity or {}


def _domain(s) -> str:
    ident = _identity(s)
    return (ident.get('domain') or
            ident.get('userdomain') or '').upper()


def _user(s) -> str:
    ident = _identity(s)
    return (ident.get('username') or '').lower()


import ipaddress


def _subnet(s) -> str:
    """Return the /24 (IPv4) or /64 prefix (IPv6) of last_addr.

    Uses ipaddress so compressed forms, scope ids, and the various
    zero-run spellings all collapse to the same network. The manual
    split on ':' that this replaces handled only the fully-expanded
    form, which no operator or router writes.
    """
    addr = s.last_addr or ''
    if not addr:
        return ''
    if '%' in addr:
        addr = addr.split('%', 1)[0]
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return addr
    prefix = 64 if isinstance(ip, ipaddress.IPv6Address) else 24
    net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    return str(net)


def _ports(s) -> str:
    """Listening ports the beacon has reported, if any. Empty when
    the identity does not carry them."""
    ident = _identity(s)
    ports = ident.get('listen_ports') or ident.get('ports') or []
    if not ports:
        return ''
    if isinstance(ports, str):
        return ports
    try:
        return ','.join(str(int(p)) for p in sorted(ports))
    except Exception:
        return ','.join(str(p) for p in ports)


class Graph:

    def __init__(self, engine):
        self.engine = engine

    # ------------------------------------------------------------------
    # Data model

    def build(self) -> dict:
        """Return {'nodes': [...], 'edges': [...], 'groups': {...},
        'generated': <epoch>}.

        Nodes carry the beacon's id, display name, os, arch, user,
        domain, subnet, ports, alive flag, last-seen age, and the
        fingerprint. Edges connect beacons that share at least one
        attribute and are labelled with the shared keys.
        """
        import time
        sessions = list(self.engine.list_all())
        nodes: List[dict] = []
        for s in sessions:
            nodes.append({
                'id':          s.id,
                'name':        s.display_name,
                'os':          _identity(s).get('os', '?'),
                'arch':        _identity(s).get('arch', ''),
                'user':        _user(s),
                'domain':      _domain(s),
                'subnet':      _subnet(s),
                'ports':       _ports(s),
                'alive':       s.alive,
                'age':         s.age,
                'checkins':    s.checkins,
                'fingerprint': s.fingerprint,
            })

        edges: List[dict] = []
        for i in range(len(nodes)):
            for j in range(i + 1, len(nodes)):
                a, b = nodes[i], nodes[j]
                shared = []
                if a['user'] and a['user'] == b['user']:
                    shared.append(f"user={a['user']}")
                if a['domain'] and a['domain'] == b['domain']:
                    shared.append(f"domain={a['domain']}")
                if a['subnet'] and a['subnet'] == b['subnet']:
                    shared.append(f"subnet={a['subnet']}")
                if shared:
                    edges.append({
                        'from': a['id'], 'to': b['id'],
                        'shared': shared,
                    })

        groups = {'user': {}, 'domain': {}, 'subnet': {}}
        for n in nodes:
            for key in groups:
                v = n.get(key) or ''
                if v:
                    groups[key].setdefault(v, []).append(n['id'])

        return {
            'nodes':     nodes,
            'edges':     edges,
            'groups':    groups,
            'generated': time.time(),
        }

    # ------------------------------------------------------------------
    # Path finding

    def find_path(self, src_id: int, dst_id: int) -> Optional[List[int]]:
        """Return the shortest path through shared-attribute edges,
        or None if no path exists.

        A beacon that shares nothing with any other beacon has no
        edges and is therefore unreachable from any other. The
        returned list includes both endpoints.
        """
        g = self.build()
        if src_id == dst_id:
            return [src_id]

        adj: Dict[int, Set[int]] = defaultdict(set)
        for e in g['edges']:
            adj[e['from']].add(e['to'])
            adj[e['to']].add(e['from'])

        seen = {src_id}
        q: deque = deque([(src_id, [src_id])])
        while q:
            cur, path = q.popleft()
            for nxt in adj.get(cur, ()):
                if nxt == dst_id:
                    return path + [nxt]
                if nxt not in seen:
                    seen.add(nxt)
                    q.append((nxt, path + [nxt]))
        return None

    # ------------------------------------------------------------------
    # Rendering

    def render_ascii(self, colors: dict, mode: str = 'tree') -> str:
        """Render the graph. `mode` is one of 'tree', 'flat',
        'summary'."""
        if mode == 'flat':
            return self._render_flat(colors)
        if mode == 'summary':
            return self._render_summary(colors)
        return self._render_tree(colors)

    def _render_tree(self, c: dict) -> str:
        """The original grouped view. Domain → user → beacon."""
        g = self.build()
        if not g['nodes']:
            return f"{c['dim']}no beacons{c['end']}"

        out = [f"{c['cyan']}SESSION GRAPH{c['end']}"]
        by_domain: Dict[str, List[dict]] = {}
        for n in g['nodes']:
            dom = n['domain'] or '(no domain)'
            by_domain.setdefault(dom, []).append(n)

        for dom in sorted(by_domain):
            out.append('')
            out.append(f"  {c['bold']}{dom}{c['end']}")
            by_user: Dict[str, List[dict]] = {}
            for n in by_domain[dom]:
                u = n['user'] or '(unknown)'
                by_user.setdefault(u, []).append(n)
            for u in sorted(by_user):
                out.append(f"    {c['green']}{u}{c['end']}")
                for n in sorted(by_user[u], key=lambda x: x['id']):
                    mark = (f"{c['green']}●{c['end']}" if n['alive']
                            else f"{c['red']}○{c['end']}")
                    ports = (f" {c['dim']}ports={n['ports']}{c['end']}"
                             if n['ports'] else '')
                    out.append(
                        f"      {mark} "
                        f"{c['cyan']}#{n['id']}{c['end']} "
                        f"{n['name']} "
                        f"{c['dim']}[{n['os']}/{n['arch']}] "
                        f"{n['subnet']} "
                        f"age={n['age']}s"
                        f"{c['end']}{ports}")

        if g['edges']:
            out.append('')
            out.append(f"  {c['dim']}shared attributes:{c['end']}")
            for e in g['edges']:
                out.append(
                    f"    {c['dim']}#{e['from']} ↔ #{e['to']}: "
                    f"{', '.join(e['shared'])}{c['end']}")

        return '\n'.join(out)

    def _render_flat(self, c: dict) -> str:
        """One beacon per line, pipe-separated, for grep / awk.

        Format:
          <id> | <name> | <os>/<arch> | <user>@<domain> | <subnet> | <alive> | <age>s
        """
        g = self.build()
        if not g['nodes']:
            return f"{c['dim']}no beacons{c['end']}"
        out = [f"{c['cyan']}SESSION GRAPH (flat){c['end']}"]
        for n in sorted(g['nodes'], key=lambda x: x['id']):
            mark = (f"{c['green']}●{c['end']}" if n['alive']
                    else f"{c['red']}○{c['end']}")
            dom = n['domain'] or '-'
            user = n['user'] or '-'
            subnet = n['subnet'] or '-'
            out.append(
                f"  {mark} {n['id']:<5} "
                f"{n['name']:<24} "
                f"{n['os']}/{n['arch']:<8} "
                f"{user}@{dom:<16} "
                f"{subnet:<18} "
                f"{n['age']}s"
            )
        return '\n'.join(out)

    def _render_summary(self, c: dict) -> str:
        """Counts only. Fast when the engagement has dozens of
        beacons and the operator just wants the shape."""
        g = self.build()
        if not g['nodes']:
            return f"{c['dim']}no beacons{c['end']}"

        alive = sum(1 for n in g['nodes'] if n['alive'])
        dead = len(g['nodes']) - alive

        out = [
            f"{c['cyan']}SESSION GRAPH (summary){c['end']}",
            '',
            f"  {c['bold']}{len(g['nodes'])}{c['end']} beacons "
            f"({c['green']}{alive} alive{c['end']}, "
            f"{c['red']}{dead} stale{c['end']})",
        ]

        for kind in ('domain', 'user', 'subnet'):
            entries = g['groups'].get(kind) or {}
            if not entries:
                continue
            out.append('')
            out.append(f"  {c['bold']}by {kind}{c['end']}")
            for value in sorted(entries):
                ids = entries[value]
                out.append(
                    f"    {c['cyan']}{value:<24}{c['end']} "
                    f"{len(ids):>2} beacon(s)  "
                    f"{c['dim']}#{', #'.join(str(i) for i in ids)}"
                    f"{c['end']}"
                )

        return '\n'.join(out)

    # ------------------------------------------------------------------
    # JSON view (for the HTML export and for scripts)

    def to_json(self) -> dict:
        """Return the raw graph dict. Same as build() but with a
        stable, documented shape so the export and any external
        consumer can depend on it."""
        return self.build()