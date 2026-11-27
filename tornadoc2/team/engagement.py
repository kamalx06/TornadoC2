"""Engagement data model and report builder.

Hosts are observed from live sessions; users, shares, services,
findings, evidence and timeline entries are operator or event
supplied. The file is evidence-adjacent state, not authoritative
beacon state.

The store is versioned. ``SCHEMA`` is bumped on a forward migration
and older files are upgraded on load; a newer file is refused rather
than truncated.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import threading
import time

from . import atrest

SCHEMA = 2

MAX_HOSTS = 50_000
MAX_FINDINGS = 10_000
MAX_TIMELINE = 50_000
MAX_USERS = 20_000
MAX_SHARES = 20_000
MAX_SERVICES = 20_000
MAX_EVIDENCE = 20_000
FLUSH_SECONDS = 10.0

# Timeline kinds that map to an ATT&CK technique.
MITRE = {
    'jump': ('Lateral Movement', 'T1021'),
    'jump.psexec': ('Lateral Movement', 'T1021.002'),
    'jump.winrm': ('Lateral Movement', 'T1021.006'),
    'jump.wmi': ('Execution', 'T1047'),
    'persist': ('Persistence', 'T1543'),
    'persist.registry': ('Persistence', 'T1547.001'),
    'persist.task': ('Persistence', 'T1053.005'),
    'persist.service': ('Persistence', 'T1543.003'),
    'persist.cron': ('Persistence', 'T1053.003'),
    'persist.systemd': ('Persistence', 'T1543.002'),
    'stomp': ('Defense Evasion', 'T1055'),
    'unhook': ('Defense Evasion', 'T1562.001'),
    'update': ('Persistence', 'T1105'),
    'creds': ('Credential Access', 'T1003'),
    'finding': ('Discovery', 'T1082'),
}


class SchemaError(RuntimeError):
    pass


def _csv_safe(v) -> str:
    """Neutralise spreadsheet formula injection."""
    text = '' if v is None else str(v)
    if text[:1] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + text
    return text


def _md(v) -> str:
    """One-line, table-safe Markdown."""
    text = '' if v is None else str(v)
    text = text.replace('\r', ' ').replace('\n', ' ')
    for ch in ('\\', '|', '`'):
        text = text.replace(ch, '\\' + ch)
    return text[:500]


def _stix_pattern(kind: str, value: str) -> str:
    esc = value.replace("\\", "\\\\").replace("'", "\\'")
    if kind == 'sha256':
        return f"file:hashes.'SHA-256' = '{esc}'"
    if kind == 'account':
        return f"user-account:account_login = '{esc}'"
    if kind == 'share':
        return f"directory:path = '{esc}'"
    if kind == 'service':
        return f"software:name = '{esc}'"
    return f"domain-name:value = '{esc}'"


class Engagement:
    MAX_HOSTS = MAX_HOSTS
    MAX_FINDINGS = MAX_FINDINGS
    MAX_TIMELINE = MAX_TIMELINE
    FLUSH_SECONDS = FLUSH_SECONDS

    def __init__(self, path='logs/engagement.json'):
        self.path = path
        self._lock = threading.RLock()
        self._dirty = False
        self._last_save = 0.0
        self._data = self._blank()
        self._load()

    @staticmethod
    def _blank() -> dict:
        return {'schema': SCHEMA, 'hosts': {}, 'findings': [],
                'timeline': [], 'users': [], 'shares': [],
                'services': [], 'evidence': []}

    # ------------------------------------------------------------------
    # Persistence and schema

    def _load(self):
        try:
            raw = atrest.load_json(self.path, {})
        except (OSError, ValueError) as exc:
            import sys as _sys
            print(f"[ENGAGEMENT] {self.path} unreadable: {exc}; "
                  f"kept aside as .corrupt", file=_sys.stderr)
            try:
                if not os.path.exists(self.path + '.corrupt'):
                    os.replace(self.path, self.path + '.corrupt')
            except OSError:
                pass
            return
        if not isinstance(raw, dict):
            return
        version = int(raw.get('schema') or 1)
        if version > SCHEMA:
            raise SchemaError(
                f'engagement schema {version} is newer than {SCHEMA}')
        data = self._blank()
        for key in data:
            if key == 'schema':
                continue
            got = raw.get(key)
            if isinstance(data[key], dict):
                data[key] = got if isinstance(got, dict) else {}
            else:
                data[key] = got if isinstance(got, list) else []
        self._data = data
        if version < SCHEMA:
            try:
                self._save()
            except OSError:
                pass

    def _save(self):
        atrest.save_json(self.path, self._data)
        self._dirty = False
        self._last_save = time.time()

    def flush(self):
        with self._lock:
            if self._dirty:
                self._save()

    # ------------------------------------------------------------------
    # Hosts (live)

    def observe(self, session):
        self.observe_many([session])

    def observe_many(self, sessions):
        """Record sessions without a write per beacon.

        Called from the beacon broadcast, which runs every few
        seconds. The file is rewritten at most once per
        ``FLUSH_SECONDS``; callers that need durability call
        ``flush()``.
        """
        now = time.time()
        with self._lock:
            hosts = self._data['hosts']
            for session in sessions:
                ident = session.identity or {}
                key = ident.get('machine_id') or f'#{session.id}'
                h = hosts.get(key) or {'machine_id': key,
                                       'first_seen': now}
                h.update({
                    'last_seen': now,
                    'beacon_id': session.id,
                    'hostname': ident.get('hostname', ''),
                    'os': ident.get('os', ''),
                    'arch': ident.get('arch', ''),
                    'user': ident.get('username', ''),
                    'privilege': ident.get('privilege', 'user'),
                    'parent': ident.get('parent_name', ''),
                })
                hosts[key] = h
            if len(hosts) > self.MAX_HOSTS:
                oldest = sorted(hosts.values(),
                                key=lambda x: x.get('last_seen', 0))
                for drop in oldest[:len(hosts) - self.MAX_HOSTS]:
                    hosts.pop(drop['machine_id'], None)
            self._dirty = True
            if now - self._last_save >= self.FLUSH_SECONDS:
                self._save()

    def hosts(self):
        with self._lock:
            return sorted(self._data['hosts'].values(),
                          key=lambda h: h.get('hostname', ''))

    # ------------------------------------------------------------------
    # Entities

    def _append(self, key, cap, row):
        with self._lock:
            rows = self._data[key]
            rows.append(row)
            if len(rows) > cap:
                del rows[:-cap]
            self._save()
            return row

    def _next_id(self, rows) -> int:
        return max((r.get('id', 0) for r in rows), default=0) + 1

    def add_user(self, user, host, kind='local', admin=False,
                 by='system'):
        with self._lock:
            row = {'id': self._next_id(self._data['users']),
                   'ts': time.time(), 'user': user[:256],
                   'host': host[:120], 'kind': kind,
                   'admin': bool(admin), 'by': by}
            self._append('users', MAX_USERS, row)
            self.record('user', f'{user} on {host} ({kind})', by)
            return row

    def add_share(self, name, host, access='read', by='system'):
        with self._lock:
            row = {'id': self._next_id(self._data['shares']),
                   'ts': time.time(), 'name': name[:256],
                   'host': host[:120], 'access': access, 'by': by}
            self._append('shares', MAX_SHARES, row)
            self.record('share', f'{name} on {host} ({access})', by)
            return row

    def add_service(self, name, host, state='running', by='system'):
        with self._lock:
            row = {'id': self._next_id(self._data['services']),
                   'ts': time.time(), 'name': name[:256],
                   'host': host[:120], 'state': state, 'by': by}
            self._append('services', MAX_SERVICES, row)
            self.record('service', f'{name} on {host} ({state})', by)
            return row

    def add_evidence(self, sha256, name, host, detail='',
                     by='system', size=0):
        digest = (sha256 or '').lower()
        if digest and (len(digest) != 64 or any(
                c not in '0123456789abcdef' for c in digest)):
            raise ValueError('evidence sha256 must be 64 hex chars')
        if len(digest) == 64:
            with self._lock:
                for e in self._data['evidence']:
                    if e.get('sha256') == digest:
                        return e
        with self._lock:
            row = {'id': self._next_id(self._data['evidence']),
                   'ts': time.time(), 'sha256': digest,
                   'name': name[:200], 'host': host[:120],
                   'detail': detail[:2000], 'size': int(size),
                   'by': by}
            self._append('evidence', MAX_EVIDENCE, row)
            self.record('evidence',
                        f'{name} on {host} sha256={digest[:16]}…', by)
            return row

    def entities(self) -> dict:
        with self._lock:
            return {k: list(self._data[k]) for k in
                    ('users', 'shares', 'services', 'evidence')}

    # ------------------------------------------------------------------
    # Findings and timeline

    def add_finding(self, title, severity, host, detail, by,
                    evidence=None):
        with self._lock:
            row = {'id': self._next_id(self._data['findings']),
                   'ts': time.time(), 'title': title,
                   'severity': severity, 'host': host,
                   'detail': detail, 'by': by,
                   'evidence': list(evidence or [])}
            self._append('findings', self.MAX_FINDINGS, row)
            self.record('finding', f'[{severity}] {title} on {host}',
                        by)
            return row

    def findings(self):
        with self._lock:
            return list(self._data['findings'])

    def record(self, kind, text, by='system'):
        """Append a timeline entry. Everything goes through here."""
        with self._lock:
            self._data['timeline'].append({
                'ts': time.time(), 'kind': kind,
                'text': text[:500], 'by': by})
            if len(self._data['timeline']) > self.MAX_TIMELINE:
                del self._data['timeline'][:-self.MAX_TIMELINE]
            self._save()

    add_timeline = record

    def timeline(self, limit=200):
        with self._lock:
            return self._data['timeline'][-limit:]

    # ------------------------------------------------------------------
    # Export

    def dataset_hash(self) -> str:
        with self._lock:
            raw = json.dumps(self._data, sort_keys=True,
                             separators=(',', ':')).encode()
        return hashlib.sha256(raw).hexdigest()

    def mitre(self) -> list:
        with self._lock:
            kinds = {t.get('kind', '') for t in self._data['timeline']}
        rows = []
        for kind, (tactic, technique) in sorted(MITRE.items()):
            if any(k == kind or k.startswith(kind + '.') for k in kinds):
                rows.append({'kind': kind, 'tactic': tactic,
                             'technique': technique})
        return rows

    def iocs(self) -> list:
        with self._lock:
            data = json.loads(json.dumps(self._data))
        out = []
        for h in data['hosts'].values():
            if h.get('hostname'):
                out.append({'type': 'hostname',
                            'value': h['hostname'],
                            'context': h.get('os', '')})
            if h.get('user'):
                out.append({'type': 'account',
                            'value': h['user'],
                            'context': h.get('hostname', '')})
        for u in data['users']:
            out.append({'type': 'account', 'value': u['user'],
                        'context': u.get('host', '')})
        for s in data['shares']:
            out.append({'type': 'share', 'value': s['name'],
                        'context': s.get('host', '')})
        for s in data['services']:
            out.append({'type': 'service', 'value': s['name'],
                        'context': s.get('host', '')})
        for e in data['evidence']:
            if e.get('sha256'):
                out.append({'type': 'sha256',
                            'value': e['sha256'],
                            'context': e.get('name', '')})
        seen, uniq = set(), []
        for row in out:
            key = (row['type'], row['value'])
            if key in seen:
                continue
            seen.add(key)
            uniq.append(row)
        return uniq

    def ioc_csv(self) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(['type', 'value', 'context'])
        for row in self.iocs():
            w.writerow([_csv_safe(row['type']),
                        _csv_safe(row['value']),
                        _csv_safe(row['context'])])
        return buf.getvalue()

    def stix(self, at=None) -> dict:
        """STIX 2.1 bundle of observed indicators and identities."""
        stamp = time.strftime('%Y-%m-%dT%H:%M:%SZ',
                              time.gmtime(at or time.time()))
        objects = []
        for i, row in enumerate(self.iocs(), 1):
            kind = {'hostname': 'domain-name', 'account':
                    'user-account', 'sha256': 'file',
                    'share': 'directory', 'service':
                    'software'}.get(row['type'], 'x-tornado')
            oid = f'indicator--{hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()[:32]}'
            obj = {'type': 'indicator', 'spec_version': '2.1',
                   'id': oid, 'created': stamp, 'modified': stamp,
                   'name': f"{row['type']}: {row['value']}",
                   'pattern_type': 'stix',
                   'pattern': _stix_pattern(row['type'],
                                             row['value']),
                   'x_tornado_kind': kind,
                   'x_tornado_context': row.get('context', '')}
            objects.append(obj)
        return {'type': 'bundle', 'id': f'bundle--{self.dataset_hash()[:32]}',
                'spec_version': '2.1', 'objects': objects}

    def report(self, at=None) -> str:
        stamp = time.strftime('%Y-%m-%d %H:%M:%SZ',
                              time.gmtime(at or time.time()))
        lines = ['# TornadoC2 engagement report', '',
                 f'generated: {stamp}',
                 f'dataset: {self.dataset_hash()}', '',
                 '## Hosts', '']
        hosts = self.hosts()
        if not hosts:
            lines.append('_none observed_')
        for h in hosts:
            lines.append(
                f"- **{_md(h.get('hostname') or h.get('machine_id'))}** "
                f"({_md(h.get('os'))}/{_md(h.get('arch'))}) "
                f"user={_md(h.get('user'))} "
                f"priv={_md(h.get('privilege'))} "
                f"beacon=#{h.get('beacon_id')}")

        ents = self.entities()
        for title, key, cols in (
                ('## Users', 'users', ('user', 'host', 'kind')),
                ('## Shares', 'shares', ('name', 'host', 'access')),
                ('## Services', 'services',
                 ('name', 'host', 'state'))):
            lines += ['', title, '']
            if not ents[key]:
                lines.append('_none_')
            for row in ents[key]:
                lines.append('- ' + ' · '.join(
                    _md(row.get(c, '')) for c in cols))

        lines += ['', '## Evidence', '']
        if not ents['evidence']:
            lines.append('_none_')
        for e in ents['evidence']:
            lines.append(
                f"- `{_md(e.get('sha256'))}` {_md(e.get('name'))} on "
                f"{_md(e.get('host'))} ({e.get('size')} bytes) — "
                f"{_md(e.get('detail'))} [{_md(e.get('by'))}]")

        lines += ['', '## Findings', '']
        fs = self.findings()
        if not fs:
            lines.append('_none_')
        for f in fs:
            ev = ''
            if f.get('evidence'):
                ev = ' evidence=' + ','.join(
                    e[:12] for e in f['evidence'])
            lines.append(
                f"- [{str(f['severity']).upper()}] #{f['id']} "
                f"{_md(f['title'])} on {_md(f['host'])} — "
                f"{_md(f['detail'])} ({_md(f['by'])}){ev}")

        lines += ['', '## MITRE ATT&CK', '']
        mt = self.mitre()
        if not mt:
            lines.append('_none_')
        for row in mt:
            lines.append(
                f"- {row['tactic']} · {row['technique']} "
                f"({row['kind']})")

        lines += ['', '## Timeline', '']
        for t in self.timeline(1000):
            when = time.strftime('%Y-%m-%d %H:%M:%S',
                                 time.localtime(t['ts']))
            lines.append(
                f"- {when} {_md(t['kind'])}: {_md(t['text'])} "
                f"({_md(t['by'])})")
        return '\n'.join(lines) + '\n'
