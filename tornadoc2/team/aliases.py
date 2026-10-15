"""Per-beacon aliases and tags.

Stored separately from the session record so a beacon that goes
stale and reconnects keeps its alias. The session registry keys on
fingerprint; this store keys on the beacon id and is reconciled on
each reconnect by the engine.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time

_NAME_RE = re.compile(r'^[A-Za-z][A-Za-z0-9._-]{0,31}$')


class AliasStore:

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)

    def _load(self) -> dict:
        try:
            with open(self.path, 'r', encoding='utf-8') as fh:
                d = json.load(fh)
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self, d: dict) -> None:
        tmp = self.path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as fh:
            json.dump(d, fh, indent=2, sort_keys=True)
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def _entry(self, data: dict, bid: int) -> dict:
        key = str(bid)
        e = data.get(key)
        if e is None:
            e = {'alias': '', 'tags': [], 'set_by': '', 'set_at': 0.0}
            data[key] = e
        return e

    def get(self, bid: int) -> dict:
        with self._lock:
            e = dict(self._load().get(str(bid), {}))
        return {
            'alias': e.get('alias', ''),
            'tags':  list(e.get('tags', [])),
            'set_by': e.get('set_by', ''),
            'set_at': e.get('set_at', 0.0),
        }

    def all(self) -> dict:
        with self._lock:
            return self._load()

    def set_alias(self, bid: int, alias: str, by: str) -> None:
        if alias and not _NAME_RE.match(alias):
            raise ValueError(
                'alias must start with a letter and contain only '
                'A-Z a-z 0-9 . _ -')
        if alias:
            with self._lock:
                data = self._load()
                for other, e in data.items():
                    if other == str(bid):
                        continue
                    if e.get('alias') == alias:
                        raise ValueError(
                            f'alias {alias!r} is already in use '
                            f'by beacon #{other}')
                self._entry(data, bid)['alias'] = alias
                self._entry(data, bid)['set_by'] = by
                self._entry(data, bid)['set_at'] = time.time()
                self._save(data)
        else:
            with self._lock:
                data = self._load()
                self._entry(data, bid)['alias'] = ''
                self._entry(data, bid)['set_by'] = by
                self._entry(data, bid)['set_at'] = time.time()
                self._save(data)

    def add_tag(self, bid: int, tag: str, by: str) -> list:
        if not _NAME_RE.match(tag):
            raise ValueError(
                'tag must start with a letter and contain only '
                'A-Z a-z 0-9 . _ -')
        with self._lock:
            data = self._load()
            e = self._entry(data, bid)
            tags = list(e.get('tags', []))
            if tag not in tags:
                tags.append(tag)
                e['tags'] = sorted(tags)
                e['set_by'] = by
                e['set_at'] = time.time()
                self._save(data)
            return list(e.get('tags', []))

    def remove_tag(self, bid: int, tag: str, by: str) -> list:
        with self._lock:
            data = self._load()
            e = self._entry(data, bid)
            tags = [t for t in e.get('tags', []) if t != tag]
            e['tags'] = tags
            e['set_by'] = by
            e['set_at'] = time.time()
            self._save(data)
            return list(tags)

    def resolve(self, name_or_id: str) -> int | None:
        """Resolve a name against a live beacon. Returns the id or
        None. Numeric strings resolve as ids first; a non-numeric
        string resolves as an alias."""
        if name_or_id.isdigit():
            return int(name_or_id)
        with self._lock:
            data = self._load()
        for key, e in data.items():
            if e.get('alias') == name_or_id:
                return int(key)
        return None

    def forget(self, bid: int) -> None:
        with self._lock:
            data = self._load()
            data.pop(str(bid), None)
            self._save(data)