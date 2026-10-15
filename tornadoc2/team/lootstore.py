"""Content-addressed loot store for the team server.

Operators collect files from beacons. Those files belong to the
engagement, not to the operator who happened to type `download`
first — another operator on the same engagement should be able to
retrieve the same bytes without going back to the target. This
module is the shared store.

Design mirrors the chat file store: bytes are written to a path
derived from their SHA-256, with a JSON sidecar carrying metadata,
under a base directory that defaults to logs/lootstore/. Two
uploads of the same bytes deduplicate by hash.

    <base_dir>/<sha256>          the bytes, 0600
    <base_dir>/<sha256>.meta     the metadata, 0600

The server never opens, parses, sniffs, or executes a stored file.
It writes bytes, reads bytes back on request, and deletes on
request. No MIME detection, no server-side preview, no execution
path.

Metadata fields:

    owner           the operator who first uploaded the bytes
    ts              unix timestamp of the first upload
    name            display name — the local path the operator
                    saved to, or the remote basename
    source_path     the remote path the file was read from on the
                    target, before any local rename
    source_beacon   the beacon ID it came from, or 0

Ownership is by first upload. A later upload of the same bytes by
a different operator deduplicates to the existing blob and does
NOT transfer ownership — the first uploader keeps it. Only the
owner or an admin may delete a blob; the admin override is
recorded in the audit chain under the admin's name. If a blob is
deleted, any other operator's earlier `loot list` row that
referenced the same hash becomes a dangling pointer: the row stays
in whatever client cached it, the audit chain keeps the original
upload entry, and a download on the hash returns 404.

Caps. Three, all refuse rather than prune:

    MAX_FILE_BYTES    per-file. Rejected before any disk I/O.
    MAX_TOTAL_BYTES   cumulative. Existing files are never
                      deleted to make room — the audit chain may
                      reference any hash ever stored.
    MAX_FILES         inode guard. A flood of tiny files hits
                      this before it hits the byte cap.

MAX_FILE_BYTES bounds the chunked path only. The single-shot
POST endpoint is still bounded by Flask's MAX_CONTENT_LENGTH
(90 MiB by default after base64 expansion), so a file larger
than ~64 MiB cannot be uploaded through `/api/v1/loot/upload`
regardless of what this constant says. The chunked path
(`init` → `chunk` → `finish`) carries 4 MiB chunks that
base64-expand to ~5.3 MiB on the wire, well inside the request
body limit, and is the only path that reaches files up to
MAX_FILE_BYTES. The client selects the chunked path
automatically for any file above its own SMALL_FILE_THRESHOLD
(16 MiB), so a `lootstore upload` of a 100 GiB file goes
chunked with no operator action.

MAX_TOTAL_BYTES is the practical ceiling: 64 TiB, or 512
files at the full 128 GiB per-file limit. Whichever fills
first refuses the next upload.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time


class LootStore:
    """Content-addressed blob store for operator-shared loot.

    Thread-safe. All mutation holds `self._lock`. Reads of the
    in-memory index hold the lock only long enough to copy the
    relevant rows; the caller does not hold it while it uses the
    result.
    """

    MAX_FILE_BYTES = 128 * 1024 * 1024 * 1024        # 128 GiB per file
    MAX_TOTAL_BYTES = 64 * 1024 * 1024 * 1024 * 1024  # 64 TiB
    MAX_FILES = 8192 * 4                               # 32768
    UPLOAD_CHUNK_SIZE = 4 * 1024 * 1024
    UPLOAD_TTL        = 4 * 3600        # 4 hours

    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        os.makedirs(base_dir, mode=0o700, exist_ok=True)
        try:
            os.chmod(base_dir, 0o700)
        except OSError:
            pass
        self._lock = threading.Lock()
        self._index: dict = {}
        self._total_bytes = 0
        self.incoming_dir = os.path.join(base_dir, 'incoming')
        os.makedirs(self.incoming_dir, mode=0o700, exist_ok=True)
        try:
            os.chmod(self.incoming_dir, 0o700)
        except OSError:
            pass
        self._uploads: dict = {}
        self._upload_locks: dict = {}
        self._clean_incoming_on_start()
        self._rescan()

    # ------------------------------------------------------------------
    # Validation

    @staticmethod
    def is_valid_hash(h: str) -> bool:
        """True when h is exactly 64 lowercase hex characters.

        Called before any path is constructed from the hash, so no
        traversal is possible even from a hostile hash string. The
        same check the chat file store uses; the two stores are
        independent but must agree on the shape of a valid hash so
        an operator can move a hash between them without surprise.
        """
        if not isinstance(h, str) or len(h) != 64:
            return False
        return all(c in '0123456789abcdef' for c in h)

    # ------------------------------------------------------------------
    # Index

    def _rescan(self) -> None:
        """Rebuild the index by walking the store directory.

        Two files per blob:

            <sha256>          the bytes
            <sha256>.meta     JSON with owner, ts, name,
                              source_path, source_beacon

        A blob whose name is not a valid hash is skipped — it is
        not in the store, and the server will never serve it. A
        blob with no `.meta` sidecar loads with an empty owner;
        no non-admin requester can match an empty owner, so the
        blob is undeletable by any operator. An admin can still
        delete it — the override path bypasses the ownership
        check — and the audit chain records the deletion. That is
        the correct default for a blob whose provenance cannot be
        established.

        A `.meta` sidecar that is malformed JSON loads with the
        same degraded state — owner empty, all other fields
        default — rather than failing construction. The blob is
        still readable by hash; only deletion is refused.
        """
        with self._lock:
            self._index.clear()
            total = 0
            blobs: dict = {}
            metas: dict = {}
            try:
                for entry in os.scandir(self.base_dir):
                    if not entry.is_file():
                        continue
                    name = entry.name
                    if name.endswith('.meta'):
                        base = name[:-5]
                        if self.is_valid_hash(base):
                            metas[base] = entry.path
                        continue
                    if name.endswith('.tmp'):
                        continue
                    if not self.is_valid_hash(name):
                        continue
                    try:
                        st = entry.stat()
                    except OSError:
                        continue
                    blobs[name] = st.st_size
                    total += st.st_size
            except OSError:
                pass

            for h, size in blobs.items():
                owner = ''
                ts = 0.0
                name_field = ''
                source_path = ''
                source_beacon = 0
                meta_path = metas.get(h)
                if meta_path:
                    try:
                        with open(meta_path, 'r',
                                  encoding='utf-8') as fh:
                            meta = json.load(fh)
                        if isinstance(meta.get('owner'), str):
                            owner = meta['owner']
                        if isinstance(meta.get('ts'), (int, float)):
                            ts = float(meta['ts'])
                        if isinstance(meta.get('name'), str):
                            name_field = meta['name']
                        if isinstance(meta.get('source_path'), str):
                            source_path = meta['source_path']
                        sb = meta.get('source_beacon')
                        if isinstance(sb, (int, float)):
                            source_beacon = int(sb)
                    except (OSError, ValueError):
                        pass
                self._index[h] = {
                    'size':          size,
                    'owner':         owner,
                    'ts':            ts,
                    'name':          name_field,
                    'source_path':   source_path,
                    'source_beacon': source_beacon,
                }
            self._total_bytes = total

    # ------------------------------------------------------------------
    # Write

    def store(self, data: bytes, uploaded_by: str = '',
              display_name: str = '',
              source_path: str = '',
              source_beacon: int = 0) -> dict:
        """Store `data` and return {sha256, size, deduped, owner}.

        Raises ValueError on a cap violation, OSError on a disk
        failure. On success the bytes are durable before the
        method returns — the file is written to a temp name,
        fsynced, then atomically renamed into place. A crash mid-
        write cannot leave a partial blob in the store.

        On a dedup (the same bytes are already present), the
        existing sidecar is left untouched: the first uploader's
        provenance and ownership stick. The returned `owner` is
        the existing owner, not the caller.
        """
        size = len(data)
        if size == 0:
            raise ValueError('empty file')
        if size > self.MAX_FILE_BYTES:
            raise ValueError(
                f'file too large: {size} > {self.MAX_FILE_BYTES}')

        digest = hashlib.sha256(data).hexdigest()
        path = os.path.join(self.base_dir, digest)

        with self._lock:
            if digest in self._index:
                existing = self._index[digest]
                return {
                    'sha256':  digest,
                    'size':    size,
                    'deduped': True,
                    'owner':   existing.get('owner', ''),
                }
            if len(self._index) >= self.MAX_FILES:
                raise ValueError(
                    f'loot store full ({self.MAX_FILES} files)')
            if self._total_bytes + size > self.MAX_TOTAL_BYTES:
                raise ValueError(
                    f'loot store full '
                    f'({self._total_bytes + size} > '
                    f'{self.MAX_TOTAL_BYTES} bytes)')

            sp = (source_path or '')[:1024]
            sb = int(source_beacon or 0)
            now = time.time()
            tmp = path + '.tmp'
            meta_path = path + '.meta'
            meta_tmp = meta_path + '.tmp'
            try:
                with open(tmp, 'wb') as fh:
                    fh.write(data)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, path)
                try:
                    os.chmod(path, 0o600)
                except OSError:
                    pass

                with open(meta_tmp, 'w', encoding='utf-8') as fh:
                    json.dump({
                        'owner':         uploaded_by or '',
                        'ts':            now,
                        'name':          display_name or '',
                        'source_path':   sp,
                        'source_beacon': sb,
                    }, fh)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(meta_tmp, meta_path)
                try:
                    os.chmod(meta_path, 0o600)
                except OSError:
                    pass
            except OSError:
                for p in (tmp, meta_tmp):
                    try:
                        os.remove(p)
                    except OSError:
                        pass
                raise

            self._index[digest] = {
                'size':          size,
                'owner':         uploaded_by or '',
                'ts':            now,
                'name':          display_name or '',
                'source_path':   sp,
                'source_beacon': sb,
            }
            self._total_bytes += size
            return {
                'sha256':  digest,
                'size':    size,
                'deduped': False,
                'owner':   uploaded_by or '',
            }

    # ------------------------------------------------------------------
    # Chunked upload

    def _clean_incoming_on_start(self) -> None:
        """Remove any staging files left over from a previous
        process. They cannot be resumed — the upload state was
        in-memory — so the only correct action is to delete them."""
        try:
            for entry in os.scandir(self.incoming_dir):
                if not entry.is_file():
                    continue
                try:
                    os.remove(entry.path)
                except OSError:
                    pass
        except OSError:
            pass

    def initiate_upload(self, owner: str, total_size: int,
                        sha256: str, display_name: str = '',
                        source_path: str = '',
                        source_beacon: int = 0) -> dict:
        """Open a chunked upload. Returns a dict:

            {'upload_id': str or None, 'deduped': bool, 'size': int}

        If the bytes are already in the store (dedup by hash),
        `deduped` is True and `upload_id` is None — the client
        should skip the chunk stream entirely.

        Raises ValueError on bad input or a cap violation, OSError
        on a disk failure.
        """
        if not isinstance(total_size, int) or total_size <= 0:
            raise ValueError('total_size must be a positive integer')
        if not self.is_valid_hash(sha256):
            raise ValueError('invalid sha256')

        try:
            self.sweep_stale_uploads()
        except Exception:
            pass

        with self._lock:
            if sha256 in self._index:
                return {
                    'upload_id': None,
                    'deduped': True,
                    'size': self._index[sha256].get('size',
                                                    total_size),
                }
            if len(self._index) >= self.MAX_FILES:
                raise ValueError(
                    f'loot store full ({self.MAX_FILES} files)')
            if (self._total_bytes + total_size
                    > self.MAX_TOTAL_BYTES):
                raise ValueError(
                    f'loot store full '
                    f'({self._total_bytes + total_size} > '
                    f'{self.MAX_TOTAL_BYTES} bytes)')
            upload_id = secrets.token_hex(16)
            staging = os.path.join(self.incoming_dir, upload_id)
            self._uploads[upload_id] = {
                'path':          staging,
                'offset':        0,
                'total_size':    total_size,
                'sha256':        sha256,
                'owner':         owner or '',
                'name':          display_name or '',
                'source_path':   source_path or '',
                'source_beacon': int(source_beacon or 0),
                'started':       time.time(),
            }
            self._upload_locks[upload_id] = threading.Lock()

        try:
            with open(staging, 'wb') as fh:
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(staging, 0o600)
        except OSError:
            with self._lock:
                self._uploads.pop(upload_id, None)
                self._upload_locks.pop(upload_id, None)
            raise

        return {
            'upload_id': upload_id,
            'deduped':   False,
            'size':      total_size,
        }

    def append_chunk(self, upload_id: str, offset: int,
                     data: bytes) -> int:
        """Append one chunk. Returns the new offset.

        The per-upload lock serializes appends so two concurrent
        chunk POSTs for the same upload cannot interleave their
        disk writes. The store lock is held only around the
        state read and the state update, never across the fsync —
        otherwise a slow disk would block every other operator's
        loot operation.

        Raises ValueError on an unknown upload, an offset
        mismatch, or a chunk that would exceed the declared
        total_size. OSError on a disk failure.
        """
        with self._lock:
            u = self._uploads.get(upload_id)
            if u is None:
                raise ValueError('unknown or expired upload_id')
            lock = self._upload_locks.get(upload_id)
            if lock is None:
                lock = threading.Lock()
                self._upload_locks[upload_id] = lock

        with lock:
            with self._lock:
                u = self._uploads.get(upload_id)
                if u is None:
                    raise ValueError('upload aborted')
                expected = u['offset']
                total = u['total_size']
                staging = u['path']

            if offset != expected:
                raise ValueError(
                    f'offset mismatch: expected {expected}, '
                    f'got {offset}')
            if expected + len(data) > total:
                raise ValueError(
                    f'chunk would exceed declared total_size '
                    f'({expected + len(data)} > {total})')

            with open(staging, 'ab') as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())

            with self._lock:
                u = self._uploads.get(upload_id)
                if u is None:
                    raise ValueError('upload aborted during write')
                u['offset'] += len(data)
                u['started'] = time.time()
                return u['offset']

    def finish_upload(self, upload_id: str) -> dict:
        """Complete a chunked upload.

        Verifies that the received bytes match the declared total
        size, hashes the staging file, and compares against the
        digest the client declared on init. Only then is the file
        moved into the content-addressed slot.

        On any failure the staging file is removed and the upload
        state is dropped, so a failed finish never leaves a
        partial blob in the store.

        The per-upload lock is held across the whole operation so
        two concurrent finish calls for the same upload cannot
        both try to move the same staging file into place.

        Returns {sha256, size, deduped, owner}.
        """
        with self._lock:
            u = self._uploads.get(upload_id)
            if u is None:
                raise ValueError('unknown or expired upload_id')
            lock = self._upload_locks.get(upload_id)
            if lock is None:
                lock = threading.Lock()
                self._upload_locks[upload_id] = lock

        with lock:
            with self._lock:
                u = self._uploads.get(upload_id)
                if u is None:
                    raise ValueError('upload aborted')
                staging = u['path']
                declared_size = u['total_size']
                declared_sha = u['sha256']
                owner = u['owner']
                name = u['name']
                source_path = u['source_path']
                source_beacon = u['source_beacon']
                actual = u['offset']

            if actual != declared_size:
                self.abort_upload(upload_id)
                raise ValueError(
                    f'incomplete upload: {actual} of '
                    f'{declared_size} bytes received')

            h = hashlib.sha256()
            try:
                with open(staging, 'rb') as fh:
                    for block in iter(
                            lambda: fh.read(1024 * 1024), b''):
                        h.update(block)
            except OSError:
                self.abort_upload(upload_id)
                raise
            got = h.hexdigest()
            if got != declared_sha:
                self.abort_upload(upload_id)
                raise ValueError(
                    f'sha256 mismatch: declared {declared_sha}, '
                    f'got {got}')

            with self._lock:
                if declared_sha in self._index:
                    existing = self._index[declared_sha]
                    self._drop_upload_state(upload_id)
                    try:
                        os.remove(staging)
                    except OSError:
                        pass
                    return {
                        'sha256':  declared_sha,
                        'size':    existing.get('size', actual),
                        'deduped': True,
                        'owner':   existing.get('owner', ''),
                    }
                if len(self._index) >= self.MAX_FILES:
                    self._drop_upload_state(upload_id)
                    try:
                        os.remove(staging)
                    except OSError:
                        pass
                    raise ValueError(
                        f'loot store full ({self.MAX_FILES} files)')
                if (self._total_bytes + actual
                        > self.MAX_TOTAL_BYTES):
                    self._drop_upload_state(upload_id)
                    try:
                        os.remove(staging)
                    except OSError:
                        pass
                    raise ValueError('loot store full at finish')

            final_path = os.path.join(self.base_dir, declared_sha)
            meta_path = final_path + '.meta'
            try:
                os.replace(staging, final_path)
                try:
                    os.chmod(final_path, 0o600)
                except OSError:
                    pass
                meta_tmp = meta_path + '.tmp'
                now = time.time()
                with open(meta_tmp, 'w', encoding='utf-8') as fh:
                    json.dump({
                        'owner':         owner,
                        'ts':            now,
                        'name':          name,
                        'source_path':   source_path,
                        'source_beacon': source_beacon,
                    }, fh)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(meta_tmp, meta_path)
                try:
                    os.chmod(meta_path, 0o600)
                except OSError:
                    pass
            except OSError:
                raise

            with self._lock:
                self._index[declared_sha] = {
                    'size':          actual,
                    'owner':         owner,
                    'ts':            time.time(),
                    'name':          name,
                    'source_path':   source_path,
                    'source_beacon': source_beacon,
                }
                self._total_bytes += actual
                self._drop_upload_state(upload_id)

            return {
                'sha256':  declared_sha,
                'size':    actual,
                'deduped': False,
                'owner':   owner,
            }

    def abort_upload(self, upload_id: str) -> bool:
        """Drop the upload state and delete the staging file.
        Returns True if an upload was in progress."""
        with self._lock:
            u = self._uploads.get(upload_id)
            if u is None:
                return False
            staging = u['path']
            self._drop_upload_state(upload_id)
        try:
            os.remove(staging)
        except OSError:
            pass
        return True

    def sweep_stale_uploads(self, ttl: int = None) -> int:
        """Delete staging files older than ttl seconds.

        Called opportunistically on each initiate_upload. A
        crashed client leaves a staging file behind; this is the
        only thing that cleans it up. Returns the number of files
        removed.
        """
        if ttl is None:
            ttl = self.UPLOAD_TTL
        cutoff = time.time() - ttl
        removed = 0

        with self._lock:
            stale = [uid for uid, u in self._uploads.items()
                     if u.get('started', 0) < cutoff]
            for uid in stale:
                lock = self._upload_locks.get(uid)
                if lock is not None:
                    if not lock.acquire(blocking=False):
                        continue
                try:
                    u = self._uploads.pop(uid, None)
                    self._upload_locks.pop(uid, None)
                    if u is not None:
                        try:
                            os.remove(u['path'])
                            removed += 1
                        except OSError:
                            pass
                finally:
                    if lock is not None:
                        try:
                            lock.release()
                        except RuntimeError:
                            pass

        try:
            for entry in os.scandir(self.incoming_dir):
                if not entry.is_file():
                    continue
                try:
                    st = entry.stat()
                except OSError:
                    continue
                if st.st_mtime < cutoff:
                    try:
                        os.remove(entry.path)
                        removed += 1
                    except OSError:
                        pass
        except OSError:
            pass

        return removed

    def _drop_upload_state(self, upload_id: str) -> None:
        """Caller must hold self._lock."""
        self._uploads.pop(upload_id, None)
        self._upload_locks.pop(upload_id, None)

    # ------------------------------------------------------------------
    # Read

    def read(self, digest: str):
        """Return the bytes for a hash, or None if unknown.

        Validates the hash shape before touching the filesystem,
        so a request with a hostile hash string cannot cause a
        path lookup outside the store directory.
        """
        if not self.is_valid_hash(digest):
            return None
        path = os.path.join(self.base_dir, digest)
        try:
            with open(path, 'rb') as fh:
                return fh.read()
        except OSError:
            return None

    def stat(self, digest: str):
        """Return a copy of one blob's index entry, or None."""
        with self._lock:
            entry = self._index.get(digest)
        return dict(entry) if entry else None

    def list_all(self) -> list:
        """Return a snapshot of every stored blob.

        The lock is held only for the copy, not for anything the
        caller does with the result — the caller can sort, render,
        or audit without blocking a concurrent upload. Newest
        first is the caller's job; this returns insertion order,
        which for a dict in CPython is insertion order of the
        rescan walk, which is filesystem order. Sort by `ts` if
        you need chronological.
        """
        with self._lock:
            return [{
                'sha256':        h,
                'size':          e.get('size', 0),
                'owner':         e.get('owner', ''),
                'name':          e.get('name', '') or '',
                'ts':            e.get('ts', 0.0),
                'source_path':   e.get('source_path', '') or '',
                'source_beacon': e.get('source_beacon', 0) or 0,
            } for h, e in self._index.items()]

    # ------------------------------------------------------------------
    # Delete

    def delete(self, digest: str, requester: str,
               is_admin: bool = False) -> dict:
        """Delete a stored file if `requester` is its owner, or
        if `is_admin` is True.

        Raises ValueError on a malformed hash, FileNotFoundError
        if the hash is not in the store, PermissionError if the
        caller is neither the owner nor an admin, OSError on a
        disk failure.

        Ownership semantics. The owner is the operator who first
        uploaded the bytes. A later upload of the same bytes by a
        different operator deduplicates to the existing blob and
        does not transfer ownership — the first uploader keeps
        it. If the owner deletes the file, any other operator's
        earlier `loot list` row that referenced the same hash
        becomes a dangling pointer: the row stays in whatever
        client cached it, the audit chain keeps the original
        upload entry, and a download on the hash returns 404.
        This is the correct trade for a team tool — the operator
        who paid for the upload decides when it goes away, and a
        dedup is never a claim of ownership.

        Admins can delete any loot, including blobs with no
        recorded owner (uploaded by an older server version, or
        written before the meta sidecar existed). The caller is
        responsible for auditing the override — this method only
        enforces the rule.

        Returns a dict with `sha256`, `size`, `owner`, and
        `overrode` (True when an admin deleted a blob they did
        not own).
        """
        if not self.is_valid_hash(digest):
            raise ValueError('invalid hash')

        with self._lock:
            entry = self._index.get(digest)
            if entry is None:
                raise FileNotFoundError(digest)

            owner = entry.get('owner', '') or ''

            if is_admin:
                overrode = (owner != requester)
            else:
                overrode = False
                if not owner:
                    raise PermissionError(
                        'file has no recorded owner; ask an '
                        'admin to remove it')
                if owner != requester:
                    raise PermissionError(
                        f'file is owned by {owner!r}; ask an '
                        f'admin to remove it')

            path = os.path.join(self.base_dir, digest)
            meta_path = path + '.meta'
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
            try:
                os.remove(meta_path)
            except FileNotFoundError:
                pass

            self._total_bytes -= entry.get('size', 0)
            del self._index[digest]
            return {
                'sha256':   digest,
                'size':     entry.get('size', 0),
                'owner':    owner,
                'overrode': overrode,
            }

    # ------------------------------------------------------------------
    # Introspection

    def total_bytes(self) -> int:
        with self._lock:
            return self._total_bytes

    def count(self) -> int:
        with self._lock:
            return len(self._index)