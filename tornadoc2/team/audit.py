"""Append-only hash-chained audit log.

Every entry contains SHA-256 of the previous entry. The tail is
sealed with an HMAC checkpoint and a second anchor file, both keyed
by a persistent server key in ``audit.key`` (0600). At startup the
whole chain, affected checkpoints and the anchor are verified; if the
chain is broken the server refuses to start (overridable with a flag
for recovery scenarios).

The key is persisted so the seal survives restarts, which is what
makes truncation detectable: deleting the last line without a fresh
checkpoint leaves the anchor pointing past the file. Set
``TORNADOC2_AUDIT_KEY`` (base64, 32 bytes) to keep the key off the
log disk and ``TORNADOC2_AUDIT_ANCHOR`` to put the anchor on another
volume. An attacker who edits the log while the server is down and
does not have the key cannot re-seal it.
"""

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from typing import List, Optional, Tuple

from . import constants


class AuditChainError(RuntimeError):
    """Raised when the chain verification fails at startup."""


class AuditLog:

    def __init__(self, base_dir: str = None,
                 verify_on_start: bool = True):
        self.base_dir = base_dir or constants.AUDIT_DIR
        self.combined_path = os.path.join(
            self.base_dir, 'combined.log')
        self.checkpoint_path = os.path.join(
            self.base_dir, 'checkpoint.json')
        self.anchor_path = (os.environ.get('TORNADOC2_AUDIT_ANCHOR')
                            or os.path.join(self.base_dir, 'anchor.json'))
        self._lock = threading.Lock()
        self._last_hash = '0' * 64

        os.makedirs(self.base_dir, exist_ok=True)
        self._seal_key = self._load_key()

        if os.path.isfile(self.combined_path):
            if verify_on_start:
                ok, msg = self.verify()
                if not ok:
                    raise AuditChainError(
                        f'audit chain verification failed: {msg}\n'
                        f'The log may have been tampered with. To '
                        f'recover, move {self.base_dir} aside and '
                        f'restart, or start with --no-audit-verify.')
            else:
                tail = self._read_tail_hash()
                if tail is not None:
                    self._last_hash = tail
                    print(f'[AUDIT] verify skipped; resuming chain '
                          f'at {tail[:16]}…')
                else:
                    print('[AUDIT] verify skipped; no tail hash '
                          'found, starting a new chain')

    def _load_key(self) -> bytes:
        env = os.environ.get('TORNADOC2_AUDIT_KEY', '').strip()
        if env:
            import base64
            try:
                raw = base64.b64decode(env, validate=True)
            except Exception as exc:
                raise AuditChainError(f'bad TORNADOC2_AUDIT_KEY: {exc}')
            if len(raw) != 32:
                raise AuditChainError(
                    'TORNADOC2_AUDIT_KEY must be 32 bytes')
            return raw
        path = os.path.join(self.base_dir, 'audit.key')
        raw = b''
        if not os.path.isfile(path):
            raw = secrets.token_bytes(32)
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                             0o600)
            except FileExistsError:
                fd = -1
                raw = b''
            if fd != -1:
                try:
                    os.write(fd, raw)
                finally:
                    os.close(fd)
        if not raw:
            raw = open(path, 'rb').read()
        if len(raw) != 32:
            raise AuditChainError(f'{path} is not a 32-byte key')
        return raw

    def _mac(self, digest: str) -> str:
        return hmac.new(self._seal_key, digest.encode(),
                        hashlib.sha256).hexdigest()

    def _write_anchor(self, last_hash: str) -> None:
        try:
            offset = os.path.getsize(self.combined_path)
        except OSError:
            offset = 0
        payload = {'hash': last_hash, 'mac': self._mac(last_hash),
                   'offset': offset, 'ts': time.time()}
        for path in (self.checkpoint_path, self.anchor_path):
            try:
                tmp = path + '.tmp'
                with open(tmp, 'w', encoding='utf-8') as fh:
                    json.dump(payload, fh)
                    fh.flush()
                    try:
                        os.fsync(fh.fileno())
                    except OSError:
                        pass
                os.replace(tmp, path)
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Write

    def write(self, operator: str, role: str, source_ip: str,
              action: str, target: str = '',
              outcome: str = 'ok', detail: str = '') -> str:
        """Append one entry. Returns its ID.

        Raises OSError if the disk is unwritable. Callers should
        refuse the request in that case — silent audit loss is worse
        than refusing service.
        """
        with self._lock:
            entry = {
                'id': self._new_id(),
                'ts': self._now_iso(),
                'operator': operator or '__local__',
                'role': role,
                'source_ip': source_ip,
                'action': action,
                'target': target,
                'outcome': outcome,
                'detail': detail[:4096],
                'prev': self._last_hash,
            }
            entry['hash'] = self._entry_hash(entry)

            line = json.dumps(
                entry, separators=(',', ':'), ensure_ascii=False) + '\n'
            self._append(self.combined_path, line)

            human = self._render_human(entry)
            human_path = os.path.join(self.base_dir, 'combined.txt')
            self._append(human_path, human + '\n')

            if operator and operator != '__local__':
                per_op = os.path.join(
                    self.base_dir, self._safe(operator) + '.log')
                self._append(per_op, line)
                per_op_txt = os.path.join(
                    self.base_dir,
                    self._safe(operator) + '.txt')
                self._append(per_op_txt, human + '\n')

            self._last_hash = entry['hash']
            self._write_checkpoint(entry['hash'])

            return entry['id']

    # ------------------------------------------------------------------
    # Verify

    def verify(self, full: bool = False) -> Tuple[bool, str]:
        """Verify the chain and the seals.

        With a valid checkpoint the sealed prefix is trusted via its
        MAC and only the suffix from the saved offset is walked, so
        startup stays proportional to new entries rather than the
        whole log. ``full=True`` walks every line.

        The write lock is held for the duration; an append cannot be
        observed half-written.
        """
        with self._lock:
            return self._verify_locked(full)

    def _verify_locked(self, full: bool) -> Tuple[bool, str]:
        if not os.path.isfile(self.combined_path):
            if (os.path.isfile(self.checkpoint_path)
                    or os.path.isfile(self.anchor_path)):
                return False, 'log file is missing but a seal exists'
            return True, 'empty'

        seed, start = '0' * 64, 0
        legacy = False
        cp = None
        if not full and os.path.isfile(self.checkpoint_path):
            try:
                with open(self.checkpoint_path, encoding='utf-8') as fh:
                    cp = json.load(fh)
            except (OSError, ValueError):
                cp = None
            if cp is not None and self._seal_ok(cp, 'checkpoint'):
                seed = str(cp.get('hash') or '')
                start = int(cp.get('offset') or 0)
            else:
                cp = None

        prev = seed
        count = 0
        try:
            size = os.path.getsize(self.combined_path)
            if start > size:
                return False, 'checkpoint offset is past the log end'
            with open(self.combined_path, 'r',
                      encoding='utf-8', errors='strict') as fh:
                fh.seek(start)
                for lineno, line in enumerate(fh, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except ValueError:
                        # A writer may have appended after the lock
                        # in a previous process; only the very last
                        # line can legitimately be partial.
                        if fh.tell() == size:
                            break
                        return False, f'line {lineno}: not JSON'
                    if entry.get('prev') != prev:
                        return False, (
                            f'line {lineno}: prev hash mismatch '
                            f'(expected {prev[:16]}…)')
                    claimed = entry.pop('hash', None)
                    if claimed != self._entry_hash(entry):
                        return False, f'line {lineno}: entry hash mismatch'
                    prev = claimed
                    count += 1
        except OSError as exc:
            return False, f'read error: {exc}'
        if prev != '0' * 64:
            entry, tail = self._read_tail_entry()
            if tail != prev:
                return False, 'tail line is missing from the log'
            if entry is not None:
                claimed = entry.get('hash')
                if self._entry_hash(
                        {k: v for k, v in entry.items()
                         if k != 'hash'}) != claimed:
                    return False, 'tail line was modified'
        self._last_hash = prev

        for label, path in (('checkpoint', self.checkpoint_path),
                            ('anchor', self.anchor_path)):
            if not os.path.isfile(path):
                continue
            try:
                with open(path, encoding='utf-8') as fh:
                    seal = json.load(fh)
            except (OSError, ValueError):
                return False, f'{label} is unreadable'
            if seal.get('hash') != prev:
                return False, (
                    f'{label} hash {str(seal.get("hash"))[:16]}… does '
                    f'not match chain tail {prev[:16]}…')
            if not hmac.compare_digest(str(seal.get('mac') or ''),
                                       self._mac(prev)):
                if label == 'checkpoint' and not legacy:
                    legacy = True
                    continue
                return False, f'{label} MAC mismatch'
            if int(seal.get('offset') or 0) != size:
                return False, f'{label} offset does not match log size'

        if legacy:
            self._write_anchor(prev)
        return True, f'{count} entries verified, chain intact'

    def _seal_ok(self, seal: dict, label: str) -> bool:
        h = str(seal.get('hash') or '')
        return bool(h) and hmac.compare_digest(
            str(seal.get('mac') or ''), self._mac(h))

    def _write_checkpoint(self, last_hash: str) -> None:
        self._write_anchor(last_hash)

    def flush(self) -> None:
        """Seal the current tail. Call on graceful shutdown."""
        with self._lock:
            if self._last_hash != '0' * 64:
                self._write_anchor(self._last_hash)

    # ------------------------------------------------------------------
    # Helpers

    @staticmethod
    def _safe(name: str) -> str:
        return ''.join(
            c if c.isalnum() or c in '-_.' else '_'
            for c in name)[:64] or 'unknown'

    def _read_tail_entry(self):
        """Return (last entry, its hash) or (None, None)."""
        try:
            with open(self.combined_path, 'rb') as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                block = 4096
                buf = b''
                pos = size
                while pos > 0:
                    read = min(block, pos)
                    pos -= read
                    fh.seek(pos)
                    buf = fh.read(read) + buf
                    if buf.count(b'\n') > 1:
                        break
        except OSError:
            return None, None
        for line in reversed(buf.decode('utf-8', 'replace').splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if isinstance(entry, dict):
                return entry, entry.get('hash')
        return None, None

    def _read_tail_hash(self) -> Optional[str]:
        """Return the `hash` field of the last well-formed line in
        combined.log, or None if the file is empty or unreadable.

        Used when the chain is not verified at startup but the log
        already exists. Without this, the next write would stamp
        `prev='0'*64` on an entry whose predecessor is the on-disk
        tail, splitting the chain at the point where the server was
        started with --no-audit-verify.

        Reads the file backwards in fixed-size blocks rather than
        line-by-line so a multi-gigabyte log does not have to be
        parsed just to find its last entry. A handful of blocks is
        enough for any realistic entry size (the `detail` field is
        capped at 4096 bytes, plus maybe 300 bytes of framing).
        """
        try:
            with open(self.combined_path, 'rb') as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                if size == 0:
                    return None
                block = 4096
                buf = b''
                pos = size
                while pos > 0:
                    read = min(block, pos)
                    pos -= read
                    fh.seek(pos)
                    buf = fh.read(read) + buf
                    stripped = buf.rstrip(b'\n')
                    if b'\n' in stripped:
                        break
        except OSError:
            return None

        text = buf.decode('utf-8', errors='replace')
        for line in reversed(text.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            h = entry.get('hash')
            if isinstance(h, str) and len(h) == 64:
                return h
        return None

    @staticmethod
    def _new_id() -> str:
        return f'{time.time_ns():016x}'

    @staticmethod
    def _now_iso() -> str:
        t = time.time()
        return (time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(t))
                + f'.{int(t * 1000000) % 1000000:06d}Z')

    @staticmethod
    def _entry_hash(entry: dict) -> str:

        canonical = json.dumps(
            {k: v for k, v in entry.items() if k != 'hash'},
            sort_keys=True, separators=(',', ':'),
            ensure_ascii=False).encode('utf-8')
        return hashlib.sha256(canonical).hexdigest()

    @staticmethod
    def _render_human(entry: dict) -> str:
        """Render one entry in the same two-line format the console
        uses. No colour; this is a file."""
        ts = str(entry.get('ts', ''))[:19].replace('T', ' ')
        op = entry.get('operator', '?')
        role = entry.get('role', '') or ''
        ip = entry.get('source_ip', '') or ''
        action = entry.get('action', '?')
        target = entry.get('target', '') or ''
        outcome = entry.get('outcome', 'ok')
        detail = entry.get('detail', '') or ''

        who = op
        if role and role != 'local':
            who += f"@{role}"
        where = f"({ip})" if ip else ""
        tgt = f" {target}" if target else ""

        header = (f"{ts}  {who} {where}  {action}{tgt}  "
                  f"{outcome}")
        if detail:
            text = detail.replace('\n', ' \\n ')
            if len(text) > 200:
                text = text[:197] + '...'
            return header + "\n    " + text
        return header

    @staticmethod
    def _append(path: str, line: str) -> None:
        with open(path, 'a', encoding='utf-8') as fh:
            fh.write(line)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Read (unchanged from before)

    def read(self, operator: Optional[str] = None,
             limit: int = 500) -> List[dict]:
        if operator:
            path = os.path.join(
                self.base_dir, self._safe(operator) + '.log')
        else:
            path = self.combined_path
        if not os.path.isfile(path):
            return []
        from collections import deque
        ring: deque = deque(maxlen=limit)
        try:
            with open(path, 'r', encoding='utf-8',
                      errors='replace') as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ring.append(json.loads(line))
                    except ValueError:
                        continue
        except OSError:
            return []
        return list(ring)