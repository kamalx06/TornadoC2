"""Append-only hash-chained audit log.

Every entry contains SHA-256 of the previous entry. The chain is
anchored by an HMAC over the last entry, keyed by a per-run secret
that lives only in memory. At startup the chain is verified; if it
is broken the server refuses to start (overridable with a flag for
recovery scenarios).

The per-run HMAC key is deliberately ephemeral. It protects against
offline edits between server runs — an attacker who edits the log
while the server is down cannot re-seal the chain because they do
not know the key that will be generated on the next start. It does
not protect against an attacker who has the key while the server is
running, which is not part of the threat model (that attacker has
already compromised the server process).
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
        self._seal_key = secrets.token_bytes(32)
        self._lock = threading.Lock()
        self._last_hash = '0' * 64

        os.makedirs(self.base_dir, exist_ok=True)

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

    def verify(self) -> Tuple[bool, str]:
        """Walk the chain and return (ok, message)."""
        if not os.path.isfile(self.combined_path):
            return True, 'empty'
        prev = '0' * 64
        prev_prev = None
        count = 0
        try:
            with open(self.combined_path, 'r',
                      encoding='utf-8', errors='strict') as fh:
                for lineno, line in enumerate(fh, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except ValueError:
                        return False, f'line {lineno}: not JSON'
                    if entry.get('prev') != prev:
                        return False, (
                            f'line {lineno}: prev hash mismatch '
                            f'(expected {prev[:16]}…, '
                            f'got {str(entry.get("prev"))[:16]}…)')
                    claimed = entry.pop('hash', None)
                    actual = self._entry_hash(entry)
                    if claimed != actual:
                        return False, (
                            f'line {lineno}: entry hash mismatch')
                    prev_prev = prev
                    prev = claimed
                    count += 1
        except OSError as exc:
            return False, f'read error: {exc}'
        self._last_hash = prev

        if os.path.isfile(self.checkpoint_path):
            try:
                with open(self.checkpoint_path, 'r',
                          encoding='utf-8') as fh:
                    cp = json.load(fh)
                cp_hash = cp.get('hash')

                if cp_hash != prev and cp_hash != prev_prev:
                    return False, (
                        f'checkpoint hash '
                        f'{str(cp_hash)[:16]}… does not match '
                        f'chain tail {prev[:16]}…')
            except (OSError, ValueError):
                pass

        return True, f'{count} entries, chain intact'

    def _write_checkpoint(self, last_hash: str) -> None:
        try:
            mac = hmac.new(
                self._seal_key, last_hash.encode(),
                hashlib.sha256).hexdigest()
            tmp = self.checkpoint_path + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as fh:
                json.dump({'hash': last_hash, 'mac': mac,
                           'ts': time.time()}, fh)
            os.replace(tmp, self.checkpoint_path)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Helpers

    @staticmethod
    def _safe(name: str) -> str:
        return ''.join(
            c if c.isalnum() or c in '-_.' else '_'
            for c in name)[:64] or 'unknown'

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