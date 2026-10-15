"""In-memory team chat.

A small, bounded, thread-safe message buffer shared by every
operator connected to the team server. The in-memory ring is 
bounded and per-process; a server
restart clears the live window. Messages are also mirrored to
two files under the chat log directory — chat.txt as a
human-readable line per message and chat.jsonl as a structured
store the room rehydrates from on startup. The audit chain
remains the authoritative record; the on-disk files exist so
the room is not blank after a restart and so `/history
--persist` has a source.

The buffer is a deque with a fixed maxlen, so memory is bounded
regardless of how many messages arrive. Old messages fall off the
front. A condition variable wakes long-polling readers the moment
a new message lands, so a client sees chat in real time without a
busy-wait.

Nothing here writes to the audit chain. Chat is conversational
traffic, and hash-chaining every "ack" and "on it" would drown
the state-changing entries that the chain exists to protect. The
`session.open` entry the listener already writes when an operator
first connects is the forensic record of presence.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import unicodedata
from collections import deque
from typing import List


# ---------------------------------------------------------------------
# Chat text sanitization
# ---------------------------------------------------------------------
SANITIZER_VERSION = 2


# CSI sequences, both the 7-bit introducer (ESC [) and the 8-bit
# one (U+009B). The parameter class [0-9;?]* covers the numeric,
# semicolon, and "private mode" prefixes real terminals send; the
# final byte is any ASCII letter.
_ANSI_CSI_RE = re.compile(
    r'(?:\x1b\[|\u009b)[0-9;?]*[A-Za-z]')

# OSC sequences. Introduced by ESC ], terminated by BEL (\x07) or
# ST (ESC \). The body may contain anything except the two
# terminators, so the character class is deliberately wide. This
# catches title-setting, hyperlinks, and clipboard writes.
_ANSI_OSC_RE = re.compile(
    r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)')

# C0, DEL, and the C1 block. C0 that are handled by line flattening
# first (\t, \n, \r) are absent from this class because they are
# already spaces by the time this runs. C1 is the 8-bit control
# range; a terminal that honours C1 treats \u009b as ESC [.
_CTRL_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]')

# Unicode formatting controls. These are codepoints the terminal
# interprets rather than displays — they change visual order or are
# invisible entirely. Stripping them is not cosmetic; leaving them
# in means the audit chain and the screen can disagree about what a
# message said.
#
#   U+200B..U+200F   zero-width space / non-joiner / joiner / LRM / RLM
#   U+202A..U+202E   bidi embedding, override (Trojan Source)
#   U+2066..U+2069   bidi isolates
#   U+FEFF           zero-width no-break space (BOM)
#   U+E0001          language tag introducer
#   U+E0020..U+E007F tag characters (hidden payload carrier)
_UNICODE_FORMAT_RE = re.compile(
    '[\u200b\u200c\u200d\u200e\u200f'
    '\u202a-\u202e\u2066-\u2069\ufeff'
    '\U000E0001\U000E0020-\U000E007F]')

# Combining marks, by Unicode general category. Used to enforce the
# anti-Zalgo cap below.
_COMBINING_CATEGORIES = frozenset(('Mn', 'Mc', 'Me'))


class SanitizeResult:
    """What the sanitizer produced, and what it removed.

    The rest of the system renders `text` and stores `text`; a
    caller that wants to know how much was removed — for the audit
    entry, for a warning, or for a rate-limit decision — reads the
    counters. `text` alone is enough for correctness; the counters
    are what make the sanitizer's work legible in the audit chain.
    """

    __slots__ = ('text', 'original_len', 'final_len',
                 'bytes_stripped', 'was_modified',
                 'combining_cap_hits', 'iterations',
                 'raw_b64', 'raw_sha256', 'raw_truncated')

    def __init__(self, text, original_len, bytes_stripped,
                 combining_cap_hits, iterations,
                 raw_b64=None, raw_sha256=None, raw_truncated=False):
        self.text = text
        self.original_len = original_len
        self.final_len = len(text)
        self.bytes_stripped = bytes_stripped
        self.was_modified = (bytes_stripped > 0
                             or original_len != len(text))
        self.combining_cap_hits = combining_cap_hits
        self.iterations = iterations
        self.raw_b64 = raw_b64
        self.raw_sha256 = raw_sha256
        self.raw_truncated = raw_truncated

    def __repr__(self):
        return (f"SanitizeResult(final_len={self.final_len}, "
                f"stripped={self.bytes_stripped}, "
                f"iter={self.iterations})")


def _apply_line_flattening(text):
    """Turn line structure into spaces.

    A body that spans multiple lines, or that uses a carriage return
    to overwrite the attribution header the client prepends, is a
    cross-operator attack launched from a single message. After
    this step the body has no line breaks of any kind.
    """
    return (text.replace('\r\n', ' ')
                .replace('\r', ' ')
                .replace('\n', ' ')
                .replace('\t', ' '))


def _count_combining_runs(text, cap):
    """Enforce an upper bound on combining marks per base character.

    Anti-Zalgo. A base character followed by thousands of combining
    marks is one grapheme visually and thousands of codepoints to
    len(). A message like that turns a single row of chat into a
    scribble. The cap is per-run: whenever more than `cap` marks
    stack on one base, the extra marks are dropped and the run is
    counted.

    Returns (text, hits).
    """
    if not text:
        return text, 0

    out = []
    run = 0
    hits = 0

    for ch in text:
        if unicodedata.category(ch) in _COMBINING_CATEGORIES:
            run += 1
            if run > cap:
                hits += 1
                continue
            out.append(ch)
        else:
            run = 0
            out.append(ch)

    return ''.join(out), hits


def _iterative_strip(text, max_iters=4):
    """Apply the escape-removal pass until the string stops changing.

    A single pass handles the common case. Iteration handles nested
    attacks: a body whose outer sequence contains a well-formed
    inner sequence. `ESC [ ESC [ 31m` fails the CSI regex on the
    first pass (the params contain an ESC), the C0 strip removes
    both ESCs, and `[31m` falls through as visible text unless the
    stripper runs again.

    The iteration count is bounded so a pathological input cannot
    force a long loop; four passes handle any nesting the terminal
    itself would resolve, because terminals do not recursively
    interpret their own output.
    """
    prev = None
    iterations = 0
    for _ in range(max_iters):
        iterations += 1
        cur = _ANSI_CSI_RE.sub('', text)
        cur = _ANSI_OSC_RE.sub('', cur)
        cur = _CTRL_RE.sub('', cur)
        cur = _UNICODE_FORMAT_RE.sub('', cur)
        if cur == prev or cur == text:
            return cur, iterations
        prev = text
        text = cur
    return text, iterations


def sanitize(text, *, max_combining=3, max_length=None):
    """Return a SanitizeResult for `text`.

    Pipeline, in order:

      1. Reject non-strings.
      2. Flatten line structure: CR, LF, CRLF, TAB become spaces.
      3. Iteratively strip ANSI CSI, ANSI OSC, C0/C1/DEL, and
         Unicode formatting controls, until the string stabilizes
         or the iteration cap is reached.
      4. NFC-normalize so two visually identical strings compare
         equal.
      5. Enforce an anti-Zalgo cap on combining marks per base.
      6. Collapse runs of spaces and trim.
      7. Enforce `max_length` if given.

    `max_length` is checked against the sanitized form, not the
    original. A message that is 4096 bytes of control sequences and
    one visible character should be accepted; one that is 4096
    visible characters should be rejected.
    """
    if not isinstance(text, str):
        raise ValueError('text must be a string')

    original_len = len(text)
    original = text

    text = _apply_line_flattening(text)

    before = len(text)
    text, iterations = _iterative_strip(text)
    bytes_stripped = before - len(text)

    text = unicodedata.normalize('NFC', text)

    text, combining_hits = _count_combining_runs(text, max_combining)
    if combining_hits:
        bytes_stripped += combining_hits

    text = re.sub(r' {2,}', ' ', text).strip()

    if max_length is not None and len(text) > max_length:
        raise ValueError(
            f'message too long (max {max_length} characters '
            f'after sanitization)')

    raw_b64 = None
    raw_sha256 = None
    raw_truncated = False
    if bytes_stripped > 0 or original_len != len(text):
        import base64 as _b64
        import hashlib as _hl
        raw_bytes = original.encode('utf-8', errors='replace')
        raw_sha256 = _hl.sha256(raw_bytes).hexdigest()
        raw_b64 = _b64.b64encode(raw_bytes).decode('ascii')
        if len(raw_b64) > 3000:
            raw_b64 = raw_b64[:3000]
            raw_truncated = True

    return SanitizeResult(
        text=text,
        original_len=original_len,
        bytes_stripped=bytes_stripped,
        combining_cap_hits=combining_hits,
        iterations=iterations,
        raw_b64=raw_b64,
        raw_sha256=raw_sha256,
        raw_truncated=raw_truncated,
    )


def _sanitize_chat_text(text: str) -> str:
    """Backwards-compatible wrapper.

    Every existing caller expects a string and nothing else. This
    keeps that contract while the richer `sanitize()` function
    carries the counters. New callers should prefer `sanitize()`;
    callers that only need the text can stay on this.
    """
    return sanitize(text).text


class FileStore:
    """Content-addressed blob store for chat file sharing.

    The server never opens, parses, sniffs, or executes a stored
    file. It writes bytes to a path derived from the file's
    SHA-256 and serves those bytes back on request. No parser, no
    MIME detection, no execution path.

    Storage path: <base_dir>/<sha256>, where sha256 is 64
    lowercase hex. No extension, no original name, no user input
    anywhere in the path. Two uploads of the same bytes
    deduplicate automatically.

    Caps. Three of them, all refuse rather than prune:

      * MAX_FILE_BYTES  — per-file. A single oversized upload is
        rejected before any disk I/O.
      * MAX_TOTAL_BYTES — cumulative. Uploads that would push the
        store over the limit are rejected; existing files are
        never deleted to make room, because the audit chain may
        reference any hash that was ever stored.
      * MAX_FILES       — inode guard. A flood of tiny files hits
        this before it hits the byte cap.

    The base64 upload of a 64 MiB file is ~85.3 MiB. The Flask
    app is configured with MAX_CONTENT_LENGTH from
    constants.MAX_REQUEST_BYTES; that value must be at least
    ~90 MiB or uploads near the cap are rejected by Flask with a
    413 before the handler ever runs. Raise MAX_REQUEST_BYTES if
    you raise MAX_FILE_BYTES further.

    Concurrency note: a single 90 MiB request occupies roughly
    180 MiB in flight (the decoded bytes plus the base64 body plus
    the JSON envelope). MAX_CONCURRENT_PER_OPERATOR caps a single
    operator at six in-flight requests, but a coordinated upload
    from several operators can push memory into the hundreds of
    megabytes. On a small VPS, lower MAX_FILE_BYTES or
    MAX_CONCURRENT_PER_OPERATOR in tandem.
    """

    MAX_FILE_BYTES  = 64 * 1024 * 1024        # 64 MiB per file
    MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB cumulative
    MAX_FILES       = 4096

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
        self._rescan()

    @staticmethod
    def is_valid_hash(h: str) -> bool:
        """True when h is exactly 64 lowercase hex characters.
        Called before any path is constructed from the hash, so
        no traversal is possible even from a hostile hash."""
        if not isinstance(h, str) or len(h) != 64:
            return False
        return all(c in '0123456789abcdef' for c in h)

    def _rescan(self) -> None:
        """Rebuild the index by walking the store directory.

        Each blob is stored as a pair of files:
          <sha256>        the bytes
          <sha256>.meta   a small JSON file with owner and ts

        A blob whose name is not a valid hash is skipped — it is
        not in the store, and the server will never serve it. A
        blob with no `.meta` sidecar loads with an empty owner,
        which no requester can match; it becomes undeletable
        through the API and can only be removed by an operator
        with filesystem access. That is the correct default for
        a blob whose provenance cannot be established (e.g. one
        uploaded by an older server version).
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
                name = ''
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
                            name = meta['name']
                    except (OSError, ValueError):
                        pass
                self._index[h] = {
                    'size':  size,
                    'owner': owner,
                    'ts':    ts,
                    'name':  name,
                }
            self._total_bytes = total

    def store(self, data: bytes, uploaded_by: str = '',
              display_name: str = '') -> dict:
        """Store `data` and return {sha256, size, deduped}.

        Raises ValueError on a cap violation, OSError on a disk
        failure. On success the bytes are durable before the
        method returns — the file is written to a temp name,
        fsynced, then atomically renamed into place. A crash mid-
        write cannot leave a partial blob in the store.
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
                    f'file store full ({self.MAX_FILES} files)')
            if self._total_bytes + size > self.MAX_TOTAL_BYTES:
                raise ValueError(
                    f'file store full '
                    f'({self._total_bytes + size} > '
                    f'{self.MAX_TOTAL_BYTES} bytes)')

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
                        'owner': uploaded_by or '',
                        'ts':    time.time(),
                        'name':  display_name or '',
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
                'size':  size,
                'owner': uploaded_by or '',
                'ts':    time.time(),
                'name':  display_name or '',
            }
            self._total_bytes += size
            return {
                'sha256':  digest,
                'size':    size,
                'deduped': False,
                'owner':   uploaded_by or '',
            }

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

    def delete(self, digest: str, requester: str) -> dict:
        """Delete a stored file if `requester` is its owner.

        Raises ValueError on a malformed hash, FileNotFoundError
        if the hash is not in the store, PermissionError if the
        caller is not the owner, OSError on a disk failure.

        Ownership semantics. The owner is the operator who first
        uploaded the bytes. A later upload of the same bytes by a
        different operator deduplicates to the existing blob and
        does *not* transfer ownership — the first uploader keeps
        it. If the owner deletes the file, any other operator's
        message that referenced the same hash becomes a dangling
        pointer: the announcement stays in the chat ring and in
        the audit chain, but a `/get` on the hash returns 404.
        This is the correct trade for a team tool — the operator
        who paid for the upload decides when it goes away, and a
        dedup is never a claim of ownership.

        A blob with no recorded owner (uploaded by an older
        server version, or written before the meta sidecar
        existed) refuses every delete. Recovering those requires
        filesystem access on the team server.
        """
        if not self.is_valid_hash(digest):
            raise ValueError('invalid hash')

        with self._lock:
            entry = self._index.get(digest)
            if entry is None:
                raise FileNotFoundError(digest)

            owner = entry.get('owner', '') or ''
            if not owner:
                raise PermissionError(
                    'file has no recorded owner; cannot delete')
            if owner != requester:
                raise PermissionError(
                    f'file is owned by {owner!r}')

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
                'sha256': digest,
                'size':   entry.get('size', 0),
                'owner':  owner,
            }

    def stat(self, digest: str):
        with self._lock:
            entry = self._index.get(digest)
        return dict(entry) if entry else None

    def total_bytes(self) -> int:
        with self._lock:
            return self._total_bytes

    def count(self) -> int:
        with self._lock:
            return len(self._index)

    def list_all(self) -> list:
        """Return a snapshot of every stored blob as a list of
        dicts.

        The lock is held only for the copy, not for anything the
        caller does with the result — the caller can sort, render,
        or audit without blocking a concurrent upload. Used by
        the /chat/files listing endpoint so the listener never
        reaches into the store's private index.
        """
        with self._lock:
            return [{
                'sha256': h,
                'size':   e.get('size', 0),
                'owner':  e.get('owner', ''),
                'name':   e.get('name', '') or '',
                'ts':     e.get('ts', 0.0),
            } for h, e in self._index.items()]


class ChatRoom:

    MAX_MESSAGES = 10000
    MAX_TEXT_LEN = 4096
    MAX_PERSISTED_LINES = 4000
    COMPACT_EVERY_WRITES = 1000

    def __init__(self, persist_dir: str = None):
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._messages: deque = deque(maxlen=self.MAX_MESSAGES)
        self._next_id = 1
        self._writes_since_compact = 0
        self._topic: dict = {
            'text':   '',
            'set_by': '',
            'set_at': 0.0,
        }
        self._persist_dir = persist_dir
        if persist_dir:
            try:
                os.makedirs(persist_dir, exist_ok=True)
            except OSError:
                self._persist_dir = None

        if persist_dir:
            try:
                self.files = FileStore(
                    os.path.join(persist_dir, 'files'))
            except Exception:
                self.files = None
        else:
            self.files = None

        if self._persist_dir:
            self._load_persisted()

    # ------------------------------------------------------------------
    # Write

    KINDS = ('chat', 'action', 'notice', 'dm', 'file')

    def post(self, operator: str, role: str, text: str,
             kind: str = 'chat', source_ip: str = '',
             recipient: str = '', file_hash: str = '',
             file_size: int = 0) -> dict:
        """Append a message and wake every waiting reader.

        `kind` is 'chat' for a normal line and 'action' for the
        IRC-style /me form ("alice staged the payload"). Clients
        render the two differently — chat as a normal message,
        action as a colored italic-style line with an asterisk
        before the speaker — but the server does not care which
        is which beyond echoing the field.

        `source_ip` is the mTLS peer's IP, set by the caller from
        `request.remote_addr`. It is written to the on-disk mirror
        only — never into the in-memory message, so it does not
        travel over the wire to other operators.

        Raises ValueError on empty or oversized input so the caller
        can return 400 rather than silently accepting a blank line
        or truncating a paste.
        """
        if kind not in self.KINDS:
            raise ValueError(f'invalid message kind: {kind!r}')
        if not isinstance(text, str):
            raise ValueError('text must be a string')

        recipient = (recipient or '').strip()
        if kind == 'dm':
            if not recipient:
                raise ValueError('dm requires a recipient')
            if recipient == operator:
                raise ValueError('cannot dm yourself')
            if recipient == 'room':
                raise ValueError("'room' is a reserved name, not "
                                 "a recipient")
        else:
            recipient = ''

        file_hash = (file_hash or '').strip().lower()
        if kind == 'file':
            if self.files is None:
                raise ValueError('file store not configured')
            if not FileStore.is_valid_hash(file_hash):
                raise ValueError('file requires a sha256')
            if not isinstance(file_size, int) or file_size <= 0:
                raise ValueError('file requires a positive size')
            if self.files.stat(file_hash) is None:
                raise ValueError('file hash not in store')
        else:
            file_hash = ''
            file_size = 0

        text = _sanitize_chat_text(text)
        if not text:
            raise ValueError('empty message')
        if len(text) > self.MAX_TEXT_LEN:
            raise ValueError(
                f'message too long (max {self.MAX_TEXT_LEN} '
                f'characters)')

        with self._cond:
            msg = {
                'id':        self._next_id,
                'ts':        time.time(),
                'operator':  operator,
                'role':      role,
                'kind':      kind,
                'text':      text,
                'recipient': recipient,
                'file_hash': file_hash,
                'file_size': file_size,
            }
            self._next_id += 1
            self._messages.append(msg)
            if self._persist_dir:
                self._persist(msg, source_ip)
            self._cond.notify_all()
            return msg

    # ------------------------------------------------------------------
    # On-disk mirror

    def _persist(self, msg: dict, source_ip: str) -> None:
        """Append one message to both on-disk files.

        Two files, two purposes:

          * chat.txt    — human-readable mirror for `tail -f`
                          and grep. Grows unbounded; managed by
                          an external logrotate policy.
          * chat.jsonl  — structured one-line-per-message store.
                          Read at startup to repopulate the ring.
                          Compacted on load and periodically
                          during long sessions so it stays
                          bounded.

        Best-effort. A disk-full or permission error is swallowed:
        the audit chain already holds the authoritative record and
        an in-memory chat should not fail because the disk is
        unavailable.
        """
        try:
            path = os.path.join(self._persist_dir, 'chat.txt')
            with open(path, 'a', encoding='utf-8') as fh:
                fh.write(self._render_human(msg, source_ip) + '\n')
        except OSError:
            pass
        try:
            path = os.path.join(self._persist_dir, 'chat.jsonl')
            with open(path, 'a', encoding='utf-8') as fh:
                fh.write(json.dumps(msg, ensure_ascii=False)
                         + '\n')
            self._writes_since_compact += 1
            if self._writes_since_compact >= self.COMPACT_EVERY_WRITES:
                self._writes_since_compact = 0
                self._compact_persisted()
        except OSError:
            pass

    @staticmethod
    def _render_human(msg: dict, source_ip: str) -> str:
        """One-line human rendering for the on-disk mirror."""
        ts = time.strftime(
            '%Y-%m-%d %H:%M:%S',
            time.localtime(msg.get('ts', 0)))
        who = msg.get('operator', '?')
        role = msg.get('role', '') or ''
        if role and role not in ('operator', 'local'):
            who += f'@{role}'
        ip = f' ({source_ip})' if source_ip else ''
        kind = msg.get('kind', 'chat')
        text = msg.get('text', '')
        if kind == 'chat':
            marker = '❯'
        elif kind == 'action':
            marker = '*'
        elif kind == 'file':
            marker = '📎'
        else:  # notice
            marker = '--'
        return f'{ts}  {who}{ip}  {marker} {text}'

    # ------------------------------------------------------------------
    # Persistence

    def _load_persisted(self) -> None:
        """Rehydrate the in-memory ring from chat.jsonl.

        Called from __init__ when a persist_dir is configured.
        Reads the tail of the file, parses each line as a message
        dict, and pushes them into the ring in order. Messages
        whose IDs are already higher than _next_id advance it so
        new messages do not reuse IDs after a restart.

        Also compacts the file to its last MAX_MESSAGES lines so
        the on-disk store does not grow without bound across
        restarts. The compaction is atomic — a crash mid-write
        leaves either the old file or the new one, never a
        partial file.

        Corrupt or truncated lines are skipped. A file that has
        been hand-edited to break the format should not prevent
        the server from starting.
        """
        path = os.path.join(self._persist_dir, 'chat.jsonl')
        if not os.path.exists(path):
            return

        lines = []
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        lines.append(line)
        except OSError:
            return

        keep = lines[-self.MAX_MESSAGES:]

        parsed = []
        max_id = 0
        for line in keep:
            try:
                msg = json.loads(line)
            except (ValueError, TypeError):
                continue
            if not isinstance(msg, dict):
                continue
            if 'id' not in msg or 'text' not in msg \
                    or 'kind' not in msg:
                continue
            parsed.append(msg)
            mid = msg.get('id', 0)
            if isinstance(mid, int) and mid > max_id:
                max_id = mid

        with self._lock:
            for msg in parsed:
                self._messages.append(msg)
            if max_id >= self._next_id:
                self._next_id = max_id + 1

        self._rewrite_persisted(parsed)

    def _rewrite_persisted(self, messages) -> None:
        """Atomically replace chat.jsonl with the given messages.

        Write to a temp file, fsync, rename into place. A crash
        at any point leaves either the old file or the new one.
        """
        path = os.path.join(self._persist_dir, 'chat.jsonl')
        tmp = path + '.tmp'
        try:
            with open(tmp, 'w', encoding='utf-8') as fh:
                for msg in messages:
                    fh.write(json.dumps(msg, ensure_ascii=False)
                             + '\n')
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except OSError:
                    pass
            os.replace(tmp, path)
        except OSError:
            try:
                os.remove(tmp)
            except OSError:
                pass

    def _compact_persisted(self) -> None:
        """Trim chat.jsonl to its last MAX_PERSISTED_LINES entries.

        Called every COMPACT_EVERY_WRITES writes during a long
        session, so the file stays bounded without a restart. The
        in-memory ring is not consulted — this reads the file
        directly and rewrites it, which is what keeps the
        operation O(file) rather than O(ring).
        """
        path = os.path.join(self._persist_dir, 'chat.jsonl')
        if not os.path.exists(path):
            return
        lines = []
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        lines.append(line)
        except OSError:
            return
        if len(lines) <= self.MAX_PERSISTED_LINES:
            return
        keep = lines[-self.MAX_PERSISTED_LINES:]
        tmp = path + '.tmp'
        try:
            with open(tmp, 'w', encoding='utf-8') as fh:
                for line in keep:
                    fh.write(line + '\n')
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except OSError:
                    pass
            os.replace(tmp, path)
        except OSError:
            try:
                os.remove(tmp)
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Read

    @staticmethod
    def _visible_to(msg: dict, viewer) -> bool:
        """True when `msg` should be delivered to `viewer`.

        Broadcast messages (no recipient) are visible to everyone.
        A direct message is visible only to its sender and its
        recipient. `viewer=None` disables the filter entirely —
        used by internal callers and tests, not by any HTTP
        endpoint.
        """
        if viewer is None:
            return True
        recipient = msg.get('recipient') or ''
        if not recipient:
            return True
        return (msg.get('operator') == viewer
                or recipient == viewer)

    def since(self, after_id: int, timeout: float = 0.0,
              viewer=None) -> List[dict]:
        """Return every message with id > after_id visible to
        `viewer`.

        With a positive `timeout`, blocks up to that many seconds
        for at least one visible message to arrive. Returns an
        empty list if nothing arrived in the window. Used by the
        long-poll endpoint.

        The filter is O(n) over the ring, and n is bounded by
        MAX_MESSAGES, so this stays cheap even at the limit.
        `viewer=None` disables the DM filter; HTTP callers always
        pass a CN.
        """
        def _snap():
            return [m for m in self._messages
                    if m['id'] > after_id
                    and self._visible_to(m, viewer)]

        if timeout <= 0.0:
            with self._lock:
                return _snap()

        deadline = time.monotonic() + timeout
        with self._cond:
            while True:
                msgs = _snap()
                if msgs:
                    return msgs
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return []
                self._cond.wait(timeout=remaining)

    def history(self, limit: int = 50, viewer=None,
                peer=None) -> List[dict]:
        """Return the last `limit` messages, oldest first.

        Three modes:

          * viewer=None, peer=None — every message. Internal
            use only (tests, administrative tooling). Not
            reachable from any HTTP endpoint.
          * viewer='alice', peer=None — the broadcast room as
            seen by alice. DMs are excluded; the entry-time
            scrollback shows the room, not a DM thread.
          * viewer='alice', peer='bob' — the DM thread between
            alice and bob, oldest first.
        """
        if limit <= 0:
            return []
        with self._lock:
            msgs = list(self._messages)

        if viewer is None:
            return msgs[-limit:]

        if peer is None:
            filtered = [m for m in msgs
                        if not (m.get('recipient') or '')]
        else:
            filtered = [
                m for m in msgs
                if (m.get('operator') in (viewer, peer)
                    and m.get('recipient') in (viewer, peer)
                    and m.get('recipient') != m.get('operator'))
            ]
        return filtered[-limit:]

    def last_id(self) -> int:
        """The id of the newest message, or 0 if the room is empty.
        Used by the client to seed its poll cursor."""
        with self._lock:
            if not self._messages:
                return 0
            return self._messages[-1]['id']

    def persistent_history(self, limit: int = 50, viewer=None,
                           peer=None) -> List[dict]:
        """Return the last `limit` messages from the on-disk store.

        Reads chat.jsonl directly, so this returns messages from
        before the current process started — the messages the
        in-memory ring cannot see after a restart, and the
        messages that have rotated off the ring during a long
        session. The normal `history()` call returns the ring;
        this one returns what was written to disk.

        Same filter semantics as `history()`:

          * viewer=None, peer=None — every message on disk. Only
            reachable from tests and internal tooling.
          * viewer='alice', peer=None — the broadcast room as
            seen by alice. DMs are excluded.
          * viewer='alice', peer='bob' — the DM thread between
            alice and bob, oldest first.

        Runs without the ring lock — the file is opened fresh
        and read to the end on each call. Chat volumes are small
        enough that this is cheaper than threading the lock
        through a file read, and it means a slow disk cannot
        block live chat.
        """
        if limit <= 0:
            return []
        if not self._persist_dir:
            return []
        path = os.path.join(self._persist_dir, 'chat.jsonl')
        if not os.path.exists(path):
            return []

        lines = []
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        lines.append(line)
        except OSError:
            return []

        parsed = []
        for line in lines[-self.MAX_PERSISTED_LINES:]:
            try:
                msg = json.loads(line)
            except (ValueError, TypeError):
                continue
            if not isinstance(msg, dict):
                continue
            if 'id' not in msg or 'text' not in msg \
                    or 'kind' not in msg:
                continue
            parsed.append(msg)

        if viewer is None:
            return parsed[-limit:]

        if peer is None:
            filtered = [m for m in parsed
                        if not (m.get('recipient') or '')]
        else:
            filtered = [
                m for m in parsed
                if (m.get('operator') in (viewer, peer)
                    and m.get('recipient') in (viewer, peer)
                    and m.get('recipient') != m.get('operator'))
            ]
        return filtered[-limit:]

    # ------------------------------------------------------------------
    # Topic

    MAX_TOPIC_LEN = 256

    def get_topic(self) -> dict:
        """Return a copy of the current pinned topic. Empty text
        means no topic is set."""
        with self._lock:
            return dict(self._topic)

    def set_topic(self, text: str, operator: str):
        """Set or clear the pinned topic.

        Returns (old, new) so the caller can audit both ends of
        the change. Empty `text` clears. The text is sanitized
        the same way message bodies are — it renders on every
        operator's terminal, so it carries the same control-
        sequence risk.
        """
        text = _sanitize_chat_text(text or '')
        if len(text) > self.MAX_TOPIC_LEN:
            text = text[:self.MAX_TOPIC_LEN].rstrip()
        with self._lock:
            old = dict(self._topic)
            self._topic = {
                'text':   text,
                'set_by': operator,
                'set_at': time.time(),
            }
            return old, dict(self._topic)