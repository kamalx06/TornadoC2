"""Credential vault.

Engagement-wide shared store for credentials collected during an
operation. Records are keyed by a short hex id and persist to
``logs/creds.json``.

Two things are stored per record:

  * The credential itself — user, domain, kind, value. The value is
    opaque bytes from this module's perspective; the shape is only
    meaningful to the consumer.
  * Provenance and validation state — which beacon the credential
    came from, who added it, when it was last validated, by which
    beacon, and what the check returned.

Validation is not performed here. The team server is almost never
on the network where the credential is useful, and a bind attempt
from the wrong network either fails silently or leaks the attempt
to a system the engagement was not authorised to touch. The
check runs on a beacon (see the ``cred_validate`` verb in the
agent) and the result is POSTed back to ``/api/v1/creds/validate``,
which calls ``CredStore.validate`` below.

**The credential value is never written to the audit chain.** The
``creds.add``, ``creds.get``, and ``creds.validate`` entries record
the record id, user, domain, kind, and source beacon only. An
operator who steals the audit log learns that a credential exists
and where it came from, not what it is.
"""

from __future__ import annotations

import os
import secrets
import threading
import time
from typing import Optional


class CredStore:

    # ------------------------------------------------------------------
    # Kinds
    
    KINDS = (
        'plaintext',
        'ntlm',
        'lm',
        'sha1',
        'aes256',
        'aes128',
        'krbtgt',
        'ticket',
        'cert',
        'token',
        'bearer',
        'ssh_key',
        'other',
    )

    # Kinds for which a validation check exists. A record whose kind
    # is not in this set can be stored and retrieved, but ``creds
    # validate`` will refuse with a clear message rather than
    # enqueueing a task the beacon cannot handle.
    #
    # What is in the set today, and where it is implemented:
    #
    #   plaintext   Windows LogonUserW  | Linux LDAP simple bind
    #   ntlm        Windows LsaLogonUser (MSV1_0)  | Linux: unsupported
    #   lm          Windows LsaLogonUser (MSV1_0)  | Linux: unsupported
    #   ticket      Windows + Linux (structural parse, no KDC call)
    #   cert        Windows + Linux (TLS client-auth handshake)
    #   token       Windows GetTokenInformation  | Linux: unsupported
    #   bearer      Windows + Linux (HTTP HEAD against the issuer)
    #   ssh_key     Windows ssh.exe  | Linux ssh -i
    #
    # `aes256` / `aes128` / `krbtgt` are stored but not validatable:
    # a raw-key check needs a hand-built Kerberos AS-REQ, which is
    # not implemented on either platform. A record with those kinds
    # is still accepted by ``add``; ``validate`` refuses it locally.
    VALIDATABLE = frozenset((
        'plaintext',
        'ntlm',
        'lm',
        'ticket',
        'cert',
        'token',
        'bearer',
        'ssh_key',
    ))

    # Possible validation outcomes. Stored on the entry as
    # ``validation_status``.
    #
    #   unvalidated — never checked
    #   valid       — check succeeded
    #   invalid     — check failed with a rejection
    #   locked      — account is locked out
    #   expired     — password or ticket expired
    #   error       — check could not complete (network, permission)
    #   unsupported — kind has no validation routine
    VALIDATION_STATUSES = frozenset((
        'unvalidated', 'valid', 'invalid', 'locked',
        'expired', 'error', 'unsupported',
    ))

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)

    # ------------------------------------------------------------------
    # Persistence

    def _load(self) -> dict:
        import json
        if not os.path.isfile(self.path):
            return {}
        try:
            with open(self.path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                return {}
            return data
        except (OSError, ValueError):
            return {}

    def _save(self, data: dict) -> None:
        import json
        tmp = self.path + '.tmp'
        try:
            with open(tmp, 'w', encoding='utf-8') as fh:
                json.dump(data, fh, indent=2, sort_keys=True)
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except OSError:
                    pass
            os.replace(tmp, self.path)
        except OSError:
            try:
                os.remove(tmp)
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Write

    def add(self, *, user, domain, kind, value,
            source_beacon, source_path, found_by,
            notes: str = '') -> dict:
        """Record a new credential. Raises ValueError on bad input."""
        if kind not in self.KINDS:
            raise ValueError(
                f'unknown credential kind {kind!r}; valid kinds: '
                f'{", ".join(self.KINDS)}')
        if not user:
            raise ValueError('missing user')
        if value is None:
            value = ''

        cid = secrets.token_hex(4)
        now = time.time()
        entry = {
            'id':           cid,
            'user':         user,
            'domain':       domain,
            'kind':         kind,
            'value':        value,
            'source_beacon': int(source_beacon or 0),
            'source_path':  source_path,
            'found_by':     found_by,
            'found_at':     now,
            'used_by':      [],
            'notes':        notes,
            # Validation state. Populated by ``validate``.
            'validation_status':  'unvalidated',
            'validation_detail':  '',
            'validated_at':       0.0,
            'validated_by':       '',
            'validated_from':     0,
        }
        with self._lock:
            data = self._load()
            data[cid] = entry
            self._save(data)
        return entry

    def delete(self, cid: str) -> Optional[dict]:
        with self._lock:
            data = self._load()
            e = data.pop(cid, None)
            if e is not None:
                self._save(data)
        return e

    def note_used(self, cid: str, beacon: int, verb: str) -> None:
        with self._lock:
            data = self._load()
            e = data.get(cid)
            if e is None:
                return
            used = e.setdefault('used_by', [])
            used.append({'beacon': int(beacon),
                         'verb': verb,
                         'ts': time.time()})
            self._save(data)

    def validate(self, cid: str, *, status: str, detail: str,
                 by: str, from_beacon: int) -> Optional[dict]:
        """Record the outcome of a validation check.

        Called by ``OperatorListener._creds_validate`` after the
        client POSTs the beacon's result back to
        ``/api/v1/creds/validate``. The store does not run the
        check itself — see the module docstring for why.

        `status` must be one of ``VALIDATION_STATUSES``. `detail`
        is a short human-readable string the operator sees on the
        next ``creds get``; it is capped at 512 characters so a
        runaway error message cannot bloat the vault file.

        Returns the updated entry, or None if the id is unknown.
        Raises ValueError on an invalid status.
        """
        if status not in self.VALIDATION_STATUSES:
            raise ValueError(
                f'unknown validation status {status!r}; valid: '
                f'{", ".join(sorted(self.VALIDATION_STATUSES))}')
        with self._lock:
            data = self._load()
            e = data.get(cid)
            if e is None:
                return None
            e['validation_status'] = status
            e['validation_detail'] = (detail or '')[:512]
            e['validated_at']      = time.time()
            e['validated_by']      = by
            e['validated_from']    = int(from_beacon or 0)
            self._save(data)
            return dict(e)

    # ------------------------------------------------------------------
    # Read

    def list(self) -> list:
        with self._lock:
            data = self._load()
        return sorted(data.values(),
                      key=lambda e: e.get('found_at', 0),
                      reverse=True)

    def get(self, cid: str) -> Optional[dict]:
        with self._lock:
            return self._load().get(cid)

    def search(self, term: str) -> list:
        t = (term or '').lower()
        with self._lock:
            data = self._load()
        out = []
        for e in data.values():
            if (t in (e.get('user') or '').lower()
                    or t in (e.get('domain') or '').lower()
                    or t in (e.get('source_path') or '').lower()
                    or t in (e.get('notes') or '').lower()):
                out.append(e)
        return out