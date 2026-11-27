"""Deterministic mutation corpus for the bridge frame reader."""
import json
import os
import random
import socket
import struct
import unittest

from support import ROOT
import sys
sys.path.insert(0, os.path.join(ROOT, 'client'))
from tornado_client import bridge  # noqa: E402


class FrameFuzz(unittest.TestCase):
    def setUp(self):
        self.a, self.b = socket.socketpair()

    def tearDown(self):
        self.a.close()
        self.b.close()

    def feed(self, payload: bytes):
        self.a.sendall(struct.pack('>I', len(payload)) + payload)
        return bridge.read_frame(self.b)

    def test_seed_shapes(self):
        for seed in (b'{}', b'{"method":"ping"}', b'[]', b'0',
                     b'{"a":' + b'1' * 100 + b'}'):
            self.assertIsNotNone(self.feed(seed))

    def test_random_bytes_never_hang(self):
        rnd = random.Random(1234)
        for _ in range(600):
            n = rnd.randrange(0, 400)
            payload = bytes(rnd.randrange(256) for _ in range(n))
            try:
                self.feed(payload)
            except (json.JSONDecodeError, UnicodeDecodeError,
                    bridge.BridgeError):
                pass

    def test_truncated_json(self):
        bad = b'{"a": 1,  '
        self.assertEqual(len(bad), 10)
        self.a.sendall(struct.pack('>I', 10) + bad)
        with self.assertRaises(Exception):
            bridge.read_frame(self.b)

    def test_frame_cap(self):
        # A declared length over the cap is refused before reading.
        self.a.sendall(struct.pack('>I', bridge.MAX_FRAME + 1))
        with self.assertRaises(bridge.BridgeError):
            bridge.read_frame(self.b)

    def test_round_trip(self):
        obj = {'id': 1, 'method': 'ping', 'params': {}}
        raw = json.dumps(obj).encode()
        got = self.feed(raw)
        self.assertEqual(got['method'], 'ping')


if __name__ == '__main__':
    unittest.main()
