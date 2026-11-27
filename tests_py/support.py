"""Shared fixtures for the server test suite."""
from __future__ import annotations

import os
import sys
import tempfile
import socket
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, 'client'))


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


def ensure_certs():
    d = os.path.join(ROOT, 'tls_certs')
    os.makedirs(d, exist_ok=True)
    os.makedirs(os.path.join(ROOT, 'mtls_certs'), exist_ok=True)
    cert = os.path.join(d, 'server.pem')
    if not os.path.isfile(cert) or os.path.getsize(cert) < 100:
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
            '-nodes', '-days', '2', '-subj', '/CN=test',
            '-keyout', os.path.join(d, 'server.key'), '-out', cert,
        ], check=True, capture_output=True)
    open(os.path.join(ROOT, 'mtls_certs', 'ca.pem'), 'w').write('x')


class TempState(unittest.TestCase):
    """Isolate writes into a temporary directory."""

    AT_REST_ENV = ('TORNADOC2_AT_REST_KEY_FILE',
                   'TORNADOC2_AT_REST_MARKER',
                   'TORNADOC2_AT_REST_KEY')

    def setUp(self):
        ensure_certs()
        self._env_saved = {}
        for name in self.AT_REST_ENV:
            self._env_saved[name] = os.environ.pop(name, None)
        self._tmp = tempfile.TemporaryDirectory()
        self._old = os.getcwd()
        os.chdir(self._tmp.name)

    def tearDown(self):
        for name, value in getattr(self, '_env_saved', {}).items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        os.chdir(self._old)
        self._tmp.cleanup()
