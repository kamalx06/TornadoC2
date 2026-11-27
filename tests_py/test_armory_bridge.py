"""Armory shell binding and signed-index behaviour."""
import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from support import TempState

from tornado_client import bridge
from tornadoc2_mcp import paths


class SessionStub:
    caps = ['armory.view', 'armory.manage']

    def require(self):
        return self


class ArmoryShellTest(TempState):
    def setUp(self):
        super().setUp()
        self.tmp = Path(tempfile.mkdtemp())
        self._old_dir = paths.ARMORY_DIR
        paths.ARMORY_DIR = self.tmp
        self._old_session = bridge.SESSION
        bridge.SESSION = SessionStub()
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives import serialization
        self.key = Ed25519PrivateKey.generate()
        pub = self.key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw)
        self.env = mock.patch.dict(
            os.environ, {'TORNADOC2_ARMORY_KEYS': base64.b64encode(pub).decode()})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        paths.ARMORY_DIR = self._old_dir
        bridge.SESSION = self._old_session
        super().tearDown()

    def _signed(self, index: dict) -> tuple[bytes, str]:
        body = json.dumps(index).encode()
        sig = base64.b64encode(self.key.sign(body)).decode()
        return body, sig

    def test_shell_binds_every_armory_helper(self):
        sh = bridge._armory_shell()
        self.assertEqual(sh.ARMORY_BASE, bridge._armory_shell().ARMORY_BASE)
        for name in ('_armory_verify', '_armory_index', '_armory_fetch',
                     '_armory_state', '_armory_installed',
                     '_armory_save_installed', '_armory_log'):
            self.assertTrue(callable(getattr(sh, name)), name)
        self.assertFalse(hasattr(sh, '_cmd_armory'))

    def test_cached_signed_index_is_accepted(self):
        sh = bridge._armory_shell()
        body, sig = self._signed({
            'version': 1,
            'bofs': [{'name': 'whoami', 'format': 'coff-x64'}],
        })
        d = sh._armory_state()
        (d / 'index.json').write_bytes(body)
        (d / 'index.json.sig').write_text(sig, encoding='utf-8')
        rows = sh._armory_index()
        self.assertEqual(rows[0]['name'], 'whoami')

    def test_bad_signature_is_rejected(self):
        sh = bridge._armory_shell()
        body, _ = self._signed({'version': 1, 'bofs': []})
        d = sh._armory_state()
        (d / 'index.json').write_bytes(body)
        (d / 'index.json.sig').write_text('AAAA', encoding='utf-8')
        with self.assertRaises(RuntimeError):
            sh._armory_index()

    def test_fetch_uses_armory_base(self):
        sh = bridge._armory_shell()
        r = mock.Mock()
        r.__enter__ = lambda s: s
        r.__exit__ = lambda *a: None
        r.read.return_value = b'coff'
        with mock.patch('urllib.request.urlopen', return_value=r) as opened:
            self.assertEqual(sh._armory_fetch('bofs/x/out.o'), b'coff')
        self.assertTrue(opened.call_args[0][0].full_url.startswith(
            sh.ARMORY_BASE + '/bofs/x/out.o'))

    def test_list_method_returns_catalogue(self):
        sh = bridge._armory_shell()
        sh._armory_index = lambda refresh=False: [{
            'name': 'whoami', 'format': 'coff-x64'}]
        with mock.patch.object(bridge, '_armory_shell', return_value=sh):
            out = bridge.m_armory_list({})
        self.assertEqual(out['catalogue'][0]['name'], 'whoami')
        self.assertIn('installed', out)


if __name__ == '__main__':
    unittest.main()
