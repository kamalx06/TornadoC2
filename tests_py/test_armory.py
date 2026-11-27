"""Per-operator armory install/uninstall and safety checks."""
import hashlib
import json
import os
import tempfile
import unittest

from support import TempState
from tornado_client.repl import Client


class ArmoryTest(TempState):
    def setUp(self):
        super().setUp()
        from pathlib import Path
        from tornadoc2_mcp import paths
        self._old_state = paths.STATE_DIR
        paths.STATE_DIR = Path(self._tmp.name) / 'state'
        paths.ARMORY_DIR = paths.STATE_DIR / 'armory'
        paths.PINS_DIR = paths.STATE_DIR / 'pins'
        self.repo = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.repo, 'bofs', 'ok'))
        self.bof = b'MZ\x00\x00' + b'x' * 40
        open(os.path.join(self.repo, 'bofs', 'ok', 'ok.o'),
             'wb').write(self.bof)
        self.index = {'version': 1, 'bofs': [{
            'name': 'ok', 'format': 'coff-x64', 'description': 't',
            'sha256': hashlib.sha256(self.bof).hexdigest(),
            'path': 'bofs/ok/ok.o', 'file': 'ok.o'}]}
        open(os.path.join(self.repo, 'index.json'), 'w').write(
            json.dumps(self.index))
        self.c = object.__new__(Client)
        os.environ['TORNADOC2_ARMORY_KEYS'] = 'off'
        self.c.caps = ['armory.view', 'armory.manage']
        self.c.ARMORY_BASE = 'file://' + self.repo

    def run_armory(self, *args):
        Client._cmd_armory(self.c, ['armory', *args])

    def test_install_lookup_uninstall(self):
        self.run_armory('update')
        self.run_armory('install', 'ok')
        got = Client._armory_lookup(self.c, 'ok')
        self.assertEqual(got[0], self.bof)
        self.assertEqual(got[1], 'coff-x64')
        self.assertIn('ok', Client._armory_installed(self.c))
        self.run_armory('uninstall', 'ok')
        self.assertEqual(Client._armory_installed(self.c), {})

    def test_digest_mismatch(self):
        self.index['bofs'][0]['sha256'] = '0' * 64
        open(os.path.join(self.repo, 'index.json'), 'w').write(
            json.dumps(self.index))
        self.run_armory('update')
        self.run_armory('install', 'ok')
        self.assertNotIn('ok', Client._armory_installed(self.c))

    def test_traversal_rejected(self):
        self.index['bofs'][0]['path'] = '../outside.o'
        open(os.path.join(self.repo, 'index.json'), 'w').write(
            json.dumps(self.index))
        self.run_armory('update')
        self.run_armory('install', 'ok')
        self.assertNotIn('ok', Client._armory_installed(self.c))

    def test_viewer_denied(self):
        self.c.caps = []
        self.run_armory('list-all')

    def _sign(self):
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        key = Ed25519PrivateKey.generate()
        body = open(os.path.join(self.repo, 'index.json'), 'rb').read()
        open(os.path.join(self.repo, 'index.json.sig'), 'wb').write(
            base64.b64encode(key.sign(body)))
        os.environ['TORNADOC2_ARMORY_KEYS'] = base64.b64encode(
            key.public_key().public_bytes_raw()).decode()
        return key

    def tearDown(self):
        from tornadoc2_mcp import paths
        paths.STATE_DIR = self._old_state
        paths.ARMORY_DIR = self._old_state / 'armory'
        paths.PINS_DIR = self._old_state / 'pins'
        os.environ.pop('TORNADOC2_ARMORY_KEYS', None)
        super().tearDown()

    def test_signed_index_accepted(self):
        self._sign()
        self.run_armory('update')
        self.run_armory('install', 'ok')
        self.assertIn('ok', Client._armory_installed(self.c))

    def test_tampered_index_rejected(self):
        self._sign()
        data = json.load(open(os.path.join(self.repo, 'index.json')))
        data['bofs'][0]['description'] = 'evil'
        open(os.path.join(self.repo, 'index.json'), 'w').write(
            json.dumps(data))
        self.run_armory('update')
        with self.assertRaises(RuntimeError):
            Client._armory_index(self.c)


if __name__ == '__main__':
    unittest.main()
