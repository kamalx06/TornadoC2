"""Operator config builder: host selection, signing and atomic write."""
import json
import os
import stat
import tempfile
import unittest

from support import TempState
from tornadoc2.team import operators


class SignedConfigTest(TempState):
    def setUp(self):
        super().setUp()
        self.reg = operators.OperatorRegistry(
            base_dir=os.path.join(os.getcwd(), 'team_ca'))
        self.reg.add('bob', role='operator', password='')
        from cryptography.hazmat.primitives.asymmetric import ec
        self.key = ec.generate_private_key(ec.SECP256R1())

    def test_build_signs_and_verifies(self):
        blob, err = operators.build_config(
            self.reg, 'bob', host='c2.example', port=4443,
            signer=self.key, signer_desc='test-key')
        self.assertIsNone(err)
        cfg = json.loads(blob)
        self.assertEqual(cfg['server_host'], 'c2.example')
        self.assertEqual(cfg['_signer_desc'], 'test-key')
        signed = {k: v for k, v in cfg.items()
                  if k not in ('config_signature_b64',
                               'config_signer_pubkey_pem')}
        canonical = json.dumps(
            signed, sort_keys=True,
            separators=(',', ':')).encode()
        import base64
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        self.key.public_key().verify(
            base64.b64decode(cfg['config_signature_b64']),
            canonical, ec.ECDSA(hashes.SHA256()))

    def test_wildcard_host_is_replaced(self):
        host = operators.advertised_host('0.0.0.0')
        self.assertNotEqual(host, '0.0.0.0')
        self.assertTrue(host)

    def test_loopback_ipv6_is_kept(self):
        self.assertEqual(operators.advertised_host('::1'), '::1')

    def test_explicit_host_and_port_survive(self):
        blob, _ = operators.build_config(
            self.reg, 'bob', host='10.0.0.5', port=9999)
        cfg = json.loads(blob)
        self.assertEqual(cfg['server_host'], '10.0.0.5')
        self.assertEqual(cfg['server_port'], 9999)

    def test_write_is_atomic_and_0600(self):
        path = os.path.join(os.getcwd(), 'out', 'bob.cfg')
        operators.write_config(path, '{"x":1}')
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(
            os.stat(os.path.dirname(path)).st_mode), 0o700)
        self.assertEqual(open(path, encoding='utf-8').read(), '{"x":1}')

    def test_missing_operator(self):
        blob, err = operators.build_config(self.reg, 'nobody')
        self.assertIsNone(blob)
        self.assertIn('not found', err)

    def test_revoked_operator(self):
        self.reg.remove('bob')
        # re-add then revoke keeps the directory absent; simulate.
        self.reg.add('bob', role='operator', password='')
        entry = self.reg.get('bob')
        self.assertFalse(entry.get('revoked'))
        ops = self.reg
        entries = ops._load()
        entries['bob']['revoked'] = True
        ops._save(entries)
        blob, err = operators.build_config(self.reg, 'bob')
        self.assertIsNone(blob)
        self.assertIn('revoked', err)


class TempDirTest(unittest.TestCase):
    def test_write_creates_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'a', 'b', 'x.cfg')
            operators.write_config(path, 'x')
            self.assertTrue(os.path.isfile(path))


if __name__ == '__main__':
    unittest.main()
