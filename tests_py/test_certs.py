"""Cert chains satisfy OpenSSL 3 AKI checks; legacy certs reissue."""
import json
import os
import socket
import ssl
import threading
import unittest

from support import TempState, free_port
from tornadoc2.team.operators import OperatorRegistry, _has_aki


class CertTest(TempState):
    def setUp(self):
        super().setUp()
        self.r = OperatorRegistry(os.getcwd())
        self.r.add('alice', 'operator')

    def test_server_and_client_carry_aki(self):
        self.r.ensure_server_cert()
        self.assertTrue(_has_aki(self.r.server_cert))
        cert = self.r.paths_for('alice')['cert']
        self.assertTrue(_has_aki(cert))

    def test_tls_handshake_verifies(self):
        self.r.ensure_server_cert()
        port = free_port()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.r.server_cert, self.r.server_key)
        srv = socket.socket()
        srv.bind(('127.0.0.1', port))
        srv.listen(1)

        def serve():
            try:
                conn, _ = srv.accept()
                with ctx.wrap_socket(conn, server_side=True):
                    pass
            except Exception:
                pass
            finally:
                srv.close()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        cli = ssl.create_default_context(cafile=self.r.ca_cert)
        with cli.wrap_socket(socket.create_connection(
                ('127.0.0.1', port)), server_hostname='localhost'):
            pass
        t.join(3)

    def test_legacy_cert_is_reissued(self):
        cert = self.r.paths_for('alice')['cert']
        open(cert, 'w').write('-----BEGIN CERTIFICATE-----\n')
        self.r.reissue_legacy_certs()
        self.assertTrue(_has_aki(cert))

    def test_config_signature_round_trip(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        from tornadoc2.beacon_handler import CommandSigner

        signer = CommandSigner()
        cfg = {'name': 'a', 'server_host': 'x'}
        raw = json.dumps(cfg, sort_keys=True,
                         separators=(',', ':')).encode()
        import base64 as _b
        cfg['config_signature_b64'] = _b.b64encode(
            signer.sign(raw)).decode()
        cfg['config_signer_pubkey_pem'] = signer.public_pem
        signed = {k: v for k, v in cfg.items()
                  if k not in ('config_signature_b64',
                               'config_signer_pubkey_pem')}
        canonical = json.dumps(signed, sort_keys=True,
                               separators=(',', ':')).encode()
        import base64
        pub = serialization.load_pem_public_key(
            cfg['config_signer_pubkey_pem'].encode())
        pub.verify(base64.b64decode(cfg['config_signature_b64']),
                   canonical, ec.ECDSA(hashes.SHA256()))


class ExportVerifyTest(TempState):
    def setUp(self):
        super().setUp()
        from pathlib import Path
        from tornadoc2_mcp import paths
        self._old = paths.PINS_DIR
        paths.PINS_DIR = Path(self._tmp.name) / 'pins'
        paths.PINS_DIR.mkdir()

    def tearDown(self):
        from tornadoc2_mcp import paths
        paths.PINS_DIR = self._old
        super().tearDown()

    def test_signed_export_verifies_in_client(self):
        from tornado_client.transport import Transport
        from tornadoc2.beacon_handler import CommandSigner
        import base64

        r = OperatorRegistry(os.getcwd())
        r.add('bob', 'operator')
        r.ensure_server_cert()
        cfg = {'name': 'bob', 'server_host': 'x'}
        raw = json.dumps(cfg, sort_keys=True,
                         separators=(',', ':')).encode()
        signer = CommandSigner()
        cfg['config_signature_b64'] = base64.b64encode(
            signer.sign(raw)).decode()
        cfg['config_signer_pubkey_pem'] = signer.public_pem

        class D:
            cfg = {}
        Transport._verify_config_signature(D(), cfg)  # must not raise

        cfg['name'] = 'mallory'
        with self.assertRaises(RuntimeError):
            Transport._verify_config_signature(D(), cfg)


if __name__ == '__main__':
    unittest.main()
