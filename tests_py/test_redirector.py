"""Redirector templates: allowlists, upstream, TLS rules."""
import importlib.util
import os
import unittest

from support import ROOT

spec = importlib.util.spec_from_file_location(
    'redirector', os.path.join(ROOT, 'scripts', 'redirector.py'))
red = importlib.util.module_from_spec(spec)
spec.loader.exec_module(red)


class RedirectorTest(unittest.TestCase):
    def test_passthrough_allowlist(self):
        text = red.render('nginx', 'passthrough',
                          ['a.example', 'b.example'],
                          'https://10.0.0.5:8443')
        self.assertIn('a.example b.example', text)
        self.assertIn('10.0.0.5:8443', text)
        self.assertIn('127.0.0.1:1', text)
        self.assertIn('ssl_preread on', text)

    def test_terminate_requires_cert(self):
        with self.assertRaises(SystemExit):
            red.main(['--kind', 'nginx', '--tls', 'terminate',
                      '--host', 'a', '--upstream', 'https://x:443'])

    def test_terminate_default_server_421(self):
        text = red.render('nginx', 'terminate', ['a.example'],
                          'https://x:443', '/c.pem', '/c.key')
        self.assertIn('return 421', text)
        self.assertIn('/c.pem', text)
        self.assertIn('TLSv1.2 TLSv1.3', text)

    def test_caddy_requires_terminate(self):
        with self.assertRaises(SystemExit):
            red.main(['--kind', 'caddy', '--host', 'a',
                      '--upstream', 'https://x:443'])

    def test_worker_allowlist(self):
        text = red.render('cloudflare', 'terminate', ['a', 'b'],
                          'https://x:443')
        self.assertIn("['a', 'b']", text)
        self.assertIn('421', text)
        self.assertIn("const UPSTREAM = 'https://x:443'", text)

    def test_bad_upstream(self):
        with self.assertRaises(SystemExit):
            red.main(['--kind', 'nginx', '--host', 'a',
                      '--upstream', 'http://x:443'])


if __name__ == '__main__':
    unittest.main()
