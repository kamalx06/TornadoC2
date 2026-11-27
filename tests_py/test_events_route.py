"""Operator API: event scope and automatic operator export."""
import json
import os
import stat
import unittest
from unittest import mock

from support import TempState, free_port
from tornadoc2.team.audit import AuditLog
from tornadoc2.team.operators import OperatorRegistry
from tornadoc2.team.server import MultiplayerState, OperatorListener


class Engine:
    def list_all(self):
        return []

    def get(self, _bid):
        return None

    def enqueue(self, bid, verb, args, timeout=120, queued_by=''):
        return 't1'


class Handler:
    def __init__(self):
        self.beacon = Engine()
        self.colors = {}
        self._listener_manager = None


class ApiTest(TempState):
    def setUp(self):
        super().setUp()
        self.port = free_port()
        self.h = Handler()
        self.engine = Engine()
        self.engine.handler = self.h
        self.audit = AuditLog()
        self.registry = OperatorRegistry(
            base_dir=os.path.join(os.getcwd(), 'team_ca'))
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.h.certfile = os.path.join(root, 'tls_certs', 'server.pem')
        self.h.keyfile = os.path.join(root, 'tls_certs', 'server.key')
        self.listener = OperatorListener(
            self.engine, '127.0.0.1', self.port, self.registry,
            self.audit, self._multiplayer())
        self.client = self.listener._build_app().test_client()
        self.actor = ('alice', 'admin', '1.1.1.1')
        self.listener._extract_peer = lambda: self.actor

    def _multiplayer(self):
        m = MultiplayerState()
        m.set_enabled(True)
        return m

    def test_events_own_scope(self):
        self.actor = ('alice', 'operator', '1.1.1.1')
        self.listener.events.emit('info', 'task', 'mine', cn='alice')
        self.listener.events.emit('info', 'task', 'theirs', cn='bob')
        r = self.client.post('/api/v1/events', json={'since': 0})
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body['scope'], 'own')
        self.assertEqual([e['text'] for e in body['events']], ['mine'])

    def test_events_admin_scope(self):
        self.listener.events.emit('info', 'task', 'theirs', cn='bob')
        r = self.client.post('/api/v1/events', json={'since': 0})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()['scope'], 'all')

    def test_first_poll_starts_at_current_sequence(self):
        self.listener.events.emit('info', 'task', 'old')
        r = self.client.post('/api/v1/events', json={})
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body['events'], [])
        self.assertGreaterEqual(body['next'], 1)

    def test_auth_failure_is_emitted(self):
        self.listener._extract_peer = lambda: (None, None, '9.9.9.9')
        r = self.client.post('/api/v1/events', json={})
        self.assertEqual(r.status_code, 401)
        rows, _ = self.listener.events.read(0, 10, ip='9.9.9.9')
        self.assertTrue(any(e['source'] == 'auth' for e in rows))

    def test_build_invalid_config_returns_fields(self):
        self.listener.build_manager = object()
        self.h._load_build_config = lambda raw, remote=True: (
            None, 'target_os: smb requires windows')
        r = self.client.post('/api/v1/beacon/build', json={
            'target_os': 'linux', 'output_format': 'elf',
            'transport_mode': 'smb'})
        self.assertEqual(r.status_code, 400)
        body = r.get_json()
        self.assertTrue(body.get('fields'))
        self.assertIn('smb_pipe',
                      {f['field'] for f in body['fields']})

    def test_add_auto_exports_a_0600_config(self):
        r = self.client.post(
            '/api/v1/operators/add',
            json={'name': 'bob', 'role': 'operator'})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        body = r.get_json()
        self.assertTrue(body.get('config_b64'))
        export = body.get('export') or {}
        path = export.get('path')
        self.assertTrue(path and os.path.isfile(path))
        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode, 0o600)
        cfg = json.loads(open(path, encoding='utf-8').read())
        self.assertEqual(cfg['name'], 'bob')
        self.assertEqual(cfg['server_port'], self.port)
        self.assertIn('client_key', cfg)
        entries = self.audit.read()
        self.assertTrue(any(
            e.get('action') == 'operator.export'
            and 'auto=1' in (e.get('detail') or '')
            for e in entries))
        rows, _ = self.listener.events.read(0, 20, cn='alice')
        self.assertTrue(any(e['source'] == 'operator' for e in rows))

    def test_add_export_failure_is_non_fatal(self):
        with mock.patch(
                'tornadoc2.team.operators.build_config',
                return_value=(None, 'boom')):
            r = self.client.post(
                '/api/v1/operators/add',
                json={'name': 'carol', 'role': 'viewer'})
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertIsNone(body.get('export'))
        self.assertTrue(body.get('export_error'))
        self.assertIsNotNone(self.registry.get('carol'))


if __name__ == '__main__':
    unittest.main()
