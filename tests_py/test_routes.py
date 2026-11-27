"""Operator API listener routes: status mapping and audit."""
import os
import unittest

from support import ROOT, TempState, free_port
from tornadoc2.beacon.listener_manager import ListenerManager
from tornadoc2.team.audit import AuditLog
from tornadoc2.team.operators import OperatorRegistry
from tornadoc2.team.server import MultiplayerState, OperatorListener

TLS = {'mode': 'server', 'cert_path': ROOT + '/tls_certs/server.pem',
       'key_path': ROOT + '/tls_certs/server.key'}


class EngineBase:
    def list_all(self):
        return []

    def get(self, _sid):
        return None


class Handler:
    beacon = EngineBase()
    colors = {'cyan': '', 'yellow': '', 'red': '', 'end': ''}
    certfile = ROOT + '/tls_certs/server.pem'
    keyfile = ROOT + '/tls_certs/server.key'
    mtls_ca_cert = ROOT + '/mtls_certs/ca.pem'


class RouteTest(TempState):
    def setUp(self):
        super().setUp()
        self.port = free_port()
        self.h = Handler()
        self.h._listener_manager = ListenerManager(
            self.h, store_path=os.path.join(os.getcwd(),
                                            'listeners.json'))

        class Engine:
            def list_all(self):
                return []

            def enqueue(self, bid, verb, args, timeout=120,
                        queued_by=''):
                return f't{bid}'

        self.engine = Engine()
        self.engine.handler = self.h
        self.h.beacon = self.engine
        self.audit = AuditLog()
        self.listener = OperatorListener(
            self.engine, '127.0.0.1', 0, OperatorRegistry(),
            self.audit, self._multiplayer())
        self.client = self.listener._build_app().test_client()
        self.as_role('admin')

    def _multiplayer(self):
        m = MultiplayerState()
        m.set_enabled(True)
        return m

    def as_role(self, role, name='alice'):
        self.listener._extract_peer = lambda: (name, role, '1.1.1.1')

    def create(self, name='a', port=None, **kw):
        body = {'spec': {'type': 'http', 'name': name,
                         'host': '127.0.0.1', 'port': port or self.port,
                         'tls': TLS, **kw}}
        return self.client.post('/api/v1/listeners/create', json=body)

    def test_viewer_denied_and_audited(self):
        self.as_role('viewer')
        r = self.client.post('/api/v1/listeners')
        self.assertEqual(r.status_code, 403)
        self.assertTrue(r.headers.get('X-Audit-Id'))
        entries = self.audit.read()
        self.assertTrue(any(e.get('outcome') == 'denied'
                            for e in entries))

    def test_create_conflict_404_invalid(self):
        r = self.create()
        self.assertEqual(r.status_code, 200)
        lid = r.get_json()['listener']['id']
        self.assertEqual(self.create(name='b').status_code, 200)
        self.assertEqual(
            self.client.post(f'/api/v1/listeners/{lid}/start')
            .status_code, 200)
        self.assertEqual(self.create(name='c').status_code, 409)
        self.assertEqual(
            self.client.post('/api/v1/listeners/nope/start')
            .status_code, 404)
        bad = self.client.post('/api/v1/listeners/create',
                               json={'spec': {'type': 'x'}})
        self.assertEqual(bad.status_code, 400)

    def test_identify_filters(self):
        self.create()
        data = self.client.post('/api/v1/identify').get_json()
        self.assertEqual(len(data['listeners']), 1)
        self.as_role('guardian')
        data = self.client.post('/api/v1/identify').get_json()
        self.assertEqual(data['listeners'], [])

    def test_jump_stage_cached_and_serialized(self):
        import threading
        r = self.create(name='jtls')
        lid = r.get_json()['listener']['id']
        self.client.post(f'/api/v1/listeners/{lid}/start')
        out = []
        lock = threading.Lock()

        def call():
            j = self.client.post('/api/v1/jump/stage',
                                 json={'listener': lid})
            with lock:
                out.append((j.status_code,
                            (j.get_json() or {}).get('sha256')))

        threads = [threading.Thread(target=call) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(out), 4)
        self.assertTrue(all(c == 200 for c, _ in out), out)
        self.assertEqual(len({d for _, d in out}), 1)

    def test_totp_header_is_ignored(self):
        r = self.client.post('/api/v1/beacons', json={},
                             headers={'X-Operator-Totp': '000000'})
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.get_json(), list)

    def test_listener_health_probe_and_route(self):
        r = self.create(name='hp')
        lid = r.get_json()['listener']['id']
        self.client.post(f'/api/v1/listeners/{lid}/start')
        mgr = self.listener._lman()
        cfg = mgr.get(lid)
        self.listener.health.probe(cfg)
        self.assertEqual(self.listener.health.status(lid)['state'], 'ok')
        events = []
        self.listener.health._fire = lambda e, p: events.append(p['to'])
        self.client.post(f'/api/v1/listeners/{lid}/stop')
        from tornadoc2.team.listener_health import FAIL_THRESHOLD
        for _ in range(FAIL_THRESHOLD):
            self.listener.health.probe(cfg)
        self.assertEqual(self.listener.health.status(lid)['state'],
                         'down')
        body = self.client.post('/api/v1/listeners/health',
                                json={}).get_json()
        row = [x for x in body['listeners'] if x['id'] == lid][0]
        self.assertEqual(row['state'], 'down')
        self.assertIn('down', events)
        self.assertIsInstance(row['cert_days_left'], int)
        probe = self.client.post('/api/v1/listeners/health/probe',
                                 json={'listener': lid})
        self.assertEqual(probe.status_code, 409)
        self.client.post(f'/api/v1/listeners/{lid}/start')
        probe = self.client.post('/api/v1/listeners/health/probe',
                                 json={'listener': lid})
        self.assertEqual(probe.status_code, 200)
        self.assertEqual(probe.get_json()['state'], 'ok')

    def test_bad_engagement_does_not_block_start(self):
        path = os.path.join(ROOT, 'logs', 'engagement.json')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, 'wb').write(b'T2ENC1\nAAAA')
        o = OperatorListener(
            self.engine, '127.0.0.1', 0, OperatorRegistry(),
            self.audit, self._multiplayer())
        try:
            self.assertEqual(o.engagement.hosts(), [])
            self.assertTrue(os.path.isfile(path + '.corrupt'))
        finally:
            o.health.stop()
        self.assertTrue(os.path.isabs(
            os.environ.get('TORNADOC2_AT_REST_KEY_FILE', '')))

    def test_audit_verify_route(self):
        self.audit.write('a', 'admin', '1', 'x')
        r = self.client.post('/api/v1/audit/verify', json={})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()['ok'])
        self.as_role('viewer')
        self.assertEqual(
            self.client.post('/api/v1/audit/verify', json={}).status_code,
            403)

    def test_atrest_status_route(self):
        r = self.client.post('/api/v1/atrest', json={'action': 'status'})
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertIn('plaintext', body)
        self.assertIn('migrated', body)
        r = self.client.post('/api/v1/atrest', json={'action': 'migrate'})
        self.assertEqual(r.status_code, 200)

    def test_jump_stager_registers_service_host(self):
        import tornadoc2.beacon.builder as bmod
        seen = {}

        class FakeBuilder:
            def __init__(self, *_a, **_k):
                pass

            def build(self, cfg):
                seen['tags'] = cfg.tags
                path = os.path.join(self_dir, 'stager.exe')
                open(path, 'wb').write(b'x')
                return path

        self_dir = os.path.join(self._tmp.name, 'b')
        os.makedirs(self_dir, exist_ok=True)
        orig = bmod.BeaconBuilder
        bmod.BeaconBuilder = FakeBuilder
        try:
            r = self.create(name='jump')
            lid = r.get_json()['listener']['id']
            self.client.post(f'/api/v1/listeners/{lid}/start')
            j = self.client.post('/api/v1/jump/stage',
                                 json={'listener': lid})
        finally:
            bmod.BeaconBuilder = orig
        self.assertEqual(j.status_code, 200)
        self.assertIn('svc_host', seen.get('tags', ''))

    def test_model_evidence_and_exports(self):
        e = self.client.post('/api/v1/evidence', json={
            'sha256': 'a' * 64, 'name': 'f', 'host': 'h'})
        self.assertEqual(e.status_code, 200)
        m = self.client.post('/api/v1/model', json={})
        self.assertEqual(m.status_code, 200)
        self.assertEqual(m.get_json()['schema'], 2)
        csv = self.client.post('/api/v1/export/ioc', json={})
        self.assertIn('a' * 64, csv.get_json()['csv'])
        stix = self.client.post('/api/v1/export/stix', json={})
        self.assertEqual(stix.get_json()['bundle']['type'], 'bundle')
        self.assertTrue(
            self.client.post('/api/v1/export/mitre', json={})
            .status_code == 200)

    def test_export_headers_and_since(self):
        r = self.client.post('/api/v1/export/ioc', json={})
        self.assertEqual(r.headers.get('X-Filename'), 'iocs.csv')
        m = self.client.post('/api/v1/model', json={'since': 1e12})
        self.assertEqual(m.get_json()['users'], [])
        m = self.client.post('/api/v1/model', json={'limit': 5})
        self.assertEqual(m.status_code, 200)

    def test_bulk_rejects_too_many(self):
        r = self.client.post('/api/v1/bulk', json={
            'action': 'kill', 'ids': list(range(501))})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()['truncated'])

    def test_evidence_loot_link(self):
        from tornadoc2.team.lootstore import LootStore
        self.listener.loot = LootStore(
            os.path.join(self._tmp.name, 'loot'))
        blob = self.listener.loot.store(b'x', uploaded_by='alice',
                                        display_name='dump.bin')
        r = self.client.post('/api/v1/evidence',
                             json={'loot': blob['sha256'], 'host': 'h'})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()['evidence']['name'], 'dump.bin')

    def test_bulk_actions_audited(self):
        r = self.client.post('/api/v1/bulk', json={
            'action': 'task', 'ids': [1, 2], 'verb': 'whoami'})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.get_json()['results']), 2)
        for row in r.get_json()['results']:
            self.assertTrue(row['audit_id'])
        r = self.client.post('/api/v1/bulk', json={
            'action': 'tag', 'ids': [1], 'tag': 'web'})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.aliases_tags(1), ['web'])

    def aliases_tags(self, bid):
        return (self.listener.aliases.get(bid) or {}).get('tags') or []

    def test_publish_requires_build_and_signer(self):
        r = self.client.post('/api/v1/agent/publish', json={})
        self.assertEqual(r.status_code, 400)
        r = self.client.post('/api/v1/agent/publish',
                             json={'build_id': 'nope'})
        self.assertIn(r.status_code, (400, 404))

    def test_beacons_carry_privilege(self):
        class S:
            id = 1
            identity = {'privilege': 'root', 'elevated': True,
                        'integrity': 'root', 'parent_name': 'p'}
            display_name = 'h'
            sleep_interval = 1
            jitter = 0.0
            age = 1
            checkins = 1
            last_addr = '1.2.3.4'
            alive = True
            fingerprint = 'f'
            spawn_to = ''
            listener_id = None
        self.engine.list_all = lambda: [S()]
        row = self.client.post('/api/v1/beacons',
                               json={}).get_json()[0]
        self.assertEqual(row['privilege'], 'root')


if __name__ == '__main__':
    unittest.main()
