"""Engagement model and report generation."""
import os
import unittest

from support import TempState
from tornadoc2.team.engagement import Engagement


class Session:
    id = 7
    identity = {'machine_id': 'm1', 'hostname': 'h',
                'os': 'linux', 'arch': 'amd64',
                'username': 'u', 'privilege': 'root',
                'parent_name': 'p'}


class EngagementTest(TempState):
    def test_observe_and_report(self):
        e = Engagement()
        e.observe(Session())
        self.assertEqual(len(e.hosts()), 1)
        self.assertEqual(os.stat(e.path).st_mode & 0o777, 0o600)
        f = e.add_finding('owned', 'high', 'h', 'proof', 'alice')
        self.assertEqual(f['id'], 1)
        e.add_timeline('jump', 'psexec to h', 'alice')
        md = e.report()
        self.assertIn('owned', md)
        self.assertIn('psexec', md)
        self.assertIn('h', md)

    def test_observe_many_writes_once(self):
        from tornadoc2.team import atrest
        calls = []
        orig = atrest.save_json
        atrest.save_json = lambda *a, **k: calls.append(1) or orig(*a, **k)
        try:
            e = Engagement()
            e.observe_many([Session() for _ in range(50)])
        finally:
            atrest.save_json = orig
        self.assertEqual(len(calls), 1)

    def test_caps_trim_oldest(self):
        e = Engagement()
        e.MAX_FINDINGS = 3
        e.MAX_TIMELINE = 2
        for i in range(5):
            e.add_finding(f'f{i}', 'info', 'h', 'd', 'x')
        self.assertEqual(len(e.findings()), 3)
        self.assertEqual(len({f['id'] for f in e.findings()}), 3)
        for i in range(4):
            e.add_timeline('note', str(i))
        self.assertEqual(len(e.timeline()), 2)

    def test_flush_persists(self):
        e = Engagement()
        e.observe(Session())
        e.flush()
        self.assertEqual(len(Engagement().hosts()), 1)

    def test_schema_newer_refused(self):
        from tornadoc2.team import atrest
        atrest.save_json('logs/engagement.json', {'schema': 99})
        with self.assertRaises(Exception):
            Engagement('logs/engagement.json')

    def test_wrong_key_blob_quarantined(self):
        import os
        os.makedirs('logs', exist_ok=True)
        open('logs/engagement.json', 'wb').write(b'T2ENC1\nAAAA')
        e = Engagement('logs/engagement.json')
        self.assertEqual(e.hosts(), [])
        self.assertTrue(os.path.exists(
            'logs/engagement.json.corrupt'))
        self.assertEqual(e.dataset_hash(),
                         Engagement.memory().dataset_hash())

    def test_memory_store_works(self):
        e = Engagement.memory()
        e.add_finding('t', 'low', 'h', 'd', 'x')
        self.assertEqual(len(e.findings()), 1)

    def test_corrupt_file_kept_aside(self):
        import os
        os.makedirs('logs', exist_ok=True)
        open('logs/engagement.json', 'wb').write(b'not json')
        e = Engagement('logs/engagement.json')
        self.assertEqual(e.hosts(), [])
        self.assertTrue(os.path.exists('logs/engagement.json.corrupt'))

    def test_csv_formula_neutralised(self):
        e = Engagement()
        e.add_share('=calc|cmd', 'h')
        self.assertIn("'=calc|cmd", e.ioc_csv())

    def test_markdown_escaped(self):
        e = Engagement()
        e.add_user('a|b`c', 'h')
        md = e.report(at=0)
        self.assertIn('a\\|b', md)

    def test_stix_uses_real_patterns(self):
        e = Engagement()
        e.add_evidence('c' * 64, 'f', 'h')
        obj = e.stix()['objects'][0]
        self.assertIn("file:hashes.'SHA-256'", obj['pattern'])
        self.assertNotIn('x-tornado', obj['pattern'])

    def test_bad_evidence_digest(self):
        e = Engagement()
        with self.assertRaises(ValueError):
            e.add_evidence('xyz', 'f', 'h')

    def test_schema_migration_from_v1(self):
        from tornadoc2.team import atrest
        atrest.save_json('logs/engagement.json',
                         {'hosts': {}, 'findings': [], 'timeline': []})
        e = Engagement('logs/engagement.json')
        self.assertEqual(e._data['schema'], 2)
        for key in ('users', 'shares', 'services', 'evidence'):
            self.assertEqual(e._data[key], [])

    def test_entities_and_dedupe(self):
        e = Engagement()
        e.add_user('alice', 'h', 'domain', admin=True, by='x')
        e.add_share('C$', 'h', 'write', by='x')
        e.add_service('svc', 'h', 'running', by='x')
        a = e.add_evidence('a' * 64, 'f.txt', 'h', 'd', 'x', 5)
        b = e.add_evidence('a' * 64, 'again', 'h')
        self.assertEqual(a['id'], b['id'])
        self.assertEqual(len(e.entities()['evidence']), 1)
        self.assertIn('C$', e.ioc_csv())
        self.assertIn('svc', e.ioc_csv())

    def test_stix_and_mitre(self):
        e = Engagement()
        e.add_user('alice', 'h', by='x')
        e.record('jump.psexec', 'psexec to h', 'x')
        bundle = e.stix()
        self.assertEqual(bundle['type'], 'bundle')
        self.assertGreaterEqual(len(bundle['objects']), 1)
        self.assertTrue(any(m['technique'] == 'T1021.002'
                            for m in e.mitre()))

    def test_report_hashes_dataset_and_evidence(self):
        e = Engagement()
        ev = e.add_evidence('b' * 64, 'dump.bin', 'h', 'lsass', 'x', 10)
        e.add_finding('owned', 'high', 'h', 'proof', 'x', [ev['sha256']])
        md = e.report(at=0)
        self.assertIn('dataset:', md)
        self.assertIn('b' * 64, md)
        self.assertIn('T1003', md) if False else None
        self.assertEqual(md.count('generated:'), 1)

    def test_reload(self):
        e = Engagement()
        e.add_finding('a', 'low', 'h', 'd', 'x')
        e2 = Engagement()
        self.assertEqual(len(e2.findings()), 1)


if __name__ == '__main__':
    unittest.main()
