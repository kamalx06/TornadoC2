"""Audit chain: sealing across restarts, truncation and tamper."""
import base64
import json
import os
import unittest

from support import TempState
from tornadoc2.team.audit import AuditChainError, AuditLog


class AuditTest(TempState):
    def setUp(self):
        super().setUp()
        self.base = 'audit'
        self.log = AuditLog(self.base)
        for i in range(3):
            self.log.write('alice', 'admin', '1.1.1.1',
                           f'event.{i}', detail=f'd{i}')
        self.log.flush()

    def tearDown(self):
        os.environ.pop('TORNADOC2_AUDIT_KEY', None)
        os.environ.pop('TORNADOC2_AUDIT_ANCHOR', None)
        super().tearDown()

    def reopen(self):
        return AuditLog(self.base, verify_on_start=False)

    def test_key_0600_and_restart_ok(self):
        st = os.stat(os.path.join(self.base, 'audit.key'))
        self.assertEqual(st.st_mode & 0o777, 0o600)
        self.assertEqual(st.st_size, 32)
        ok, msg = self.reopen().verify()
        self.assertTrue(ok, msg)

    def test_truncation_detected(self):
        path = os.path.join(self.base, 'combined.log')
        lines = open(path, 'rb').read().splitlines(keepends=True)
        open(path, 'wb').write(b''.join(lines[:-1]))
        ok, msg = self.reopen().verify()
        self.assertFalse(ok)
        self.assertTrue('offset' in msg or 'missing' in msg, msg)

    def test_edit_detected(self):
        path = os.path.join(self.base, 'combined.log')
        data = open(path).read().replace('"event.1"', '"event.x"')
        open(path, 'w').write(data)
        self.assertTrue(self.reopen().verify()[0])
        self.assertFalse(self.reopen().verify(full=True)[0])

    def test_anchor_mac_tamper_detected(self):
        p = os.path.join(self.base, 'anchor.json')
        cp = json.load(open(p))
        cp['mac'] = '0' * 64
        open(p, 'w').write(json.dumps(cp))
        ok, msg = self.reopen().verify()
        self.assertFalse(ok)
        self.assertIn('MAC', msg)

    def test_anchor_truncation_detected(self):
        # Deleting the log AND the checkpoint must still fail on the
        # anchor, which is the point of the second seal.
        os.remove(os.path.join(self.base, 'combined.log'))
        os.remove(os.path.join(self.base, 'checkpoint.json'))
        ok, msg = self.reopen().verify()
        self.assertFalse(ok)
        self.assertIn('seal', msg)

    def test_suffix_only_misses_middle_edit_and_full_finds_it(self):
        path = os.path.join(self.base, 'combined.log')
        lines = open(path).read().splitlines()
        lines[0] = lines[0].replace('"event.0"', '"event.z"')
        open(path, 'w').write('\n'.join(lines) + '\n')
        log = self.reopen()
        self.assertTrue(log.verify()[0])
        ok, msg = log.verify(full=True)
        self.assertFalse(ok)
        self.assertIn('hash', msg)

    def test_concurrent_write_during_verify(self):
        import threading
        stop = threading.Event()

        def writer():
            while not stop.is_set():
                self.log.write('a', 'admin', '1', 'burst')

        t = threading.Thread(target=writer, daemon=True)
        t.start()
        try:
            for _ in range(20):
                ok, msg = self.log.verify()
                self.assertTrue(ok, msg)
        finally:
            stop.set()
            t.join(2)

    def test_legacy_checkpoint_accepted_and_resealed(self):
        p = os.path.join(self.base, 'checkpoint.json')
        cp = json.load(open(p))
        cp['mac'] = 'f' * 64
        open(p, 'w').write(json.dumps(cp))
        os.remove(os.path.join(self.base, 'anchor.json'))
        log = AuditLog(self.base)  # must not raise
        cp2 = json.load(open(p))
        self.assertNotEqual(cp2['mac'], 'f' * 64)
        self.assertTrue(log.verify()[0])

    def test_startup_refuses_tail_tamper(self):
        path = os.path.join(self.base, 'combined.log')
        data = open(path).read().replace('"event.2"', '"event.x"')
        open(path, 'w').write(data)
        with self.assertRaises(AuditChainError):
            AuditLog(self.base)

    def test_empty_log_ok(self):
        ok, msg = AuditLog('fresh').verify()
        self.assertTrue(ok)

    def test_env_key(self):
        os.environ['TORNADOC2_AUDIT_KEY'] = base64.b64encode(
            b'k' * 32).decode()
        log = AuditLog('env')
        log.write('a', 'admin', '1', 'x')
        ok, _ = AuditLog('env').verify()
        self.assertTrue(ok)
        self.assertFalse(os.path.exists('env/audit.key'))


if __name__ == '__main__':
    unittest.main()
