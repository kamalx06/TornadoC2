"""Local console: operator add auto-exports a verified 0600 config."""
import contextlib
import io
import os
import stat
import unittest
from types import SimpleNamespace
from unittest import mock

from support import TempState
from tornadoc2.beacon_handler import BeaconHandler
from tornadoc2.team.audit import AuditLog
from tornadoc2.team.operators import OperatorRegistry

COLORS = {k: '' for k in (
    'cyan', 'yellow', 'red', 'green', 'dim', 'bold', 'end')}


class LocalAutoExportTest(TempState):
    def setUp(self):
        super().setUp()
        self.h = object.__new__(BeaconHandler)
        self.h.colors = COLORS
        self.h.operator_registry = OperatorRegistry(
            base_dir=os.path.join(os.getcwd(), 'team_ca'))
        self.h.operator_registry.ensure_ca()
        self.h.operator_listener = SimpleNamespace(
            ca_fingerprint_loaded=(
                self.h.operator_registry.ca_fingerprint()))
        self.h.audit_log = AuditLog()
        self.h.host = '127.0.0.1'
        self.h.operator_port = 31337

    def run_add(self, name='bob'):
        buf = io.StringIO()
        with mock.patch('getpass.getpass', return_value=''):
            with contextlib.redirect_stdout(buf):
                self.h._cmd_operator(['operator', 'add', name,
                                      'operator'])
        return buf.getvalue()

    def test_add_exports_config_and_audits(self):
        out = self.run_add()
        self.assertIn('exported config', out)
        path = os.path.join(
            self.h.operator_registry.paths_for('bob')['dir'], 'bob.cfg')
        self.assertTrue(os.path.isfile(path))
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertIn(path, out)
        entries = self.h.audit_log.read()
        self.assertTrue(any(
            e.get('action') == 'operator.export'
            and 'auto=1' in (e.get('detail') or '')
            for e in entries))

    def test_export_summary_hides_pem_by_default(self):
        out = self.run_add()
        self.assertNotIn('BEGIN CERTIFICATE', out)

    def test_manual_export_print_shows_body(self):
        self.run_add()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.h._cmd_operator(
                ['operator', 'export', 'bob', '--print'])
        self.assertIn('BEGIN CERTIFICATE', buf.getvalue())


if __name__ == '__main__':
    unittest.main()
