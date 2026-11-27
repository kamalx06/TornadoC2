"""Bridge armory methods use the locked module and no URL param."""
import os
import unittest
from pathlib import Path
from unittest import mock

from support import TempState
from test_armory import Fixture
from tornado_client import armory, bridge


class ArmoryBridgeTest(TempState):
    def setUp(self):
        super().setUp()
        from tornadoc2_mcp import paths
        self._old_paths = (paths.STATE_DIR, paths.ARMORY_DIR, paths.PINS_DIR)
        paths.STATE_DIR = Path(self._tmp.name) / 'state'
        paths.ARMORY_DIR = paths.STATE_DIR / 'armory'
        paths.PINS_DIR = paths.STATE_DIR / 'pins'
        self.fx = Fixture()
        self.patch = mock.patch.object(
            armory, '_read_url', side_effect=self.fx.fetch)
        self.patch.start()
        bridge.m_armory_list({})

    def tearDown(self):
        self.patch.stop()
        from tornadoc2_mcp import paths
        paths.STATE_DIR, paths.ARMORY_DIR, paths.PINS_DIR = self._old_paths
        super().tearDown()

    def test_list_reports_source_and_installed_flag(self):
        out = bridge.m_armory_list({'refresh': True, 'repo': 'ignored'})
        self.assertEqual(out['repo'], armory.ARMORY_REPO)
        self.assertFalse(out['catalogue'][0]['installed'])
        bridge.m_armory_install({'names': ['ok']})
        out = bridge.m_armory_list({})
        self.assertTrue(out['catalogue'][0]['installed'])

    def test_info(self):
        out = bridge.m_armory_info({'name': 'ok'})
        self.assertEqual(out['entry']['name'], 'ok')
        self.assertFalse(out['entry']['installed'])

    def test_install_update_remove(self):
        out = bridge.m_armory_install({'names': ['ok']})
        self.assertEqual(out['done'], [{'name': 'ok'}])
        self.fx.add('ok', b'MZ' + b'z' * 50, '3.0.0')
        out = bridge.m_armory_update({'names': ['ok']})
        self.assertEqual(out['done'], [{'name': 'ok'}])
        out = bridge.m_armory_uninstall({'names': ['ok']})
        self.assertEqual(out['done'], ['ok'])
        self.assertEqual(armory.installed(), {})

    def test_update_index(self):
        out = bridge.m_armory_update({})
        self.assertGreaterEqual(out['count'], 1)

    def test_relayed_errors(self):
        with mock.patch.object(
                armory, 'install',
                side_effect=armory.ArmoryError('boom')):
            with self.assertRaises(bridge.BridgeError) as ctx:
                bridge.m_armory_install({'names': ['ok']})
        self.assertEqual(ctx.exception.code, 'armory')

    def test_methods_registered(self):
        for name in ('armory.list', 'armory.info', 'armory.install',
                     'armory.update', 'armory.uninstall',
                     'armory.installed'):
            self.assertIn(name, bridge.METHODS)


if __name__ == '__main__':
    unittest.main()
