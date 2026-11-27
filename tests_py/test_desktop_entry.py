"""Desktop entry point: launcher resolution and override."""
import importlib.util
import os
import unittest

from support import ROOT

spec = importlib.util.spec_from_file_location(
    'beacon_client', os.path.join(ROOT, 'client', 'beacon-client.py'))
bc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bc)


class LauncherTest(unittest.TestCase):
    def test_env_override_wins(self):
        old = os.environ.get('TORNADOC2_GUI_BIN')
        os.environ['TORNADOC2_GUI_BIN'] = '/bin/true'
        try:
            cmd, cwd = bc._electron_command(['-c', 'a.cfg'])
        finally:
            if old is None:
                os.environ.pop('TORNADOC2_GUI_BIN', None)
            else:
                os.environ['TORNADOC2_GUI_BIN'] = old
        self.assertEqual(cmd, ['/bin/true', '--config', 'a.cfg'])
        self.assertEqual(cwd, ROOT)

    def test_runs_override(self):
        old = os.environ.get('TORNADOC2_GUI_BIN')
        os.environ['TORNADOC2_GUI_BIN'] = '/bin/true'
        try:
            self.assertEqual(bc._run_gui([]), 0)
        finally:
            if old is None:
                os.environ.pop('TORNADOC2_GUI_BIN', None)
            else:
                os.environ['TORNADOC2_GUI_BIN'] = old

    def test_parity_doc_exists(self):
        path = os.path.join(ROOT, 'docs', 'gui-parity.md')
        self.assertTrue(os.path.isfile(path))
        text = open(path, encoding='utf-8').read()
        for row in ('Connect', 'Jump', 'Armory', 'Cutover'):
            self.assertIn(row, text)


if __name__ == '__main__':
    unittest.main()
