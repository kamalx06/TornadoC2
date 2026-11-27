"""Builder derives the right build tags from config fields."""
import unittest

import os

from support import ROOT, TempState
from tornadoc2.beacon.builder import BeaconBuildConfig, BeaconBuilder


class TagTest(TempState):
    def setUp(self):
        super().setUp()
        self.b = BeaconBuilder(os.path.join(ROOT, 'tornadoc2', 'beacon'),
                               os.path.join(self._tmp.name, 'out'),
                               agent_dir=os.path.join(ROOT, 'tornadoc2',
                                                      'agent'))

    def tags(self, **kw):
        cfg = BeaconBuildConfig(target_os=kw.pop('os', 'windows'),
                                target_arch='amd64',
                                output_format='exe', url='https://x',
                                **kw)
        cmd = self.b._build_command(cfg, [], 'out')
        if '-tags' not in cmd:
            return set()
        return set(cmd[cmd.index('-tags') + 1].split(','))

    def test_unhook_tag(self):
        self.assertIn('ev_unhook', self.tags(unhook=True))
        self.assertNotIn('ev_unhook', self.tags())

    def test_windows_persistence_tags(self):
        t = self.tags(persistence='registry,task,service')
        self.assertTrue({'persist_registry', 'persist_task',
                         'persist_service'} <= t)

    def test_linux_persistence_tags(self):
        t = self.tags(os='linux', persistence='systemd,cron,profile')
        self.assertTrue({'persist_systemd', 'persist_cron',
                         'persist_profile'} <= t)

    def test_jump_and_wasm_tags(self):
        t = self.tags(jump_methods='psexec,scshell', wasm_extensions=True)
        self.assertTrue({'jump_psexec', 'jump_scshell',
                         'wasm_host'} <= t)

    def test_stack_spoof_default_and_off(self):
        self.assertIn('ev_stackspoof', self.tags())
        self.assertNotIn('ev_stackspoof', self.tags(stack_spoof=False))

    def test_unknown_tag_passthrough_and_all(self):
        self.assertIn('custom', self.tags(tags='custom'))
        self.assertIn('ev_unhook', self.tags(tags='all'))
        self.assertIn('persist_registry', self.tags(tags='all'))


if __name__ == '__main__':
    unittest.main()
